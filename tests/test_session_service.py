import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from threading import Barrier
from uuid import uuid4

import pytest

from app.authorization_context import AuthorizationContext, AuthorizationState
from app.models import ActionRequest
from app.security import authorize_action
from app.session_service import (
    SessionExpired,
    SessionInvalid,
    SessionRevoked,
    SessionService,
)
from app.session_store import (
    ENV_VAR,
    InMemorySessionStore,
    SessionStore,
    SessionStoreError,
    SqlServerSessionStore,
)


class FakeClock:
    def __init__(self):
        self.now = datetime(2030, 1, 1, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, **kwargs):
        self.now += timedelta(**kwargs)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def store():
    return InMemorySessionStore()


@pytest.fixture
def service(store, clock):
    return SessionService(store, clock=clock)


# ---------------------------------------------------------------------------
# Context issuance
# ---------------------------------------------------------------------------


def test_valid_session_yields_trusted_authenticated_context(service):
    subject = uuid4()
    issued = service.create_authenticated_session(subject)

    context = service.resolve_context(issued.token)

    assert isinstance(context, AuthorizationContext)
    assert context.is_trusted() is True
    assert context.state is AuthorizationState.AUTHENTICATED
    assert context.session_id == issued.session_id
    assert context.subject_id == subject


def test_session_context_is_accepted_by_authorization_for_authenticated_read():
    svc = SessionService(InMemorySessionStore())
    issued = svc.create_authenticated_session(uuid4())
    context = svc.resolve_context(issued.token)

    action = ActionRequest(
        session_id=str(issued.session_id),
        action_type="READ_FINANCIAL",
        authorization_state="UNVERIFIED",
    )

    assert authorize_action(action, context).allowed is True


def test_plain_authentication_cannot_produce_step_up_for_payment():
    svc = SessionService(InMemorySessionStore())
    issued = svc.create_authenticated_session(uuid4())
    context = svc.resolve_context(issued.token)

    payment = ActionRequest(
        session_id=str(issued.session_id),
        action_type="PAYMENT_INITIATE",
        authorization_state="STEP_UP_VERIFIED",
        amount=Decimal("100.00"),
        currency="INR",
        destination_id="merchant-1",
        destination_verified=True,
        user_confirmation=True,
    )

    decision = authorize_action(payment, context)

    assert decision.allowed is False
    assert decision.requires_step_up is True


def test_context_never_outlives_the_session(service, clock):
    issued = service.create_authenticated_session(uuid4())

    for _ in range(47):
        clock.advance(minutes=10)
        service.resolve_context(issued.token)

    clock.advance(minutes=7)
    context = service.resolve_context(issued.token)

    assert context.expires_at == issued.expires_at


# ---------------------------------------------------------------------------
# Forged / malformed tokens
# ---------------------------------------------------------------------------

_VALID_SHAPE_SECRET = "A" * 43


@pytest.mark.parametrize(
    "token",
    [
        "",
        "abc",
        "no-dot-here",
        str(uuid4()),
        f"{uuid4()}.",
        f"not-a-uuid.{_VALID_SHAPE_SECRET}",
        f"{uuid4()}.{'A' * 42}",
        f"{uuid4()}.{'A' * 44}",
        f"{uuid4()}.{'!' * 43}",
        f"{str(uuid4()).upper()}.{_VALID_SHAPE_SECRET}",
        f"{uuid4()}.{_VALID_SHAPE_SECRET}.extra",
        "x" * 500,
        None,
        123,
        b"bytes-token",
    ],
)
def test_malformed_tokens_are_rejected(service, token):
    with pytest.raises(SessionInvalid):
        service.resolve_context(token)


def test_unknown_session_is_rejected(service):
    with pytest.raises(SessionInvalid):
        service.resolve_context(f"{uuid4()}.{_VALID_SHAPE_SECRET}")


def test_wrong_secret_for_real_session_is_rejected(service):
    issued = service.create_authenticated_session(uuid4())
    forged = f"{issued.session_id}.{_VALID_SHAPE_SECRET}"

    with pytest.raises(SessionInvalid):
        service.resolve_context(forged)


def test_forged_token_does_not_learn_revocation_status(service):
    issued = service.create_authenticated_session(uuid4())
    assert service.revoke(issued.token) is True

    forged = f"{issued.session_id}.{_VALID_SHAPE_SECRET}"

    with pytest.raises(SessionInvalid) as caught:
        service.resolve_context(forged)

    assert not isinstance(caught.value, SessionRevoked)


# ---------------------------------------------------------------------------
# Timeouts
# ---------------------------------------------------------------------------


def test_idle_timeout_expires_session(service, clock):
    issued = service.create_authenticated_session(uuid4())

    clock.advance(minutes=16)

    with pytest.raises(SessionExpired):
        service.resolve_context(issued.token)


def test_activity_slides_the_idle_timeout(service, clock):
    issued = service.create_authenticated_session(uuid4())

    clock.advance(minutes=10)
    service.resolve_context(issued.token)

    clock.advance(minutes=10)
    service.resolve_context(issued.token)


def test_absolute_timeout_cannot_be_extended_by_activity(service, clock):
    issued = service.create_authenticated_session(uuid4())

    for _ in range(47):
        clock.advance(minutes=10)
        service.resolve_context(issued.token)

    clock.advance(minutes=10)

    with pytest.raises(SessionExpired):
        service.resolve_context(issued.token)


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


def test_revoked_session_cannot_create_context(service):
    issued = service.create_authenticated_session(uuid4())

    assert service.revoke(issued.token) is True

    with pytest.raises(SessionRevoked):
        service.resolve_context(issued.token)

    assert service.revoke(issued.token) is False


def test_revoke_requires_the_real_secret(service):
    issued = service.create_authenticated_session(uuid4())
    forged = f"{issued.session_id}.{_VALID_SHAPE_SECRET}"

    assert service.revoke(forged) is False
    assert service.revoke("garbage") is False
    assert service.revoke(None) is False

    service.resolve_context(issued.token)


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------


def test_rotation_replaces_token_and_keeps_absolute_expiry(service, clock):
    subject = uuid4()
    issued = service.create_authenticated_session(subject)

    clock.advance(minutes=10)
    rotated = service.rotate(issued.token)

    assert rotated.session_id != issued.session_id
    assert rotated.token != issued.token
    assert rotated.expires_at == issued.expires_at

    with pytest.raises(SessionRevoked):
        service.resolve_context(issued.token)

    context = service.resolve_context(rotated.token)
    assert context.subject_id == subject
    assert context.session_id == rotated.session_id


def test_rotation_of_invalid_token_is_rejected(service):
    with pytest.raises(SessionInvalid):
        service.rotate(f"{uuid4()}.{_VALID_SHAPE_SECRET}")


def test_rotated_session_still_expires_at_original_deadline(service, clock):
    issued = service.create_authenticated_session(uuid4())

    for _ in range(40):
        clock.advance(minutes=10)
    # keep alive by rotating periodically
    token = issued.token
    clock.now = datetime(2030, 1, 1, 12, 0, tzinfo=timezone.utc)

    for _ in range(47):
        clock.advance(minutes=10)
        token = service.rotate(token).token

    clock.advance(minutes=10)

    with pytest.raises(SessionExpired):
        service.resolve_context(token)


# ---------------------------------------------------------------------------
# Storage properties and failure behavior
# ---------------------------------------------------------------------------


def test_only_a_hash_of_the_secret_is_stored(service, store):
    issued = service.create_authenticated_session(uuid4())
    secret = issued.token.split(".")[1]

    record = store.get(issued.session_id)

    assert record.secret_hash == hashlib.sha256(secret.encode()).digest()
    assert secret not in repr(record)
    assert issued.token not in repr(issued)


def test_tokens_are_unique(service):
    subject = uuid4()
    tokens = {service.create_authenticated_session(subject).token for _ in range(100)}

    assert len(tokens) == 100


def test_sessions_are_independent(service):
    first = service.create_authenticated_session(uuid4())
    second = service.create_authenticated_session(uuid4())

    service.revoke(first.token)

    service.resolve_context(second.token)


class _BrokenStore(SessionStore):
    def __init__(self, error):
        self._error = error

    def insert(self, record):
        raise self._error

    def get(self, session_id):
        raise self._error

    def touch(self, session_id, last_seen_at, idle_expires_at):
        raise self._error

    def revoke(self, session_id, revoked_at):
        raise self._error

    def rotate(self, old_session_id, new_record, now):
        raise self._error


@pytest.mark.parametrize(
    "error",
    [SessionStoreError("outage"), RuntimeError("unexpected")],
)
def test_store_failure_fails_closed(error):
    svc = SessionService(_BrokenStore(error))

    with pytest.raises(SessionStoreError):
        svc.create_authenticated_session(uuid4())

    with pytest.raises(SessionStoreError):
        svc.resolve_context(f"{uuid4()}.{_VALID_SHAPE_SECRET}")


def test_invalid_clock_fails_closed(store):
    svc = SessionService(store, clock=lambda: datetime(2030, 1, 1))

    with pytest.raises(SessionStoreError):
        svc.create_authenticated_session(uuid4())


def test_broken_clock_fails_closed(store):
    def broken():
        raise RuntimeError("clock failure")

    svc = SessionService(store, clock=broken)

    with pytest.raises(SessionStoreError):
        svc.create_authenticated_session(uuid4())


def test_service_rejects_bad_configuration(store):
    with pytest.raises(TypeError):
        SessionService(object())

    with pytest.raises(ValueError):
        SessionService(store, idle_timeout=timedelta(0))

    with pytest.raises(TypeError):
        SessionService(store, absolute_timeout=60)

    with pytest.raises(TypeError):
        SessionService(store, clock="not callable")


def test_create_requires_uuid_subject(service):
    with pytest.raises(TypeError):
        service.create_authenticated_session("not-a-uuid")


def test_from_environment_without_variable_fails_closed(monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)

    with pytest.raises(SessionStoreError):
        SessionService.from_environment()


def test_sql_store_requires_connection_string():
    with pytest.raises(SessionStoreError):
        SqlServerSessionStore("")


# ---------------------------------------------------------------------------
# SQL Server integration tests. Run only when OVELA_SESSION_DB_CONNECTION is
# set and the database was created with scripts.setup_session_db.
# ---------------------------------------------------------------------------

requires_sql = pytest.mark.skipif(
    not os.environ.get(ENV_VAR, "").strip(),
    reason=f"{ENV_VAR} is not set; SQL Server tests skipped",
)


@pytest.fixture
def sql_service():
    sql_store = SqlServerSessionStore(os.environ[ENV_VAR])
    sql_store.create_schema()
    return SessionService(sql_store)


@requires_sql
def test_sql_session_round_trip_and_rotation(sql_service):
    subject = uuid4()
    issued = sql_service.create_authenticated_session(subject)

    context = sql_service.resolve_context(issued.token)
    assert context.is_trusted() is True
    assert context.state is AuthorizationState.AUTHENTICATED
    assert context.subject_id == subject

    rotated = sql_service.rotate(issued.token)

    with pytest.raises(SessionRevoked):
        sql_service.resolve_context(issued.token)

    assert sql_service.resolve_context(rotated.token).subject_id == subject


@requires_sql
def test_sql_wrong_secret_and_unknown_session_rejected(sql_service):
    issued = sql_service.create_authenticated_session(uuid4())

    with pytest.raises(SessionInvalid):
        sql_service.resolve_context(f"{issued.session_id}.{_VALID_SHAPE_SECRET}")

    with pytest.raises(SessionInvalid):
        sql_service.resolve_context(f"{uuid4()}.{_VALID_SHAPE_SECRET}")


@requires_sql
def test_sql_revocation(sql_service):
    issued = sql_service.create_authenticated_session(uuid4())

    assert sql_service.revoke(issued.token) is True
    assert sql_service.revoke(issued.token) is False

    with pytest.raises(SessionRevoked):
        sql_service.resolve_context(issued.token)


@requires_sql
def test_sql_only_hash_is_stored(sql_service):
    issued = sql_service.create_authenticated_session(uuid4())
    secret = issued.token.split(".")[1]

    record = sql_service._store.get(issued.session_id)

    assert record.secret_hash == hashlib.sha256(secret.encode()).digest()


@requires_sql
def test_sql_concurrent_rotation_has_exactly_one_winner(sql_service):
    issued = sql_service.create_authenticated_session(uuid4())
    workers = 16
    barrier = Barrier(workers)

    def attempt(_):
        barrier.wait()

        try:
            sql_service.rotate(issued.token)
            return "ok"
        except SessionInvalid:
            return "rejected"

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(attempt, range(workers)))

    assert results.count("ok") == 1
    assert results.count("rejected") == workers - 1


@requires_sql
def test_sql_unreachable_server_fails_closed():
    broken = SqlServerSessionStore(
        "DRIVER={ODBC Driver 18 for SQL Server};"
        "SERVER=localhost\\NO_SUCH_INSTANCE;DATABASE=OvelaSessions;"
        "Trusted_Connection=yes;TrustServerCertificate=yes;"
    )
    svc = SessionService(broken)

    with pytest.raises(SessionStoreError):
        svc.create_authenticated_session(uuid4())