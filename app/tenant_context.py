"""
app/tenant_context.py

Milestone M10: Multi-Tenancy as a First-Class Security Boundary
Ovela Foundation

Security model
--------------
* A TenantContext is the ONLY proof of "who is acting for which tenant".
  It is minted exclusively by TrustedTenantContextIssuer, which requires a
  capability object. Trust is carried by a private marker bound to the
  context's content via a process-local HMAC, so a context that was
  hand-constructed, copied with altered fields (dataclasses.replace), or
  deserialised is NOT trusted. Python cannot make this absolutely
  unforgeable against code that deliberately reaches into module privates;
  it makes accidental or casual forgery fail closed and makes deliberate
  forgery explicit and auditable.
* Every guard fails closed. Missing, untrusted, expired, or not-yet-valid
  contexts are rejected BEFORE any connection is opened or query executed.
* Cross-tenant lookups are indistinguishable from genuinely missing
  resources (TenantResourceNotFound carries a constant message), so there
  is no cross-tenant existence oracle.
* TenantScopedGateway forces `tenant_id = ?` on every lookup, lock, update
  and ledger write, using the tenant from the verified context (never a
  caller-supplied tenant). On PostgreSQL it additionally issues
  `SET LOCAL app.tenant_id = '<uuid>'` at the start of each DB transaction
  so row-level-security policies act as a second, independent boundary.

Integration notes
-----------------
* The gateway's table registry maps table name -> primary-key column. The
  M6/M9 entries match the existing schemas (transaction_executions,
  transaction_ledger_entries, settlement_statements,
  settlement_statement_entries, reconciliation_cases). The M5/M7/M8 entries
  are defaults and can be overridden via the `table_registry` constructor
  argument to match the deployed schema.
* scoped_transition applies a conservative local transition table as
  defence in depth. Prefer DurableTransactionEngine.transition_state for
  production state changes; pass `permitted_transitions` to mirror the
  engine's table exactly if this gateway is used for them.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import sys
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Callable, Iterator, Mapping

from app.transaction_engine import TransactionExecutionState

__all__ = [
    "TenantIsolationError",
    "TenantContextInvalid",
    "TenantContextExpired",
    "TenantResourceNotFound",
    "TenantContext",
    "IssuerCapability",
    "TrustedTenantContextIssuer",
    "require_same_tenant",
    "prevent_existence_oracle",
    "TenantScopedGateway",
    "generate_rls_session_statement",
]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TenantIsolationError(Exception):
    """Base class for all tenant isolation violations."""


class TenantContextInvalid(TenantIsolationError):
    """The tenant context is missing, malformed, untrusted, or not yet valid."""


class TenantContextExpired(TenantIsolationError):
    """The tenant context has expired."""


class TenantResourceNotFound(TenantIsolationError):
    """
    Resource not found for this tenant.

    Raised both for genuinely missing resources and for resources owned by a
    different tenant. The message is constant so the two cases are
    indistinguishable (no cross-tenant existence oracle).
    """

    _MESSAGE = "Resource not found"

    def __init__(self) -> None:
        super().__init__(self._MESSAGE)


# ---------------------------------------------------------------------------
# Trust primitives (private)
# ---------------------------------------------------------------------------

_PROCESS_SECRET: bytes = secrets.token_bytes(32)


class _TrustMarker:
    """
    Private marker proving a context was minted by a trusted issuer.

    Carries an HMAC digest over the context's content, so altering any field
    of an issued context invalidates trust. Cannot be copied or pickled into
    existence from outside.
    """

    __slots__ = ("_digest",)

    def __init__(self, digest: bytes) -> None:
        object.__setattr__(self, "_digest", digest)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("_TrustMarker is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("_TrustMarker is immutable")

    def __reduce__(self) -> Any:
        raise TypeError("_TrustMarker cannot be pickled")

    def __copy__(self) -> "_TrustMarker":
        return self

    def __deepcopy__(self, memo: Any) -> "_TrustMarker":
        return self

    def __repr__(self) -> str:
        return "<_TrustMarker>"

    def matches(self, digest: bytes) -> bool:
        return hmac.compare_digest(self._digest, digest)


def _content_digest(
    tenant_id: uuid.UUID,
    subject_id: uuid.UUID,
    session_id: uuid.UUID,
    context_id: uuid.UUID,
    issued_at: datetime,
    expires_at: datetime,
    roles: frozenset[str],
) -> bytes:
    parts = [
        str(tenant_id),
        str(subject_id),
        str(session_id),
        str(context_id),
        issued_at.isoformat(),
        expires_at.isoformat(),
        "\x1f".join(sorted(roles)),
    ]
    payload = "\x1e".join(parts).encode("utf-8")
    return hmac.new(_PROCESS_SECRET, payload, hashlib.sha256).digest()


def _require_uuid(value: Any, name: str, *, allow_nil: bool = False) -> uuid.UUID:
    if not isinstance(value, uuid.UUID):
        raise TenantContextInvalid(f"{name} must be a UUID")
    if not allow_nil and value.int == 0:
        raise TenantContextInvalid(f"{name} must not be the nil UUID")
    return value


def _require_utc(value: Any, name: str) -> datetime:
    if not isinstance(value, datetime):
        raise TenantContextInvalid(f"{name} must be a datetime")
    offset = value.utcoffset()
    if value.tzinfo is None or offset is None:
        raise TenantContextInvalid(f"{name} must be timezone-aware")
    if offset != timedelta(0):
        raise TenantContextInvalid(f"{name} must be in UTC")
    return value


def _require_roles(value: Any) -> frozenset[str]:
    if not isinstance(value, frozenset):
        raise TenantContextInvalid("roles must be a frozenset of strings")
    for role in value:
        if not isinstance(role, str) or not role.strip():
            raise TenantContextInvalid("roles must contain non-empty strings")
    return value


# ---------------------------------------------------------------------------
# TenantContext
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TenantContext:
    tenant_id: uuid.UUID
    subject_id: uuid.UUID
    session_id: uuid.UUID
    issued_at: datetime
    expires_at: datetime
    context_id: uuid.UUID
    roles: frozenset[str] = frozenset()
    _issuer_marker: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        _require_uuid(self.tenant_id, "tenant_id")
        _require_uuid(self.subject_id, "subject_id")
        _require_uuid(self.session_id, "session_id")
        _require_uuid(self.context_id, "context_id")
        _require_utc(self.issued_at, "issued_at")
        _require_utc(self.expires_at, "expires_at")
        if not self.expires_at > self.issued_at:
            raise TenantContextInvalid("expires_at must be after issued_at")
        _require_roles(self.roles)

    # -- trust ------------------------------------------------------------

    def is_trusted(self) -> bool:
        marker = self._issuer_marker
        if not isinstance(marker, _TrustMarker):
            return False
        try:
            digest = _content_digest(
                self.tenant_id,
                self.subject_id,
                self.session_id,
                self.context_id,
                self.issued_at,
                self.expires_at,
                self.roles,
            )
        except Exception:
            return False
        return marker.matches(digest)

    def require_trusted(self) -> None:
        if not self.is_trusted():
            raise TenantContextInvalid("Tenant context is not trusted")

    # -- validity ---------------------------------------------------------

    def is_valid_at(self, now: datetime) -> bool:
        if not isinstance(now, datetime) or now.utcoffset() is None:
            return False
        return self.issued_at <= now < self.expires_at

    def require_valid_at(self, now: datetime) -> None:
        if not isinstance(now, datetime) or now.utcoffset() is None:
            raise TenantContextInvalid("now must be a timezone-aware datetime")
        if now >= self.expires_at:
            raise TenantContextExpired("Tenant context has expired")
        if now < self.issued_at:
            raise TenantContextInvalid("Tenant context is not yet valid")


# ---------------------------------------------------------------------------
# Issuer
# ---------------------------------------------------------------------------


class IssuerCapability:
    """
    Unforgeable-by-accident capability required to construct and use a
    TrustedTenantContextIssuer. Mint it once at the composition root and
    hand it only to code allowed to establish tenant identity
    (e.g. the authentication layer).
    """

    __slots__ = ("_token",)

    def __init__(self, _token: bytes | None = None) -> None:
        if _token is None:
            raise TypeError("Use IssuerCapability.mint() to create a capability")
        object.__setattr__(self, "_token", _token)

    @classmethod
    def mint(cls) -> "IssuerCapability":
        return cls(secrets.token_bytes(32))

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("IssuerCapability is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("IssuerCapability is immutable")

    def __reduce__(self) -> Any:
        raise TypeError("IssuerCapability cannot be pickled")

    def __copy__(self) -> "IssuerCapability":
        return self

    def __deepcopy__(self, memo: Any) -> "IssuerCapability":
        return self

    def __repr__(self) -> str:
        return "<IssuerCapability>"

    def _matches(self, other: "IssuerCapability") -> bool:
        return hmac.compare_digest(self._token, other._token)


class TrustedTenantContextIssuer:
    """Capability-protected factory for trusted TenantContext instances."""

    def __init__(self, capability: IssuerCapability) -> None:
        if not isinstance(capability, IssuerCapability):
            raise TenantContextInvalid("A valid issuer capability is required")
        self._capability = capability

    def issue_context(
        self,
        capability: IssuerCapability,
        tenant_id: uuid.UUID,
        subject_id: uuid.UUID,
        session_id: uuid.UUID,
        issued_at: datetime,
        expires_at: datetime,
        roles: frozenset[str] = frozenset(),
    ) -> TenantContext:
        if not isinstance(capability, IssuerCapability) or not self._capability._matches(
            capability
        ):
            raise TenantContextInvalid("Issuer capability rejected")

        context_id = uuid.uuid4()

        # Build (and thereby fully validate) an untrusted draft first.
        draft = TenantContext(
            tenant_id=tenant_id,
            subject_id=subject_id,
            session_id=session_id,
            issued_at=issued_at,
            expires_at=expires_at,
            context_id=context_id,
            roles=roles,
        )
        digest = _content_digest(
            draft.tenant_id,
            draft.subject_id,
            draft.session_id,
            draft.context_id,
            draft.issued_at,
            draft.expires_at,
            draft.roles,
        )
        return TenantContext(
            tenant_id=draft.tenant_id,
            subject_id=draft.subject_id,
            session_id=draft.session_id,
            issued_at=draft.issued_at,
            expires_at=draft.expires_at,
            context_id=draft.context_id,
            roles=draft.roles,
            _issuer_marker=_TrustMarker(digest),
        )


# ---------------------------------------------------------------------------
# Verification guards
# ---------------------------------------------------------------------------


def _authorize_context(context: Any, now: datetime) -> TenantContext:
    """Fail-closed verification used by every guard and gateway operation."""
    if context is None:
        raise TenantContextInvalid("Tenant context is required")
    if not isinstance(context, TenantContext):
        raise TenantContextInvalid("Tenant context has an invalid type")
    context.require_trusted()
    context.require_valid_at(now)
    return context


def require_same_tenant(
    context: TenantContext,
    target_tenant_id: uuid.UUID,
    now: datetime,
) -> None:
    _authorize_context(context, now)
    if not isinstance(target_tenant_id, uuid.UUID):
        raise TenantIsolationError("Tenant boundary violation")
    if context.tenant_id != target_tenant_id:
        raise TenantIsolationError("Tenant boundary violation")


def prevent_existence_oracle(
    entity: Any | None,
    context: TenantContext,
    entity_tenant_id: uuid.UUID | None,
    now: datetime,
) -> Any:
    # Context problems say nothing about the entity, so they may be reported
    # distinctly. Everything after this point is a single indistinguishable
    # outcome.
    _authorize_context(context, now)
    if (
        entity is None
        or entity_tenant_id is None
        or not isinstance(entity_tenant_id, uuid.UUID)
        or entity_tenant_id != context.tenant_id
    ):
        raise TenantResourceNotFound()
    return entity


# ---------------------------------------------------------------------------
# RLS
# ---------------------------------------------------------------------------


def generate_rls_session_statement(tenant_id: uuid.UUID) -> str:
    """
    PostgreSQL session statement binding the transaction to one tenant for
    row-level-security policies. The value is a validated UUID rendered in
    canonical form, so it cannot carry SQL.
    """
    if not isinstance(tenant_id, uuid.UUID) or tenant_id.int == 0:
        raise TenantIsolationError("tenant_id must be a non-nil UUID")
    return f"SET LOCAL app.tenant_id = '{tenant_id}'"


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]*$")

ConnectionFactory = Callable[[], Any]

DEFAULT_TABLE_REGISTRY: Mapping[str, str] = {
    # M5 approvals
    "transaction_approvals": "approval_id",
    # M6 executions + ledger
    "transaction_executions": "transaction_execution_id",
    "transaction_ledger_entries": "entry_id",
    # M7 outbox
    "transaction_outbox": "outbox_id",
    # M8 webhooks
    "webhook_events": "event_id",
    # M9 statements / reconciliation
    "settlement_statements": "statement_id",
    "settlement_statement_entries": "entry_id",
    "reconciliation_cases": "reconciliation_id",
}

_S = TransactionExecutionState

DEFAULT_PERMITTED_TRANSITIONS: Mapping[str, frozenset[str]] = {
    _S.CREATED.value: frozenset({_S.AUTHORIZED.value, _S.FAILED.value}),
    _S.AUTHORIZED.value: frozenset({_S.APPROVED.value, _S.FAILED.value}),
    _S.APPROVED.value: frozenset({_S.RESERVED.value, _S.FAILED.value}),
    _S.RESERVED.value: frozenset({_S.SUBMITTED.value, _S.FAILED.value}),
    _S.SUBMITTED.value: frozenset(
        {_S.SETTLED.value, _S.FAILED.value, _S.UNKNOWN.value}
    ),
    _S.UNKNOWN.value: frozenset({_S.SETTLED.value, _S.FAILED.value}),
    _S.SETTLED.value: frozenset(),
    _S.FAILED.value: frozenset(),
}


def _detect_paramstyle(connection: Any) -> str:
    for klass in type(connection).__mro__:
        module_name = (klass.__module__ or "").lstrip("_")
        root = module_name.split(".")[0]
        if root == "sqlite3":
            return "qmark"
        if root.startswith("psycopg"):
            return "format"
    for klass in type(connection).__mro__:
        root = (klass.__module__ or "").split(".")[0]
        style = getattr(sys.modules.get(root), "paramstyle", None)
        if style in ("qmark", "format", "pyformat", "numeric", "named"):
            return style
    return "qmark"


def _render(style: str, sql: str, params: tuple[Any, ...]) -> tuple[str, Any]:
    """Rewrite '?' placeholders for the connection's DB-API paramstyle."""
    if style == "qmark":
        return sql, params
    if style in ("format", "pyformat"):
        return sql.replace("?", "%s"), params
    if style == "numeric":
        out: list[str] = []
        index = 0
        for ch in sql:
            if ch == "?":
                index += 1
                out.append(f":{index}")
            else:
                out.append(ch)
        return "".join(out), params
    if style == "named":
        out = []
        named: dict[str, Any] = {}
        index = 0
        for ch in sql:
            if ch == "?":
                key = f"p{index}"
                named[key] = params[index]
                index += 1
                out.append(f":{key}")
            else:
                out.append(ch)
        return "".join(out), named
    return sql, params


def _dict_row(cursor: Any, row: Any) -> dict[str, Any]:
    names = [column[0] for column in cursor.description]
    return dict(zip(names, row))


# ---------------------------------------------------------------------------
# TenantScopedGateway
# ---------------------------------------------------------------------------


class TenantScopedGateway:
    """
    Tenant-scoped repository protection wrapper across M5-M9.

    Every public operation:
      1. verifies the context (present, trusted, valid at `now`) BEFORE any
         connection is opened;
      2. runs inside one DB transaction (commit / rollback / close);
      3. applies the PostgreSQL RLS session binding where applicable;
      4. forces `WHERE tenant_id = ?` using the tenant from the verified
         context, never from a caller-supplied value.
    """

    def __init__(
        self,
        connection_factory: ConnectionFactory,
        *,
        table_registry: Mapping[str, str] | None = None,
        permitted_transitions: Mapping[str, frozenset[str]] | None = None,
        enable_rls_session: bool | None = None,
    ) -> None:
        if not callable(connection_factory):
            raise TypeError("connection_factory must be callable")
        registry = dict(
            DEFAULT_TABLE_REGISTRY if table_registry is None else table_registry
        )
        for table, id_column in registry.items():
            if not _IDENTIFIER.match(table) or not _IDENTIFIER.match(id_column):
                raise ValueError(f"Unsafe identifier in table registry: {table!r}")
        self._connection_factory = connection_factory
        self._registry = registry
        self._transitions = dict(
            DEFAULT_PERMITTED_TRANSITIONS
            if permitted_transitions is None
            else permitted_transitions
        )
        self._enable_rls_session = enable_rls_session

    # -- transaction management --------------------------------------------

    @contextmanager
    def _transaction(self, tenant_id: uuid.UUID) -> Iterator[tuple[Any, str]]:
        connection = self._connection_factory()
        style = _detect_paramstyle(connection)
        try:
            use_rls = (
                self._enable_rls_session
                if self._enable_rls_session is not None
                else style != "qmark"
            )
            if use_rls:
                cursor = connection.cursor()
                try:
                    cursor.execute(generate_rls_session_statement(tenant_id))
                finally:
                    cursor.close()
            yield connection, style
            connection.commit()
        except BaseException:
            try:
                connection.rollback()
            except Exception:  # pragma: no cover - defensive
                pass
            raise
        finally:
            try:
                connection.close()
            except Exception:  # pragma: no cover - defensive
                pass

    def _execute(
        self,
        connection: Any,
        style: str,
        sql: str,
        params: tuple[Any, ...],
    ) -> Any:
        cursor = connection.cursor()
        try:
            rendered_sql, rendered_params = _render(style, sql, params)
            cursor.execute(rendered_sql, rendered_params)
        except BaseException:
            cursor.close()
            raise
        return cursor

    def _table(self, table: Any) -> tuple[str, str]:
        if not isinstance(table, str) or table not in self._registry:
            raise TenantIsolationError("Table is not tenant-scoped")
        return table, self._registry[table]

    @staticmethod
    def _entity_uuid(value: Any) -> uuid.UUID:
        if not isinstance(value, uuid.UUID):
            raise TenantIsolationError("Entity identifier must be a UUID")
        return value

    # -- lookups -------------------------------------------------------------

    def scoped_query(
        self,
        context: TenantContext,
        table: str,
        entity_id: uuid.UUID,
        now: datetime,
    ) -> dict | None:
        context = _authorize_context(context, now)
        table_name, id_column = self._table(table)
        entity_id = self._entity_uuid(entity_id)

        with self._transaction(context.tenant_id) as (connection, style):
            cursor = self._execute(
                connection,
                style,
                f"SELECT * FROM {table_name} WHERE tenant_id = ? AND {id_column} = ?",
                (str(context.tenant_id), str(entity_id)),
            )
            try:
                row = cursor.fetchone()
                if row is None:
                    return None
                result = _dict_row(cursor, row)
            finally:
                cursor.close()

        # Defence in depth: never hand back a row from another tenant even if
        # the query layer were somehow bypassed.
        owner = result.get("tenant_id")
        if owner is not None and str(owner) != str(context.tenant_id):
            return None
        return result

    def scoped_lock(
        self,
        context: TenantContext,
        table: str,
        entity_id: uuid.UUID,
        now: datetime,
    ) -> dict | None:
        """
        Tenant-scoped row lock. Uses SELECT ... FOR UPDATE where the backend
        supports it (PostgreSQL); the enclosing transaction already provides
        write serialisation on SQLite.
        """
        context = _authorize_context(context, now)
        table_name, id_column = self._table(table)
        entity_id = self._entity_uuid(entity_id)

        with self._transaction(context.tenant_id) as (connection, style):
            suffix = "" if style == "qmark" else " FOR UPDATE"
            cursor = self._execute(
                connection,
                style,
                f"SELECT * FROM {table_name} WHERE tenant_id = ? "
                f"AND {id_column} = ?{suffix}",
                (str(context.tenant_id), str(entity_id)),
            )
            try:
                row = cursor.fetchone()
                if row is None:
                    return None
                return _dict_row(cursor, row)
            finally:
                cursor.close()

    # -- updates -------------------------------------------------------------

    def scoped_transition(
        self,
        context: TenantContext,
        execution_id: uuid.UUID,
        target_state: str,
        now: datetime,
    ) -> bool:
        """
        Tenant-scoped compare-and-set state transition. Returns True only if
        exactly one row owned by the context's tenant moved from its current
        state to a permitted target state. Anything else returns False and
        changes nothing (fail closed).
        """
        context = _authorize_context(context, now)
        execution_id = self._entity_uuid(execution_id)

        try:
            target = TransactionExecutionState(target_state).value
        except ValueError:
            return False

        with self._transaction(context.tenant_id) as (connection, style):
            suffix = "" if style == "qmark" else " FOR UPDATE"
            cursor = self._execute(
                connection,
                style,
                "SELECT state FROM transaction_executions "
                f"WHERE tenant_id = ? AND transaction_execution_id = ?{suffix}",
                (str(context.tenant_id), str(execution_id)),
            )
            try:
                row = cursor.fetchone()
            finally:
                cursor.close()
            if row is None:
                return False

            current = str(row[0])
            if target not in self._transitions.get(current, frozenset()):
                return False

            cursor = self._execute(
                connection,
                style,
                "UPDATE transaction_executions SET state = ? "
                "WHERE tenant_id = ? AND transaction_execution_id = ? "
                "AND state = ?",
                (target, str(context.tenant_id), str(execution_id), current),
            )
            try:
                return cursor.rowcount == 1
            finally:
                cursor.close()

    # -- ledger writes -------------------------------------------------------

    def scoped_append_ledger_entry(
        self,
        context: TenantContext,
        execution_id: uuid.UUID,
        entry_type: str,
        amount: Decimal,
        currency: str,
        now: datetime,
    ) -> uuid.UUID:
        """
        Append-only ledger write. The tenant is taken from the verified
        context, and the execution must already belong to that tenant;
        otherwise TenantResourceNotFound is raised (no existence oracle).
        """
        context = _authorize_context(context, now)
        execution_id = self._entity_uuid(execution_id)
        if not isinstance(entry_type, str) or not entry_type.strip():
            raise TenantIsolationError("entry_type must be a non-empty string")
        if not isinstance(amount, Decimal) or not amount.is_finite():
            raise TenantIsolationError("amount must be a finite Decimal")
        if not isinstance(currency, str) or not currency.strip():
            raise TenantIsolationError("currency must be a non-empty string")

        entry_id = uuid.uuid4()
        with self._transaction(context.tenant_id) as (connection, style):
            cursor = self._execute(
                connection,
                style,
                "SELECT 1 FROM transaction_executions "
                "WHERE tenant_id = ? AND transaction_execution_id = ?",
                (str(context.tenant_id), str(execution_id)),
            )
            try:
                owned = cursor.fetchone()
            finally:
                cursor.close()
            if owned is None:
                raise TenantResourceNotFound()

            cursor = self._execute(
                connection,
                style,
                "INSERT INTO transaction_ledger_entries ("
                "entry_id, tenant_id, transaction_execution_id, entry_type, "
                "amount, currency, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    str(entry_id),
                    str(context.tenant_id),
                    str(execution_id),
                    entry_type.strip(),
                    format(amount, "f"),
                    currency.strip().upper(),
                    now.astimezone(timezone.utc).isoformat(),
                ),
            )
            cursor.close()
        return entry_id

    # -- reconciliation gate -------------------------------------------------

    def scoped_reconcile(
        self,
        context: TenantContext,
        statement_id: uuid.UUID,
        now: datetime,
    ) -> bool:
        """
        Tenant-scoped reconciliation gate for a settlement statement.

        Returns True only if the statement exists within the context's
        tenant AND the tenant-scoped entry set is complete (entry count
        equals the statement's recorded line_count). Statements owned by
        other tenants are indistinguishable from missing ones (False). This
        gate performs no writes; run FinancialReconciliationService only for
        statements this gate approves.
        """
        context = _authorize_context(context, now)
        statement_id = self._entity_uuid(statement_id)

        with self._transaction(context.tenant_id) as (connection, style):
            cursor = self._execute(
                connection,
                style,
                "SELECT line_count FROM settlement_statements "
                "WHERE tenant_id = ? AND statement_id = ?",
                (str(context.tenant_id), str(statement_id)),
            )
            try:
                row = cursor.fetchone()
            finally:
                cursor.close()
            if row is None:
                return False
            expected = int(row[0])

            cursor = self._execute(
                connection,
                style,
                "SELECT COUNT(*) FROM settlement_statement_entries "
                "WHERE tenant_id = ? AND statement_id = ?",
                (str(context.tenant_id), str(statement_id)),
            )
            try:
                count_row = cursor.fetchone()
            finally:
                cursor.close()
            actual = int(count_row[0]) if count_row is not None else 0
            return actual == expected

    # -- RLS -----------------------------------------------------------------

    def generate_rls_session_statement(self, tenant_id: uuid.UUID) -> str:
        return generate_rls_session_statement(tenant_id)