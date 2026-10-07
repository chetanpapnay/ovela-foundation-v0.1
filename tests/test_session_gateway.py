from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from app.authorization_context import AuthorizationState
from app.session_gateway import (
    AuthStrength,
    DPoPProofInvalid,
    DeviceBinding,
    DeviceBindingMethod,
    InMemoryReplayProtectionStore,
    InMemoryRevocationRegistry,
    ReplayAttackDetected,
    SessionContext,
    SessionContextExpired,
    SessionContextInvalid,
    SessionRevokedError,
    SessionSecurityGateway,
)


@pytest.fixture()
def gateway() -> SessionSecurityGateway:
    return SessionSecurityGateway(
        replay_store=InMemoryReplayProtectionStore(),
        revocation_registry=InMemoryRevocationRegistry(),
    )


@pytest.fixture()
def security_material() -> dict[str, object]:
    now = datetime.now(timezone.utc).replace(microsecond=0)

    return {
        "now": now,
        "tenant_id": uuid4(),
        "subject_id": uuid4(),
        "session_id": uuid4(),
        "token_jti": uuid4(),
        "issuer": "https://issuer.ovela.example",
        "audience": "ovela-api",
        "key_thumbprint": "dpop-thumbprint-001",
    }


def make_access_token_claims(
    security_material: dict[str, object],
    *,
    key_thumbprint: str | None = None,
    session_id: UUID | None = None,
    token_jti: UUID | None = None,
    expires_at: datetime | None = None,
    issued_at: datetime | None = None,
    auth_time: datetime | None = None,
) -> dict[str, object]:
    now = security_material["now"]
    tenant_id = security_material["tenant_id"]
    subject_id = security_material["subject_id"]
    default_session_id = security_material["session_id"]
    default_token_jti = security_material["token_jti"]
    issuer = security_material["issuer"]
    audience = security_material["audience"]
    default_thumbprint = security_material["key_thumbprint"]

    assert isinstance(now, datetime)
    assert isinstance(tenant_id, UUID)
    assert isinstance(subject_id, UUID)
    assert isinstance(default_session_id, UUID)
    assert isinstance(default_token_jti, UUID)
    assert isinstance(issuer, str)
    assert isinstance(audience, str)
    assert isinstance(default_thumbprint, str)

    effective_issued_at = issued_at or now
    effective_expires_at = expires_at or (
        now + timedelta(minutes=5)
    )
    effective_auth_time = auth_time or effective_issued_at
    effective_session_id = session_id or default_session_id
    effective_token_jti = token_jti or default_token_jti
    effective_thumbprint = (
        key_thumbprint
        if key_thumbprint is not None
        else default_thumbprint
    )

    return {
        "iss": issuer,
        "aud": audience,
        "sub": str(subject_id),
        "exp": effective_expires_at.timestamp(),
        "nbf": effective_issued_at.timestamp(),
        "iat": effective_issued_at.timestamp(),
        "auth_time": effective_auth_time.timestamp(),
        "tenant_id": str(tenant_id),
        "session_id": str(effective_session_id),
        "jti": str(effective_token_jti),
        "cnf": {
            "jkt": effective_thumbprint,
        },
    }


def make_dpop_proof(
    security_material: dict[str, object],
    *,
    key_thumbprint: str | None = None,
    dpop_jti: str | None = None,
    method: str = "GET",
    uri: str = "https://api.ovela.example/v1/resource",
    issued_at: datetime | None = None,
) -> dict[str, object]:
    now = security_material["now"]
    default_thumbprint = security_material["key_thumbprint"]

    assert isinstance(now, datetime)
    assert isinstance(default_thumbprint, str)

    effective_thumbprint = (
        key_thumbprint
        if key_thumbprint is not None
        else default_thumbprint
    )
    effective_jti = dpop_jti or str(uuid4())
    effective_issued_at = issued_at or now

    return {
        "htm": method,
        "htu": uri,
        "jti": effective_jti,
        "iat": effective_issued_at.timestamp(),
        "jkt": effective_thumbprint,
    }


def authenticate(
    gateway: SessionSecurityGateway,
    claims: dict[str, object],
    proof: dict[str, object],
    security_material: dict[str, object],
    *,
    auth_strength: AuthStrength = AuthStrength.AAL2_MFA,
) -> SessionContext:
    issuer = security_material["issuer"]
    audience = security_material["audience"]
    now = security_material["now"]

    assert isinstance(issuer, str)
    assert isinstance(audience, str)
    assert isinstance(now, datetime)

    return gateway.authenticate_and_issue_context(
        claims,
        proof,
        expected_issuer=issuer,
        expected_audience=audience,
        request_method="GET",
        request_uri="https://api.ovela.example/v1/resource",
        now=now,
        auth_strength=auth_strength,
        authentication_methods=("password", "mfa"),
    )


def test_matching_dpop_key_passes(
    gateway: SessionSecurityGateway,
    security_material: dict[str, object],
) -> None:
    claims = make_access_token_claims(security_material)
    proof = make_dpop_proof(security_material)

    context = authenticate(
        gateway,
        claims,
        proof,
        security_material,
    )

    assert isinstance(context, SessionContext)
    assert context.is_trusted()
    assert context.device_binding.method is DeviceBindingMethod.DPOP
    assert (
        context.device_binding.key_thumbprint
        == security_material["key_thumbprint"]
    )


def test_mismatched_dpop_key_thumbprint_fails_closed(
    gateway: SessionSecurityGateway,
    security_material: dict[str, object],
) -> None:
    claims = make_access_token_claims(
        security_material,
        key_thumbprint="token-bound-thumbprint",
    )
    proof = make_dpop_proof(
        security_material,
        key_thumbprint="different-proof-thumbprint",
    )

    with pytest.raises(DPoPProofInvalid):
        authenticate(
            gateway,
            claims,
            proof,
            security_material,
        )


def test_request_without_dpop_proof_fails_closed_when_binding_is_required(
    gateway: SessionSecurityGateway,
    security_material: dict[str, object],
) -> None:
    claims = make_access_token_claims(security_material)

    with pytest.raises(DPoPProofInvalid):
        authenticate(
            gateway,
            claims,
            {},
            security_material,
        )


def test_first_dpop_proof_consumes_dpop_jti_successfully(
    gateway: SessionSecurityGateway,
    security_material: dict[str, object],
) -> None:
    claims = make_access_token_claims(security_material)
    proof = make_dpop_proof(
        security_material,
        dpop_jti="unique-dpop-jti-001",
    )

    context = authenticate(
        gateway,
        claims,
        proof,
        security_material,
    )

    assert context.token_jti == security_material["token_jti"]


def test_replayed_dpop_proof_is_rejected(
    gateway: SessionSecurityGateway,
    security_material: dict[str, object],
) -> None:
    claims = make_access_token_claims(security_material)
    proof = make_dpop_proof(
        security_material,
        dpop_jti="replayed-dpop-jti-001",
    )

    first_context = authenticate(
        gateway,
        claims,
        proof,
        security_material,
    )

    assert first_context.is_trusted()

    with pytest.raises(ReplayAttackDetected):
        authenticate(
            gateway,
            claims,
            proof,
            security_material,
        )


def test_active_session_succeeds(
    gateway: SessionSecurityGateway,
    security_material: dict[str, object],
) -> None:
    claims = make_access_token_claims(security_material)
    proof = make_dpop_proof(
        security_material,
        dpop_jti="active-session-jti-001",
    )

    context = authenticate(
        gateway,
        claims,
        proof,
        security_material,
    )

    assert context.session_id == security_material["session_id"]
    assert context.subject_id == security_material["subject_id"]
    assert context.tenant_id == security_material["tenant_id"]


def test_revoking_session_id_causes_immediate_rejection(
    gateway: SessionSecurityGateway,
    security_material: dict[str, object],
) -> None:
    session_id = security_material["session_id"]
    assert isinstance(session_id, UUID)

    initial_claims = make_access_token_claims(security_material)
    initial_proof = make_dpop_proof(
        security_material,
        dpop_jti="session-revocation-initial",
    )

    context = authenticate(
        gateway,
        initial_claims,
        initial_proof,
        security_material,
    )

    assert context.session_id == session_id

    gateway.revocation_registry.revoke_session(
        session_id,
        reason="security-test",
    )

    revoked_claims = make_access_token_claims(
        security_material,
        token_jti=uuid4(),
    )
    revoked_proof = make_dpop_proof(
        security_material,
        dpop_jti="session-revocation-after-revoke",
    )

    with pytest.raises(SessionRevokedError):
        authenticate(
            gateway,
            revoked_claims,
            revoked_proof,
            security_material,
        )


def test_revoking_token_jti_causes_immediate_rejection(
    gateway: SessionSecurityGateway,
    security_material: dict[str, object],
) -> None:
    token_jti = security_material["token_jti"]
    assert isinstance(token_jti, UUID)

    claims = make_access_token_claims(security_material)
    proof = make_dpop_proof(
        security_material,
        dpop_jti="token-revocation-initial",
    )

    context = authenticate(
        gateway,
        claims,
        proof,
        security_material,
    )

    assert context.token_jti == token_jti

    gateway.revocation_registry.revoke_token(
        token_jti,
        reason="security-test",
    )

    revoked_proof = make_dpop_proof(
        security_material,
        dpop_jti="token-revocation-after-revoke",
    )

    with pytest.raises(SessionRevokedError):
        authenticate(
            gateway,
            claims,
            revoked_proof,
            security_material,
        )


def test_direct_session_context_without_issuer_marker_is_rejected(
    security_material: dict[str, object],
) -> None:
    now = security_material["now"]
    tenant_id = security_material["tenant_id"]
    subject_id = security_material["subject_id"]
    session_id = security_material["session_id"]
    token_jti = security_material["token_jti"]

    assert isinstance(now, datetime)
    assert isinstance(tenant_id, UUID)
    assert isinstance(subject_id, UUID)
    assert isinstance(session_id, UUID)
    assert isinstance(token_jti, UUID)

    context = SessionContext(
        session_id=session_id,
        tenant_id=tenant_id,
        subject_id=subject_id,
        device_binding=DeviceBinding(
            method=DeviceBindingMethod.DPOP,
            key_thumbprint="untrusted-thumbprint",
        ),
        auth_strength=AuthStrength.AAL2_MFA,
        authentication_methods=("password", "mfa"),
        token_jti=token_jti,
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
        issuer="https://issuer.ovela.example",
        audience=("ovela-api",),
        auth_time=now,
    )

    assert not context.is_trusted()

    with pytest.raises(SessionContextInvalid):
        context.require_trusted()


def test_expired_session_context_is_rejected(
    gateway: SessionSecurityGateway,
    security_material: dict[str, object],
) -> None:
    claims = make_access_token_claims(security_material)
    proof = make_dpop_proof(
        security_material,
        dpop_jti="expired-context-source",
    )

    context = authenticate(
        gateway,
        claims,
        proof,
        security_material,
    )

    now = security_material["now"]
    assert isinstance(now, datetime)

    expired_issued_at = now - timedelta(minutes=10)
    expired_expires_at = now - timedelta(seconds=1)

    expired_context = SessionContext(
        session_id=context.session_id,
        tenant_id=context.tenant_id,
        subject_id=context.subject_id,
        device_binding=context.device_binding,
        auth_strength=context.auth_strength,
        authentication_methods=context.authentication_methods,
        token_jti=context.token_jti,
        issued_at=expired_issued_at,
        expires_at=expired_expires_at,
        issuer=context.issuer,
        audience=context.audience,
        auth_time=expired_issued_at,
        scopes=context.scopes,
        _issuer_marker=context._issuer_marker,
    )

    with pytest.raises(SessionContextExpired):
        expired_context.require_valid_at(now)


def test_verified_session_context_maps_to_trusted_tenant_context(
    gateway: SessionSecurityGateway,
    security_material: dict[str, object],
) -> None:
    claims = make_access_token_claims(security_material)
    proof = make_dpop_proof(
        security_material,
        dpop_jti="tenant-context-mapping",
    )

    session_context = authenticate(
        gateway,
        claims,
        proof,
        security_material,
    )

    now = security_material["now"]
    assert isinstance(now, datetime)

    tenant_context = gateway.to_tenant_context(
        session_context,
        now,
    )

    assert tenant_context.tenant_id == session_context.tenant_id
    assert tenant_context.subject_id == session_context.subject_id
    assert tenant_context.session_id == session_context.session_id
    assert tenant_context.issued_at == session_context.issued_at
    assert tenant_context.expires_at == session_context.expires_at
    assert tenant_context.roles == session_context.scopes
    assert tenant_context.is_trusted()


def test_standard_auth_maps_to_authenticated_authorization_state(
    gateway: SessionSecurityGateway,
    security_material: dict[str, object],
) -> None:
    claims = make_access_token_claims(security_material)
    proof = make_dpop_proof(
        security_material,
        dpop_jti="authorization-authenticated",
    )

    session_context = authenticate(
        gateway,
        claims,
        proof,
        security_material,
        auth_strength=AuthStrength.AAL2_MFA,
    )

    now = security_material["now"]
    assert isinstance(now, datetime)

    authorization_context = gateway.to_authorization_context(
        session_context,
        now,
    )

    assert (
        authorization_context.state
        is AuthorizationState.AUTHENTICATED
    )
    assert (
        authorization_context.session_id
        == session_context.session_id
    )
    assert (
        authorization_context.subject_id
        == session_context.subject_id
    )


def test_step_up_auth_maps_to_step_up_verified_state(
    gateway: SessionSecurityGateway,
    security_material: dict[str, object],
) -> None:
    claims = make_access_token_claims(security_material)
    proof = make_dpop_proof(
        security_material,
        dpop_jti="authorization-step-up",
    )

    session_context = authenticate(
        gateway,
        claims,
        proof,
        security_material,
        auth_strength=AuthStrength.STEP_UP_VERIFIED,
    )

    now = security_material["now"]
    assert isinstance(now, datetime)

    authorization_context = gateway.to_authorization_context(
        session_context,
        now,
    )

    assert (
        authorization_context.state
        is AuthorizationState.STEP_UP_VERIFIED
    )
    assert (
        authorization_context.session_id
        == session_context.session_id
    )
    assert (
        authorization_context.subject_id
        == session_context.subject_id
    )