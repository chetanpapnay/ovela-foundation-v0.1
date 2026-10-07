from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from threading import RLock
from typing import Any, Callable, Mapping
from uuid import UUID, uuid4

from app.authorization_context import (
    AuthorizationContext,
    AuthorizationState,
)
from app.tenant_context import (
    IssuerCapability,
    TrustedTenantContextIssuer,
    TenantContext,
)


class SessionSecurityError(Exception):
    """Base exception for session-gateway security failures."""


class SessionContextInvalid(SessionSecurityError):
    """Raised when session credentials or context data are invalid."""


class SessionContextExpired(SessionSecurityError):
    """Raised when session credentials or context data have expired."""


class SessionRevokedError(SessionSecurityError):
    """Raised when a token, session, subject, or tenant is revoked."""


class DPoPProofInvalid(SessionSecurityError):
    """Raised when a DPoP proof is missing, malformed, or mismatched."""


class ReplayAttackDetected(SessionSecurityError):
    """Raised when a previously consumed DPoP proof is replayed."""


class AuthStrength(StrEnum):
    AAL1_PASSWORD = "AAL1_PASSWORD"
    AAL2_MFA = "AAL2_MFA"
    AAL3_HARDWARE_KEY = "AAL3_HARDWARE_KEY"
    STEP_UP_VERIFIED = "STEP_UP_VERIFIED"


class DeviceBindingMethod(StrEnum):
    DPOP = "DPOP"
    MTLS = "MTLS"


@dataclass(frozen=True, slots=True)
class DeviceBinding:
    method: DeviceBindingMethod
    key_thumbprint: str

    def __post_init__(self) -> None:
        if not isinstance(self.method, DeviceBindingMethod):
            try:
                object.__setattr__(
                    self,
                    "method",
                    DeviceBindingMethod(self.method),
                )
            except (TypeError, ValueError) as exc:
                raise SessionContextInvalid(
                    "invalid device binding method"
                ) from exc

        if not isinstance(self.key_thumbprint, str):
            raise SessionContextInvalid(
                "device binding key thumbprint must be a string"
            )

        if not self.key_thumbprint.strip():
            raise SessionContextInvalid(
                "device binding key thumbprint must not be empty"
            )


@dataclass(frozen=True, slots=True)
class SessionContext:
    session_id: UUID
    tenant_id: UUID
    subject_id: UUID
    device_binding: DeviceBinding
    auth_strength: AuthStrength
    authentication_methods: tuple[str, ...]
    token_jti: UUID
    issued_at: datetime
    expires_at: datetime
    issuer: str
    audience: tuple[str, ...]
    auth_time: datetime
    scopes: frozenset[str] = frozenset()
    _issuer_marker: object = field(
        default=None,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        for name, value in (
            ("session_id", self.session_id),
            ("tenant_id", self.tenant_id),
            ("subject_id", self.subject_id),
            ("token_jti", self.token_jti),
        ):
            if not isinstance(value, UUID):
                raise SessionContextInvalid(
                    f"{name} must be a UUID"
                )

        if not isinstance(self.device_binding, DeviceBinding):
            raise SessionContextInvalid(
                "device_binding must be a DeviceBinding"
            )

        if not isinstance(self.auth_strength, AuthStrength):
            try:
                object.__setattr__(
                    self,
                    "auth_strength",
                    AuthStrength(self.auth_strength),
                )
            except (TypeError, ValueError) as exc:
                raise SessionContextInvalid(
                    "invalid authentication strength"
                ) from exc

        if not isinstance(self.authentication_methods, tuple):
            raise SessionContextInvalid(
                "authentication_methods must be a tuple"
            )

        if any(
            not isinstance(method, str) or not method.strip()
            for method in self.authentication_methods
        ):
            raise SessionContextInvalid(
                "authentication_methods must contain non-empty strings"
            )

        if not isinstance(self.issuer, str) or not self.issuer.strip():
            raise SessionContextInvalid(
                "issuer must be a non-empty string"
            )

        if not isinstance(self.audience, tuple):
            raise SessionContextInvalid(
                "audience must be a tuple"
            )

        if any(
            not isinstance(value, str) or not value.strip()
            for value in self.audience
        ):
            raise SessionContextInvalid(
                "audience must contain non-empty strings"
            )

        if not isinstance(self.scopes, frozenset):
            try:
                object.__setattr__(
                    self,
                    "scopes",
                    frozenset(self.scopes),
                )
            except TypeError as exc:
                raise SessionContextInvalid(
                    "scopes must be a collection of strings"
                ) from exc

        if any(
            not isinstance(scope, str) or not scope.strip()
            for scope in self.scopes
        ):
            raise SessionContextInvalid(
                "scopes must contain non-empty strings"
            )

        _require_aware_datetime(self.issued_at, "issued_at")
        _require_aware_datetime(self.expires_at, "expires_at")
        _require_aware_datetime(self.auth_time, "auth_time")

        if _utc(self.expires_at) <= _utc(self.issued_at):
            raise SessionContextInvalid(
                "expires_at must be later than issued_at"
            )

        if _utc(self.auth_time) > _utc(self.expires_at):
            raise SessionContextInvalid(
                "auth_time must not be later than expires_at"
            )

    def is_trusted(self) -> bool:
        return self._issuer_marker is _SESSION_CONTEXT_ISSUER_MARKER

    def require_trusted(self) -> None:
        if not self.is_trusted():
            raise SessionContextInvalid(
                "session context lacks trusted issuer provenance"
            )

    def is_valid_at(self, now: datetime) -> bool:
        self.require_trusted()

        if not isinstance(now, datetime):
            return False

        if now.tzinfo is None or now.utcoffset() is None:
            return False

        current = _utc(now)
        issued = _utc(self.issued_at)
        expires = _utc(self.expires_at)

        return issued <= current < expires

    def require_valid_at(self, now: datetime) -> None:
        self.require_trusted()

        current = _require_aware_datetime(now, "now")

        if current >= _utc(self.expires_at):
            raise SessionContextExpired(
                "session context has expired"
            )

        if current < _utc(self.issued_at):
            raise SessionContextInvalid(
                "session context is not yet valid"
            )


_SESSION_CONTEXT_ISSUER_MARKER = object()


class InMemoryReplayProtectionStore:
    """Thread-safe in-memory DPoP replay protection store."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._entries: dict[
            tuple[UUID, UUID, str, str],
            datetime,
        ] = {}

    def try_consume_dpop_proof(
        self,
        tenant_id: UUID,
        subject_id: UUID,
        key_thumbprint: str,
        dpop_jti: str,
        now: datetime,
        ttl_seconds: int = 300,
    ) -> bool:
        _require_uuid(tenant_id, "tenant_id")
        _require_uuid(subject_id, "subject_id")

        if not isinstance(key_thumbprint, str):
            raise DPoPProofInvalid(
                "DPoP key thumbprint must be a string"
            )

        if not key_thumbprint.strip():
            raise DPoPProofInvalid(
                "DPoP key thumbprint must not be empty"
            )

        if not isinstance(dpop_jti, str):
            raise DPoPProofInvalid(
                "DPoP JTI must be a string"
            )

        if not dpop_jti.strip():
            raise DPoPProofInvalid(
                "DPoP JTI must not be empty"
            )

        current = _require_aware_datetime(now, "now")

        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, int)
            or ttl_seconds <= 0
        ):
            raise ValueError(
                "ttl_seconds must be a positive integer"
            )

        replay_key = (
            tenant_id,
            subject_id,
            key_thumbprint,
            dpop_jti,
        )

        expiry = current + timedelta_seconds(ttl_seconds)

        with self._lock:
            expired_keys = [
                existing_key
                for existing_key, existing_expiry in self._entries.items()
                if existing_expiry <= current
            ]

            for expired_key in expired_keys:
                del self._entries[expired_key]

            if replay_key in self._entries:
                return False

            self._entries[replay_key] = expiry
            return True


class InMemoryRevocationRegistry:
    """Thread-safe in-memory token/session revocation registry."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._revoked_tokens: dict[UUID, str] = {}
        self._revoked_sessions: dict[UUID, str] = {}
        self._revoked_subjects: dict[UUID, str] = {}
        self._revoked_tenants: dict[UUID, str] = {}

    def is_revoked(
        self,
        token_jti: UUID,
        session_id: UUID,
        subject_id: UUID,
        tenant_id: UUID,
    ) -> bool:
        _require_uuid(token_jti, "token_jti")
        _require_uuid(session_id, "session_id")
        _require_uuid(subject_id, "subject_id")
        _require_uuid(tenant_id, "tenant_id")

        with self._lock:
            return (
                token_jti in self._revoked_tokens
                or session_id in self._revoked_sessions
                or subject_id in self._revoked_subjects
                or tenant_id in self._revoked_tenants
            )

    def revoke_session(
        self,
        session_id: UUID,
        reason: str = "",
    ) -> None:
        _require_uuid(session_id, "session_id")

        if not isinstance(reason, str):
            reason = str(reason)

        with self._lock:
            self._revoked_sessions[session_id] = reason

    def revoke_token(
        self,
        token_jti: UUID,
        reason: str = "",
    ) -> None:
        _require_uuid(token_jti, "token_jti")

        if not isinstance(reason, str):
            reason = str(reason)

        with self._lock:
            self._revoked_tokens[token_jti] = reason

    def revoke_subject(
        self,
        subject_id: UUID,
        reason: str = "",
    ) -> None:
        _require_uuid(subject_id, "subject_id")

        if not isinstance(reason, str):
            reason = str(reason)

        with self._lock:
            self._revoked_subjects[subject_id] = reason

    def revoke_tenant(
        self,
        tenant_id: UUID,
        reason: str = "",
    ) -> None:
        _require_uuid(tenant_id, "tenant_id")

        if not isinstance(reason, str):
            reason = str(reason)

        with self._lock:
            self._revoked_tenants[tenant_id] = reason


class TrustedSessionContextIssuer:
    """Capability-guarded issuer for trusted SessionContext objects."""

    _CAPABILITY = object()

    @classmethod
    def capability(cls) -> object:
        return cls._CAPABILITY

    @classmethod
    def issue_session_context(
        cls,
        capability: object,
        *,
        session_id: UUID,
        tenant_id: UUID,
        subject_id: UUID,
        device_binding: DeviceBinding,
        auth_strength: AuthStrength,
        authentication_methods: tuple[str, ...],
        token_jti: UUID,
        issued_at: datetime,
        expires_at: datetime,
        issuer: str,
        audience: tuple[str, ...],
        auth_time: datetime,
        scopes: frozenset[str] = frozenset(),
    ) -> SessionContext:
        if capability is not cls._CAPABILITY:
            raise SessionContextInvalid(
                "invalid session-context issuer capability"
            )

        return SessionContext(
            session_id=session_id,
            tenant_id=tenant_id,
            subject_id=subject_id,
            device_binding=device_binding,
            auth_strength=auth_strength,
            authentication_methods=authentication_methods,
            token_jti=token_jti,
            issued_at=issued_at,
            expires_at=expires_at,
            issuer=issuer,
            audience=audience,
            auth_time=auth_time,
            scopes=scopes,
            _issuer_marker=_SESSION_CONTEXT_ISSUER_MARKER,
        )


AuthorizationIssuer = Callable[
    [
        UUID,
        UUID,
        AuthorizationState,
        datetime,
        datetime,
        object,
    ],
    AuthorizationContext,
]


class SessionSecurityGateway:
    """
    Zero-trust session security gateway.

    Untrusted token and proof claims are accepted only at this boundary.
    A trusted SessionContext is emitted only after identity binding,
    temporal validation, replay protection, and revocation checks succeed.
    """

    def __init__(
        self,
        replay_store: InMemoryReplayProtectionStore | None = None,
        revocation_registry: InMemoryRevocationRegistry | None = None,
        authorization_issuer: AuthorizationIssuer | None = None,
    ) -> None:
        self.replay_store = (
            replay_store
            if replay_store is not None
            else InMemoryReplayProtectionStore()
        )

        self.revocation_registry = (
            revocation_registry
            if revocation_registry is not None
            else InMemoryRevocationRegistry()
        )

        self.authorization_issuer = authorization_issuer

    def authenticate_and_issue_context(
        self,
        access_token_claims: Mapping[str, Any],
        dpop_proof: Mapping[str, Any],
        *,
        expected_issuer: str,
        expected_audience: str | tuple[str, ...] | frozenset[str],
        request_method: str,
        request_uri: str,
        now: datetime | None = None,
        session_id: UUID | None = None,
        auth_strength: AuthStrength = AuthStrength.AAL1_PASSWORD,
        authentication_methods: tuple[str, ...] = (),
        scopes: frozenset[str] = frozenset(),
        replay_ttl_seconds: int = 300,
    ) -> SessionContext:
        current_time = _require_aware_datetime(
            now if now is not None else datetime.now(timezone.utc),
            "now",
        )

        if not isinstance(access_token_claims, Mapping):
            raise SessionContextInvalid(
                "access-token claims must be a mapping"
            )

        if not isinstance(dpop_proof, Mapping):
            raise DPoPProofInvalid(
                "DPoP proof must be a mapping"
            )

        if not isinstance(expected_issuer, str):
            raise SessionContextInvalid(
                "expected issuer must be a string"
            )

        if not expected_issuer.strip():
            raise SessionContextInvalid(
                "expected issuer must not be empty"
            )

        issuer = access_token_claims.get("iss")

        if issuer != expected_issuer:
            raise SessionContextInvalid(
                "access-token issuer validation failed"
            )

        expected_audiences = _normalize_expected_audience(
            expected_audience
        )

        token_audience = _normalize_token_audience(
            access_token_claims.get("aud")
        )

        if not token_audience:
            raise SessionContextInvalid(
                "access token is missing audience"
            )

        if not set(expected_audiences).intersection(token_audience):
            raise SessionContextInvalid(
                "access-token audience validation failed"
            )

        subject_id = _parse_uuid_claim(
            access_token_claims.get("sub"),
            "sub",
        )

        tenant_id = _parse_uuid_claim(
            access_token_claims.get("tenant_id"),
            "tenant_id",
        )

        token_jti = _parse_uuid_claim(
            access_token_claims.get("jti"),
            "jti",
        )

        expires_at = _parse_numeric_datetime_claim(
            access_token_claims.get("exp"),
            "exp",
        )

        if current_time >= expires_at:
            raise SessionContextExpired(
                "access token has expired"
            )

        not_before_value = access_token_claims.get("nbf")

        if not_before_value is not None:
            not_before = _parse_numeric_datetime_claim(
                not_before_value,
                "nbf",
            )

            if current_time < not_before:
                raise SessionContextInvalid(
                    "access token is not yet valid"
                )

        issued_at = _parse_datetime_claim(
            access_token_claims.get("iat", current_time),
            "iat",
        )

        if issued_at > expires_at:
            raise SessionContextInvalid(
                "access-token issued-at time is later than expiry"
            )

        auth_time = _parse_datetime_claim(
            access_token_claims.get("auth_time", issued_at),
            "auth_time",
        )

        if auth_time > current_time:
            raise SessionContextInvalid(
                "authentication time cannot be in the future"
            )

        if auth_time > expires_at:
            raise SessionContextInvalid(
                "authentication time cannot be later than token expiry"
            )

        cnf = access_token_claims.get("cnf")

        if not isinstance(cnf, Mapping):
            raise DPoPProofInvalid(
                "access token is missing confirmation data"
            )

        token_thumbprint = cnf.get("jkt")

        if (
            not isinstance(token_thumbprint, str)
            or not token_thumbprint.strip()
        ):
            raise DPoPProofInvalid(
                "access token is missing cnf.jkt"
            )

        proof_method = dpop_proof.get("htm")

        if not isinstance(proof_method, str):
            raise DPoPProofInvalid(
                "DPoP proof is missing htm"
            )

        if not isinstance(request_method, str):
            raise DPoPProofInvalid(
                "request method must be a string"
            )

        if proof_method.upper() != request_method.upper():
            raise DPoPProofInvalid(
                "DPoP HTTP method does not match the request"
            )

        proof_uri = dpop_proof.get("htu")

        if not isinstance(proof_uri, str) or not proof_uri.strip():
            raise DPoPProofInvalid(
                "DPoP proof is missing htu"
            )

        if not isinstance(request_uri, str) or not request_uri.strip():
            raise DPoPProofInvalid(
                "request URI must be a non-empty string"
            )

        if proof_uri != request_uri:
            raise DPoPProofInvalid(
                "DPoP URI does not match the request URI"
            )

        proof_thumbprint = _extract_dpop_thumbprint(
            dpop_proof
        )

        if proof_thumbprint != token_thumbprint:
            raise DPoPProofInvalid(
                "DPoP public-key thumbprint does not match cnf.jkt"
            )

        dpop_jti = dpop_proof.get("jti")

        if not isinstance(dpop_jti, str) or not dpop_jti.strip():
            raise DPoPProofInvalid(
                "DPoP proof is missing jti"
            )

        if (
            isinstance(replay_ttl_seconds, bool)
            or not isinstance(replay_ttl_seconds, int)
            or replay_ttl_seconds <= 0
        ):
            raise SessionContextInvalid(
                "replay_ttl_seconds must be a positive integer"
            )

        dpop_iat = dpop_proof.get("iat")

        if dpop_iat is not None:
            dpop_issued_at = _parse_numeric_datetime_claim(
                dpop_iat,
                "dpop.iat",
            )

            if dpop_issued_at > current_time:
                raise DPoPProofInvalid(
                    "DPoP proof was issued in the future"
                )

            proof_age = (
                current_time - dpop_issued_at
            ).total_seconds()

            if proof_age > replay_ttl_seconds:
                raise DPoPProofInvalid(
                    "DPoP proof is too old"
                )

            if proof_age < 0:
                raise DPoPProofInvalid(
                    "DPoP proof has an invalid issue time"
                )

        effective_session_id = session_id

        claimed_session_id = access_token_claims.get(
            "session_id"
        )

        if effective_session_id is None:
            if claimed_session_id is None:
                raise SessionContextInvalid(
                    "session ID is required"
                )

            effective_session_id = _parse_uuid_claim(
                claimed_session_id,
                "session_id",
            )
        else:
            _require_uuid(
                effective_session_id,
                "session_id",
            )

            if claimed_session_id is not None:
                parsed_claimed_session_id = _parse_uuid_claim(
                    claimed_session_id,
                    "session_id",
                )

                if parsed_claimed_session_id != effective_session_id:
                    raise SessionContextInvalid(
                        "session ID does not match the access-token claim"
                    )

        consumed = self.replay_store.try_consume_dpop_proof(
            tenant_id=tenant_id,
            subject_id=subject_id,
            key_thumbprint=token_thumbprint,
            dpop_jti=dpop_jti,
            now=current_time,
            ttl_seconds=replay_ttl_seconds,
        )

        if not consumed:
            raise ReplayAttackDetected(
                "duplicate DPoP proof detected"
            )

        if self.revocation_registry.is_revoked(
            token_jti=token_jti,
            session_id=effective_session_id,
            subject_id=subject_id,
            tenant_id=tenant_id,
        ):
            raise SessionRevokedError(
                "session, token, subject, or tenant has been revoked"
            )

        normalized_auth_strength = _normalize_auth_strength(
            auth_strength
        )

        normalized_authentication_methods = (
            _normalize_string_tuple(
                authentication_methods,
                "authentication_methods",
            )
        )

        normalized_scopes = _normalize_scopes(scopes)

        device_binding = DeviceBinding(
            method=DeviceBindingMethod.DPOP,
            key_thumbprint=token_thumbprint,
        )

        return TrustedSessionContextIssuer.issue_session_context(
            TrustedSessionContextIssuer.capability(),
            session_id=effective_session_id,
            tenant_id=tenant_id,
            subject_id=subject_id,
            device_binding=device_binding,
            auth_strength=normalized_auth_strength,
            authentication_methods=normalized_authentication_methods,
            token_jti=token_jti,
            issued_at=issued_at,
            expires_at=expires_at,
            issuer=issuer,
            audience=token_audience,
            auth_time=auth_time,
            scopes=normalized_scopes,
        )

    def to_tenant_context(
        self,
        session_context: SessionContext,
        now: datetime,
    ) -> TenantContext:
        if not isinstance(session_context, SessionContext):
            raise SessionContextInvalid(
                "session_context must be a SessionContext"
            )

        current_time = _require_aware_datetime(
            now,
            "now",
        )

        session_context.require_valid_at(current_time)

        try:
            capability = IssuerCapability.mint()
            issuer = TrustedTenantContextIssuer(capability)

            return issuer.issue_context(
                capability,
                session_context.tenant_id,
                session_context.subject_id,
                session_context.session_id,
                session_context.issued_at,
                session_context.expires_at,
                frozenset(session_context.scopes),
            )
        except SessionContextInvalid:
            raise
        except Exception as exc:
            raise SessionContextInvalid(
                "trusted tenant-context issuance failed"
            ) from exc

    def to_authorization_context(
        self,
        session_context: SessionContext,
        now: datetime,
    ) -> AuthorizationContext:
        if not isinstance(session_context, SessionContext):
            raise SessionContextInvalid(
                "session_context must be a SessionContext"
            )

        current_time = _require_aware_datetime(
            now,
            "now",
        )

        session_context.require_valid_at(current_time)

        if (
            session_context.auth_strength
            is AuthStrength.STEP_UP_VERIFIED
        ):
            state = AuthorizationState.STEP_UP_VERIFIED
        else:
            state = AuthorizationState.AUTHENTICATED

        if self.authorization_issuer is not None:
            try:
                authorization_context = self.authorization_issuer(
                    session_context.session_id,
                    session_context.subject_id,
                    state,
                    session_context.issued_at,
                    session_context.expires_at,
                    session_context._issuer_marker,
                )
            except SessionSecurityError:
                raise
            except Exception as exc:
                raise SessionContextInvalid(
                    "authorization-context issuance failed"
                ) from exc

            if not isinstance(
                authorization_context,
                AuthorizationContext,
            ):
                raise SessionContextInvalid(
                    "authorization issuer returned an invalid context"
                )

            return authorization_context

        return AuthorizationContext(
            context_id=uuid4(),
            session_id=session_context.session_id,
            subject_id=session_context.subject_id,
            state=state,
            issued_at=session_context.issued_at,
            expires_at=session_context.expires_at,
            _issuer_marker=session_context._issuer_marker,
        )


def timedelta_seconds(seconds: int) -> Any:
    from datetime import timedelta

    return timedelta(seconds=seconds)


def _utc(value: datetime) -> datetime:
    return value.astimezone(timezone.utc)


def _require_aware_datetime(
    value: datetime,
    name: str,
) -> datetime:
    if not isinstance(value, datetime):
        raise SessionContextInvalid(
            f"{name} must be a datetime"
        )

    if value.tzinfo is None or value.utcoffset() is None:
        raise SessionContextInvalid(
            f"{name} must be timezone-aware"
        )

    return _utc(value)


def _require_uuid(
    value: object,
    name: str,
) -> UUID:
    if not isinstance(value, UUID):
        raise SessionContextInvalid(
            f"{name} must be a UUID"
        )

    return value


def _parse_uuid_claim(
    value: object,
    name: str,
) -> UUID:
    if isinstance(value, UUID):
        return value

    if not isinstance(value, str) or not value.strip():
        raise SessionContextInvalid(
            f"access-token claim {name} must contain a UUID"
        )

    try:
        return UUID(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise SessionContextInvalid(
            f"access-token claim {name} is not a valid UUID"
        ) from exc


def _parse_numeric_datetime_claim(
    value: object,
    name: str,
) -> datetime:
    if isinstance(value, bool):
        raise SessionContextInvalid(
            f"{name} must be a numeric timestamp"
        )

    if not isinstance(value, (int, float)):
        raise SessionContextInvalid(
            f"{name} must be a numeric timestamp"
        )

    try:
        return datetime.fromtimestamp(
            float(value),
            tz=timezone.utc,
        )
    except (OverflowError, OSError, ValueError) as exc:
        raise SessionContextInvalid(
            f"{name} contains an invalid timestamp"
        ) from exc


def _parse_datetime_claim(
    value: object,
    name: str,
) -> datetime:
    if isinstance(value, datetime):
        return _require_aware_datetime(
            value,
            name,
        )

    if isinstance(value, bool):
        raise SessionContextInvalid(
            f"{name} contains an invalid timestamp"
        )

    if isinstance(value, (int, float)):
        return _parse_numeric_datetime_claim(
            value,
            name,
        )

    if isinstance(value, str):
        raw = value.strip()

        if not raw:
            raise SessionContextInvalid(
                f"{name} contains an empty timestamp"
            )

        try:
            parsed = datetime.fromisoformat(
                raw.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise SessionContextInvalid(
                f"{name} contains an invalid timestamp"
            ) from exc

        return _require_aware_datetime(
            parsed,
            name,
        )

    raise SessionContextInvalid(
        f"{name} contains an unsupported timestamp type"
    )


def _normalize_expected_audience(
    audience: str | tuple[str, ...] | frozenset[str],
) -> tuple[str, ...]:
    if isinstance(audience, str):
        values = (audience,)
    elif isinstance(audience, (tuple, frozenset)):
        values = tuple(audience)
    else:
        raise SessionContextInvalid(
            "expected audience must be a string or collection of strings"
        )

    if not values:
        raise SessionContextInvalid(
            "expected audience must not be empty"
        )

    if any(
        not isinstance(value, str) or not value.strip()
        for value in values
    ):
        raise SessionContextInvalid(
            "expected audience must contain non-empty strings"
        )

    return tuple(dict.fromkeys(values))


def _normalize_token_audience(
    value: object,
) -> tuple[str, ...]:
    if isinstance(value, str):
        values = (value,)
    elif isinstance(
        value,
        (list, tuple, set, frozenset),
    ):
        values = tuple(value)
    else:
        raise SessionContextInvalid(
            "access-token aud claim must be a string or sequence of strings"
        )

    if not values:
        raise SessionContextInvalid(
            "access-token aud claim must not be empty"
        )

    if any(
        not isinstance(item, str) or not item.strip()
        for item in values
    ):
        raise SessionContextInvalid(
            "access-token aud claim must contain non-empty strings"
        )

    return tuple(dict.fromkeys(values))


def _normalize_auth_strength(
    value: AuthStrength,
) -> AuthStrength:
    if isinstance(value, AuthStrength):
        return value

    try:
        return AuthStrength(value)
    except (TypeError, ValueError) as exc:
        raise SessionContextInvalid(
            "invalid authentication strength"
        ) from exc


def _normalize_string_tuple(
    values: tuple[str, ...],
    name: str,
) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise SessionContextInvalid(
            f"{name} must be a tuple"
        )

    if any(
        not isinstance(value, str) or not value.strip()
        for value in values
    ):
        raise SessionContextInvalid(
            f"{name} must contain non-empty strings"
        )

    return tuple(dict.fromkeys(values))


def _normalize_scopes(
    scopes: frozenset[str],
) -> frozenset[str]:
    if not isinstance(
        scopes,
        (frozenset, set, tuple, list),
    ):
        raise SessionContextInvalid(
            "scopes must be a collection of strings"
        )

    normalized = frozenset(scopes)

    if any(
        not isinstance(scope, str) or not scope.strip()
        for scope in normalized
    ):
        raise SessionContextInvalid(
            "scopes must contain non-empty strings"
        )

    return normalized


def _extract_dpop_thumbprint(
    dpop_proof: Mapping[str, Any],
) -> str:
    direct_jkt = dpop_proof.get("jkt")

    if isinstance(direct_jkt, str) and direct_jkt.strip():
        return direct_jkt

    jwk = dpop_proof.get("jwk")

    if isinstance(jwk, Mapping):
        nested_jkt = jwk.get("jkt")

        if (
            isinstance(nested_jkt, str)
            and nested_jkt.strip()
        ):
            return nested_jkt

    raise DPoPProofInvalid(
        "DPoP proof does not contain a usable public-key thumbprint"
    )