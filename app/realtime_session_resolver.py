"""
OVELA / JURIX realtime session resolver.

This module bridges an authenticated WebSocket transport to the existing
SessionSecurityGateway.

Security boundary
-----------------
The WebSocket client is never allowed to establish:

- subject identity
- session identity
- authorization state
- authentication strength
- scopes
- step-up status
- OVELA privileges

This resolver therefore does NOT decode JWTs, trust JSON protocol messages,
or derive authorization from arbitrary WebSocket headers.

Instead, a server-side credential verifier is injected. That verifier is
responsible for cryptographically authenticating the transport credentials
and returning verified claims/proof data.

Those verified credentials are then passed through SessionSecurityGateway,
which performs:

- issuer validation
- audience validation
- subject/tenant/session validation
- token lifetime validation
- DPoP binding validation
- DPoP replay protection
- revocation checks
- trusted SessionContext issuance

Only after the SessionSecurityGateway succeeds is the resulting
SessionContext converted into a trusted AuthorizationContext.

The resolver fails closed if any required dependency or credential is absent
or invalid.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Mapping
from uuid import UUID

from fastapi import WebSocket

from app.authorization_context import AuthorizationContext
from app.session_gateway import (
    AuthStrength,
    SessionContextExpired,
    SessionContextInvalid,
    SessionRevokedError,
    DPoPProofInvalid,
    ReplayAttackDetected,
    SessionSecurityError,
    SessionSecurityGateway,
)


class RealtimeSessionResolutionError(Exception):
    """Base error for realtime session resolution failures."""


class RealtimeAuthenticationRequired(
    RealtimeSessionResolutionError
):
    """Raised when no authenticated realtime credentials are available."""


class RealtimeAuthenticationFailed(
    RealtimeSessionResolutionError
):
    """Raised when transport authentication fails."""


class RealtimeCredentialVerificationError(
    RealtimeSessionResolutionError
):
    """Raised when the upstream credential verifier rejects credentials."""


@dataclass(frozen=True, slots=True)
class VerifiedRealtimeCredentials:
    """
    Cryptographically verified transport credentials.

    This object MUST only be constructed by the trusted credential
    verification layer supplied to GatewayRealtimeSessionResolver.

    The resolver does not treat raw WebSocket headers as these credentials.
    """

    access_token_claims: Mapping[str, Any]
    dpop_proof: Mapping[str, Any]

    auth_strength: AuthStrength
    authentication_methods: tuple[str, ...]

    scopes: frozenset[str]

    session_id: UUID | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.access_token_claims, Mapping):
            raise TypeError(
                "access_token_claims must be a mapping"
            )

        if not isinstance(self.dpop_proof, Mapping):
            raise TypeError(
                "dpop_proof must be a mapping"
            )

        if not isinstance(self.auth_strength, AuthStrength):
            try:
                normalized_strength = AuthStrength(
                    self.auth_strength
                )
            except (TypeError, ValueError) as exc:
                raise TypeError(
                    "auth_strength must be a valid AuthStrength"
                ) from exc

            object.__setattr__(
                self,
                "auth_strength",
                normalized_strength,
            )

        if not isinstance(
            self.authentication_methods,
            tuple,
        ):
            raise TypeError(
                "authentication_methods must be a tuple"
            )

        if any(
            not isinstance(method, str) or not method.strip()
            for method in self.authentication_methods
        ):
            raise TypeError(
                "authentication_methods must contain non-empty strings"
            )

        if not isinstance(self.scopes, frozenset):
            raise TypeError(
                "scopes must be a frozenset"
            )

        if any(
            not isinstance(scope, str) or not scope.strip()
            for scope in self.scopes
        ):
            raise TypeError(
                "scopes must contain non-empty strings"
            )

        if self.session_id is not None and not isinstance(
            self.session_id,
            UUID,
        ):
            raise TypeError(
                "session_id must be a UUID or None"
            )


CredentialVerifier = Callable[
    [WebSocket],
    VerifiedRealtimeCredentials
    | None
    | Awaitable[
        VerifiedRealtimeCredentials
        | None
    ],
]


class GatewayRealtimeSessionResolver:
    """
    Concrete RealtimeSessionResolver implementation.

    Flow:

        WebSocket
            |
            v
        server-side credential verifier
            |
            v
        VerifiedRealtimeCredentials
            |
            v
        SessionSecurityGateway.authenticate_and_issue_context(...)
            |
            v
        trusted SessionContext
            |
            v
        SessionSecurityGateway.to_authorization_context(...)
            |
            v
        trusted AuthorizationContext

    The resolver never accepts authorization state, session ID, subject ID,
    or step-up status from the realtime JSON protocol.
    """

    def __init__(
        self,
        *,
        gateway: SessionSecurityGateway,
        credential_verifier: CredentialVerifier,
        expected_issuer: str,
        expected_audience: (
            str
            | tuple[str, ...]
            | frozenset[str]
        ),
        replay_ttl_seconds: int = 300,
    ) -> None:
        if not isinstance(
            gateway,
            SessionSecurityGateway,
        ):
            raise TypeError(
                "gateway must be a SessionSecurityGateway"
            )

        if not callable(credential_verifier):
            raise TypeError(
                "credential_verifier must be callable"
            )

        if not isinstance(expected_issuer, str):
            raise TypeError(
                "expected_issuer must be a string"
            )

        if not expected_issuer.strip():
            raise ValueError(
                "expected_issuer must not be empty"
            )

        if isinstance(expected_audience, str):
            if not expected_audience.strip():
                raise ValueError(
                    "expected_audience must not be empty"
                )
        elif isinstance(
            expected_audience,
            (tuple, frozenset),
        ):
            if not expected_audience:
                raise ValueError(
                    "expected_audience must not be empty"
                )

            if any(
                not isinstance(value, str)
                or not value.strip()
                for value in expected_audience
            ):
                raise ValueError(
                    "expected_audience must contain non-empty strings"
                )
        else:
            raise TypeError(
                "expected_audience must be a string, tuple, or frozenset"
            )

        if (
            isinstance(replay_ttl_seconds, bool)
            or not isinstance(replay_ttl_seconds, int)
        ):
            raise TypeError(
                "replay_ttl_seconds must be an integer"
            )

        if replay_ttl_seconds <= 0:
            raise ValueError(
                "replay_ttl_seconds must be positive"
            )

        self._gateway = gateway
        self._credential_verifier = credential_verifier
        self._expected_issuer = expected_issuer
        self._expected_audience = expected_audience
        self._replay_ttl_seconds = replay_ttl_seconds

    async def resolve(
        self,
        websocket: WebSocket,
    ) -> AuthorizationContext | None:
        """
        Resolve a WebSocket into a trusted AuthorizationContext.

        Returns None only when no authenticated session can be established.

        All authentication/security failures are converted into
        RealtimeSessionResolutionError subclasses so the transport boundary
        can fail closed without exposing internal authentication details.
        """

        if not isinstance(websocket, WebSocket):
            raise TypeError(
                "websocket must be a FastAPI WebSocket"
            )

        credentials = await self._verify_transport_credentials(
            websocket
        )

        if credentials is None:
            raise RealtimeAuthenticationRequired(
                "authenticated realtime credentials are required"
            )

        current_time = datetime.now(timezone.utc)

        request_method = self._request_method(
            websocket
        )

        request_uri = self._request_uri(
            websocket
        )

        try:
            session_context = (
                self._gateway.authenticate_and_issue_context(
                    credentials.access_token_claims,
                    credentials.dpop_proof,
                    expected_issuer=self._expected_issuer,
                    expected_audience=self._expected_audience,
                    request_method=request_method,
                    request_uri=request_uri,
                    now=current_time,
                    session_id=credentials.session_id,
                    auth_strength=credentials.auth_strength,
                    authentication_methods=(
                        credentials.authentication_methods
                    ),
                    scopes=credentials.scopes,
                    replay_ttl_seconds=(
                        self._replay_ttl_seconds
                    ),
                )
            )

            authorization_context = (
                self._gateway.to_authorization_context(
                    session_context,
                    current_time,
                )
            )

        except (
            SessionContextExpired,
            SessionContextInvalid,
            SessionRevokedError,
            DPoPProofInvalid,
            ReplayAttackDetected,
        ) as exc:
            raise RealtimeAuthenticationFailed(
                "realtime session authentication failed"
            ) from exc

        except SessionSecurityError as exc:
            raise RealtimeAuthenticationFailed(
                "realtime session security validation failed"
            ) from exc

        except Exception as exc:
            raise RealtimeAuthenticationFailed(
                "realtime session resolution failed"
            ) from exc

        self._require_trusted_authorization_context(
            authorization_context
        )

        return authorization_context

    async def _verify_transport_credentials(
        self,
        websocket: WebSocket,
    ) -> VerifiedRealtimeCredentials | None:
        """
        Ask the server-side credential verifier for verified credentials.

        This method deliberately does not:

        - parse JWT payloads
        - base64-decode JWTs
        - trust Authorization headers directly
        - trust DPoP headers directly
        - read session IDs from query parameters
        - read authorization state from cookies
        - read identity claims from WebSocket JSON

        Cryptographic verification belongs to the injected authentication
        subsystem, not this transport adapter.
        """

        try:
            result = self._credential_verifier(
                websocket
            )

            if hasattr(result, "__await__"):
                result = await result

        except RealtimeSessionResolutionError:
            raise

        except Exception as exc:
            raise RealtimeCredentialVerificationError(
                "realtime credential verification failed"
            ) from exc

        if result is None:
            return None

        if not isinstance(
            result,
            VerifiedRealtimeCredentials,
        ):
            raise RealtimeCredentialVerificationError(
                "credential verifier returned invalid credentials"
            )

        return result

    @staticmethod
    def _request_method(
        websocket: WebSocket,
    ) -> str:
        """
        Obtain the transport method from the ASGI scope.

        WebSocket handshakes are normally represented as GET requests.
        The value is taken from the server-created scope rather than from
        client application JSON.
        """

        method = websocket.scope.get(
            "method",
            "GET",
        )

        if not isinstance(method, str):
            raise RealtimeAuthenticationFailed(
                "invalid realtime request method"
            )

        normalized = method.strip().upper()

        if not normalized:
            raise RealtimeAuthenticationFailed(
                "missing realtime request method"
            )

        return normalized

    @staticmethod
    def _request_uri(
        websocket: WebSocket,
    ) -> str:
        """
        Obtain the canonical request URI from the ASGI transport.

        The URI is supplied by the server-side WebSocket request context.
        It is not accepted from realtime protocol JSON.
        """

        try:
            url = websocket.url
        except Exception as exc:
            raise RealtimeAuthenticationFailed(
                "unable to determine realtime request URI"
            ) from exc

        value = str(url)

        if not value.strip():
            raise RealtimeAuthenticationFailed(
                "realtime request URI is empty"
            )

        return value

    @staticmethod
    def _require_trusted_authorization_context(
        context: AuthorizationContext,
    ) -> None:
        """
        Independent defense-in-depth verification.

        Even though SessionSecurityGateway is responsible for trusted
        issuance, the realtime boundary independently verifies provenance.
        """

        if not isinstance(
            context,
            AuthorizationContext,
        ):
            raise RealtimeAuthenticationFailed(
                "session gateway returned invalid authorization context"
            )

        try:
            context.require_trusted()
            context.require_valid_at(
                datetime.now(timezone.utc)
            )
        except Exception as exc:
            raise RealtimeAuthenticationFailed(
                "session gateway returned an untrusted or expired context"
            ) from exc


__all__ = [
    "CredentialVerifier",
    "GatewayRealtimeSessionResolver",
    "RealtimeAuthenticationFailed",
    "RealtimeAuthenticationRequired",
    "RealtimeCredentialVerificationError",
    "RealtimeSessionResolutionError",
    "VerifiedRealtimeCredentials",
]