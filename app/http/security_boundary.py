"""Ovela Foundation - Milestone M15: Live HTTP/ASGI Security Boundary.

This module is the single point where untrusted network input is converted
into server-authoritative facts. It provides:

* The security boundary exception hierarchy.
* Deterministic request canonicalisation (scheme, authority, path) that fails
  closed on untrusted ``X-Forwarded-*`` / ``Forwarded`` headers.
* An RFC 9449 (DPoP) proof verifier: exactly one proof, ``typ=dpop+jwt``,
  asymmetric algorithms only, public-only embedded JWK, ``htm`` / ``htu`` /
  ``iat`` / ``ath`` validation, optional server nonce and an atomic
  single-use ``jti`` replay check.
* Pluggable ports: ``DPoPReplayStore``, ``NonceProvider`` and ``SessionResolver``.
* ``VerifiedRequestContext``, a frozen output model that carries only verified
  server facts.
* Request limits, a security response header helper, ``verify_incoming_request``
  (the full fail-closed pipeline) and ``SecurityBoundaryMiddleware`` (ASGI).

Invariants
----------
* Untrusted network data never becomes authority. ``tenant_id``,
  ``subject_id`` and the session come exclusively from the ``SessionResolver``,
  which resolves the access token against server-side session state. Nothing
  in headers, query strings or bodies is copied into the output context.
* The access token must be presented with the ``DPoP`` authorization scheme.
  A ``Bearer`` presentation is refused so a stolen token cannot be downgraded.
* The proof key must match the session's bound device thumbprint (RFC 7638).
* Any anomaly, and any unexpected exception, fails closed.
* The replay ``jti`` is consumed last, after every other check has passed, so
  rejected requests never burn a legitimate proof.
* Signature verification uses the ``cryptography`` package, imported lazily.
  If it is unavailable the verifier fails closed instead of skipping the check.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    List,
    MutableMapping,
    NamedTuple,
    Optional,
    Protocol,
    Tuple,
    Union,
)
from urllib.parse import quote, urlsplit
from uuid import UUID

logger = logging.getLogger(__name__)

__all__ = [
    "SecurityBoundaryError",
    "DPoPVerificationError",
    "DPoPNonceRequired",
    "ReplayDetectedError",
    "UntrustedProxyError",
    "RequestLimitExceeded",
    "AuthenticationRequired",
    "DPoPReplayStore",
    "NonceProvider",
    "SessionResolver",
    "ResolvedSession",
    "SecurityBoundaryConfig",
    "VerifiedRequestContext",
    "DEFAULT_ALLOWED_ALGORITHMS",
    "VERIFIED_CONTEXT_SCOPE_KEY",
    "normalize_headers",
    "enforce_request_limits",
    "determine_canonical_uri",
    "compute_access_token_hash",
    "compute_jwk_thumbprint",
    "security_headers",
    "apply_security_headers",
    "verify_incoming_request",
    "get_verified_context",
    "SecurityBoundaryMiddleware",
]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SecurityBoundaryError(Exception):
    """Base class for all security boundary failures."""


class DPoPVerificationError(SecurityBoundaryError):
    """Raised when a DPoP proof is missing, malformed or fails verification."""


class DPoPNonceRequired(DPoPVerificationError):
    """Raised when the server requires a (fresh) DPoP nonce; carries a new one if available."""

    def __init__(self, message: str, nonce: Optional[str] = None) -> None:
        super().__init__(message)
        self.nonce = nonce


class ReplayDetectedError(SecurityBoundaryError):
    """Raised when a DPoP proof ``jti`` has already been consumed."""


class UntrustedProxyError(SecurityBoundaryError):
    """Raised when forwarding headers are present without explicit proxy trust."""


class RequestLimitExceeded(SecurityBoundaryError):
    """Raised when a request exceeds a configured header or body limit."""

    def __init__(self, message: str, status_code: int = 413) -> None:
        super().__init__(message)
        self.status_code = status_code


class AuthenticationRequired(SecurityBoundaryError):
    """Raised when no valid authenticated session accompanies the request."""


# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------


class DPoPReplayStore(Protocol):
    """Atomic single-use store for DPoP proof identifiers."""

    def consume_jti(self, jti: str, expires_at: datetime) -> bool:
        """Atomically record ``jti``. Return ``True`` if it was new, ``False`` if already seen."""
        ...


class NonceProvider(Protocol):
    """Issues and validates server-provided DPoP nonces."""

    def validate_nonce(self, nonce: str) -> bool: ...

    def create_nonce(self) -> str: ...


class ResolvedSession(NamedTuple):
    """Validated server-side session facts."""

    session_id: UUID
    tenant_id: UUID
    subject_id: UUID
    device_thumbprint: str


class SessionResolver(Protocol):
    """Resolves an access token into validated session facts, or ``None`` when invalid."""

    def resolve(self, access_token: str) -> Optional[Tuple[UUID, UUID, UUID, str]]:
        """Return ``(session_id, tenant_id, subject_id, device_thumbprint)`` or ``None``."""
        ...


# ---------------------------------------------------------------------------
# Configuration and output model
# ---------------------------------------------------------------------------

DEFAULT_ALLOWED_ALGORITHMS: FrozenSet[str] = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
)

_HOSTNAME_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_PORT_RE = re.compile(r"^[0-9]{1,5}$")
_PATH_RE = re.compile(r"^/[!-~]*$")
_TOKEN68_RE = re.compile(r"^[A-Za-z0-9\-._~+/]+=*$")
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_METHOD_RE = re.compile(r"^[A-Z]{1,16}$")
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_JTI_RE = re.compile(r"^[!-~]{1,256}$")
_DIGITS_RE = re.compile(r"^[0-9]{1,15}$")

_DEFAULT_PORTS = {"http": 80, "https": 443}
_PRIVATE_JWK_PARAMS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
_ALLOWED_FORWARDED_HEADERS = frozenset({"x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"})

VERIFIED_CONTEXT_SCOPE_KEY = "ovela.verified_request_context"


@dataclass(frozen=True, slots=True)
class SecurityBoundaryConfig:
    """Static, server-side configuration of the security boundary.

    ``allowed_hosts`` holds the canonical authorities this service answers for
    (lowercase ``host`` or ``host:port``; default ports are omitted).
    ``trusted_proxies`` holds the peer addresses allowed to supply
    ``X-Forwarded-Proto`` / ``X-Forwarded-Host``. Empty means no proxy is trusted.
    """

    allowed_hosts: FrozenSet[str]
    trusted_proxies: FrozenSet[str] = frozenset()
    require_https: bool = True
    max_header_bytes: int = 16 * 1024
    max_header_count: int = 100
    max_body_bytes: int = 2 * 1024 * 1024
    iat_window_seconds: int = 300
    max_proof_bytes: int = 8192
    max_access_token_bytes: int = 4096
    allowed_algorithms: FrozenSet[str] = DEFAULT_ALLOWED_ALGORITHMS
    min_rsa_bits: int = 2048
    hsts_max_age: int = 63072000

    def __post_init__(self) -> None:
        if not self.allowed_hosts:
            raise ValueError("allowed_hosts must not be empty")
        for entry in self.allowed_hosts:
            if not isinstance(entry, str) or entry != entry.lower():
                raise ValueError("allowed_hosts entries must be lowercase strings")
            _parse_authority(entry)
        for name in (
            "max_header_bytes",
            "max_header_count",
            "max_body_bytes",
            "iat_window_seconds",
            "max_proof_bytes",
            "max_access_token_bytes",
            "min_rsa_bits",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if not self.allowed_algorithms:
            raise ValueError("allowed_algorithms must not be empty")
        if not self.allowed_algorithms <= DEFAULT_ALLOWED_ALGORITHMS:
            raise ValueError("allowed_algorithms may only contain supported asymmetric algorithms")
        if isinstance(self.hsts_max_age, bool) or not isinstance(self.hsts_max_age, int) or self.hsts_max_age < 0:
            raise ValueError("hsts_max_age must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class VerifiedRequestContext:
    """Server-authoritative facts about a verified request.

    Contains only values derived from verified server-side state; no raw
    request payload, header or query data is carried here.
    """

    session_id: UUID
    tenant_id: UUID
    subject_id: UUID
    device_thumbprint: str
    request_id: str
    canonical_uri: str
    http_method: str
    verified_at: datetime


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _b64url_decode(value: Any) -> bytes:
    if not isinstance(value, str) or not _B64URL_RE.fullmatch(value) or len(value) % 4 == 1:
        raise DPoPVerificationError("invalid base64url value")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as exc:
        raise DPoPVerificationError("invalid base64url value") from exc


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _reject_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite JSON constant: {name}")


def _loads_strict(raw: bytes) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise DPoPVerificationError("invalid JSON in DPoP proof") from exc


def _parse_authority(value: str) -> Tuple[str, Optional[int]]:
    """Parse ``host[:port]`` into a lowercase host and optional port. Raises ``ValueError``."""
    if not isinstance(value, str) or not value or len(value) > 261:
        raise ValueError("invalid authority")
    text = value.lower()
    port_text: Optional[str] = None
    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            raise ValueError("invalid authority")
        host = text[: end + 1]
        rest = text[end + 1 :]
        if rest:
            if not rest.startswith(":"):
                raise ValueError("invalid authority")
            port_text = rest[1:]
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError as exc:
            raise ValueError("invalid authority") from exc
    else:
        if text.count(":") > 1:
            raise ValueError("invalid authority")
        if ":" in text:
            host, port_text = text.split(":", 1)
        else:
            host = text
        if not _HOSTNAME_RE.fullmatch(host):
            raise ValueError("invalid authority")
    port: Optional[int] = None
    if port_text is not None:
        if not _PORT_RE.fullmatch(port_text):
            raise ValueError("invalid authority")
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise ValueError("invalid authority")
    return host, port


def _canonical_authority(host: str, port: Optional[int], scheme: str) -> str:
    if port is None or port == _DEFAULT_PORTS.get(scheme):
        return host
    return f"{host}:{port}"


def _status_error_reason(exc: BaseException) -> str:
    return type(exc).__name__


# ---------------------------------------------------------------------------
# Header handling and request limits
# ---------------------------------------------------------------------------

HeaderInput = Iterable[Tuple[Union[bytes, str], Union[bytes, str]]]


def normalize_headers(raw_headers: HeaderInput) -> List[Tuple[str, str]]:
    """Return ``(lowercase name, value)`` pairs; fail closed on control characters."""
    normalized: List[Tuple[str, str]] = []
    for item in raw_headers:
        try:
            name, value = item
        except (TypeError, ValueError) as exc:
            raise SecurityBoundaryError("malformed header entry") from exc
        try:
            name_text = name.decode("latin-1") if isinstance(name, (bytes, bytearray)) else str(name)
            value_text = value.decode("latin-1") if isinstance(value, (bytes, bytearray)) else str(value)
        except Exception as exc:
            raise SecurityBoundaryError("malformed header entry") from exc
        if not name_text or any(c in name_text for c in " \t\r\n\x00:"):
            raise SecurityBoundaryError("malformed header name")
        if any(c in value_text for c in "\r\n\x00"):
            raise SecurityBoundaryError("malformed header value")
        normalized.append((name_text.lower(), value_text.strip()))
    return normalized


def _single_header(headers: List[Tuple[str, str]], name: str) -> Optional[str]:
    values = [v for n, v in headers if n == name]
    if len(values) > 1:
        raise SecurityBoundaryError(f"multiple {name} headers")
    return values[0] if values else None


def enforce_request_limits(headers: List[Tuple[str, str]], config: SecurityBoundaryConfig) -> None:
    """Enforce header size/count limits and the declared body size limit."""
    total = 0
    for name, value in headers:
        total += len(name) + len(value) + 4
    if len(headers) > config.max_header_count or total > config.max_header_bytes:
        raise RequestLimitExceeded("request headers exceed the configured limit", status_code=431)
    lengths = {v for n, v in headers if n == "content-length"}
    if len(lengths) > 1:
        raise SecurityBoundaryError("conflicting content-length headers")
    if lengths:
        text = next(iter(lengths))
        if not _DIGITS_RE.fullmatch(text):
            raise SecurityBoundaryError("invalid content-length")
        if int(text) > config.max_body_bytes:
            raise RequestLimitExceeded("request body exceeds the configured limit", status_code=413)


# ---------------------------------------------------------------------------
# Canonical URI
# ---------------------------------------------------------------------------


def determine_canonical_uri(
    headers: List[Tuple[str, str]],
    *,
    scheme: str,
    path: str,
    client_host: Optional[str],
    config: SecurityBoundaryConfig,
) -> str:
    """Return the canonical ``scheme://authority/path`` URI of the request.

    The query string and fragment are never part of it. Forwarding headers are
    honoured only when the immediate peer is in ``config.trusted_proxies``; any
    forwarding header from an untrusted peer, and any unsupported forwarding
    header (``Forwarded``, ``X-Forwarded-Port``, ``X-Forwarded-Prefix`` ...)
    fails closed.
    """
    forwarded = [n for n, _v in headers if n.startswith("x-forwarded-") or n == "forwarded"]
    effective_scheme = scheme.lower() if isinstance(scheme, str) else ""
    host_value = _single_header(headers, "host")

    if forwarded:
        if client_host is None or client_host not in config.trusted_proxies:
            raise UntrustedProxyError("forwarding headers received from an untrusted peer")
        if any(n not in _ALLOWED_FORWARDED_HEADERS for n in forwarded):
            raise UntrustedProxyError("unsupported forwarding header")
        proto = _single_header(headers, "x-forwarded-proto")
        if proto is not None:
            if "," in proto:
                raise UntrustedProxyError("ambiguous X-Forwarded-Proto")
            effective_scheme = proto.strip().lower()
        fwd_host = _single_header(headers, "x-forwarded-host")
        if fwd_host is not None:
            if "," in fwd_host:
                raise UntrustedProxyError("ambiguous X-Forwarded-Host")
            host_value = fwd_host

    if effective_scheme not in _DEFAULT_PORTS:
        raise SecurityBoundaryError("unsupported request scheme")
    if config.require_https and effective_scheme != "https":
        raise SecurityBoundaryError("https is required")
    if host_value is None:
        raise SecurityBoundaryError("missing Host header")
    try:
        host, port = _parse_authority(host_value)
    except ValueError as exc:
        raise SecurityBoundaryError("invalid Host header") from exc
    authority = _canonical_authority(host, port, effective_scheme)
    if authority not in config.allowed_hosts:
        raise SecurityBoundaryError("host is not allowed")

    if not isinstance(path, str) or not _PATH_RE.fullmatch(path):
        raise SecurityBoundaryError("invalid request path")
    return f"{effective_scheme}://{authority}{path}"


def _normalize_htu(htu: Any) -> str:
    """Canonicalise a DPoP ``htu`` claim (query and fragment are ignored)."""
    if not isinstance(htu, str) or not htu or len(htu) > 2048:
        raise DPoPVerificationError("invalid htu claim")
    try:
        parts = urlsplit(htu)
        scheme = parts.scheme.lower()
        netloc = parts.netloc
        if scheme not in _DEFAULT_PORTS or not netloc or "@" in netloc:
            raise ValueError("invalid htu")
        host, port = _parse_authority(netloc)
    except ValueError as exc:
        raise DPoPVerificationError("invalid htu claim") from exc
    path = parts.path or "/"
    return f"{scheme}://{_canonical_authority(host, port, scheme)}{path}"


# ---------------------------------------------------------------------------
# JWK handling
# ---------------------------------------------------------------------------

_RSA_ALGS = {
    "RS256": ("SHA256", False),
    "RS384": ("SHA384", False),
    "RS512": ("SHA512", False),
    "PS256": ("SHA256", True),
    "PS384": ("SHA384", True),
    "PS512": ("SHA512", True),
}
_EC_ALGS = {
    "ES256": ("P-256", "SHA256", 32),
    "ES384": ("P-384", "SHA384", 48),
    "ES512": ("P-521", "SHA512", 66),
}


def _validate_public_jwk(jwk: Any, alg: str, config: SecurityBoundaryConfig) -> Dict[str, Any]:
    """Validate that ``jwk`` is a well-formed public key compatible with ``alg``."""
    if not isinstance(jwk, dict) or not jwk:
        raise DPoPVerificationError("DPoP proof requires an embedded jwk")
    if _PRIVATE_JWK_PARAMS & set(jwk):
        raise DPoPVerificationError("embedded jwk contains private key parameters")
    kty = jwk.get("kty")
    if not isinstance(kty, str):
        raise DPoPVerificationError("embedded jwk has no kty")
    if "use" in jwk and jwk["use"] != "sig":
        raise DPoPVerificationError("embedded jwk is not a signature key")
    if "key_ops" in jwk:
        ops = jwk["key_ops"]
        if not isinstance(ops, list) or "verify" not in ops:
            raise DPoPVerificationError("embedded jwk does not permit verification")
    if "alg" in jwk and jwk["alg"] != alg:
        raise DPoPVerificationError("embedded jwk algorithm mismatch")

    def _member(name: str) -> str:
        value = jwk.get(name)
        if not isinstance(value, str) or not value:
            raise DPoPVerificationError(f"embedded jwk is missing {name}")
        return value

    if alg in _RSA_ALGS:
        if kty != "RSA":
            raise DPoPVerificationError("jwk type does not match algorithm")
        modulus = _b64url_decode(_member("n"))
        _b64url_decode(_member("e"))
        if int.from_bytes(modulus, "big").bit_length() < config.min_rsa_bits:
            raise DPoPVerificationError("RSA key is too small")
        return {"kty": "RSA", "n": jwk["n"], "e": jwk["e"]}
    if alg in _EC_ALGS:
        curve, _hash, size = _EC_ALGS[alg]
        if kty != "EC" or jwk.get("crv") != curve:
            raise DPoPVerificationError("jwk type does not match algorithm")
        if len(_b64url_decode(_member("x"))) != size or len(_b64url_decode(_member("y"))) != size:
            raise DPoPVerificationError("invalid EC coordinate length")
        return {"kty": "EC", "crv": curve, "x": jwk["x"], "y": jwk["y"]}
    if alg == "EdDSA":
        if kty != "OKP" or jwk.get("crv") != "Ed25519":
            raise DPoPVerificationError("jwk type does not match algorithm")
        if len(_b64url_decode(_member("x"))) != 32:
            raise DPoPVerificationError("invalid Ed25519 key length")
        return {"kty": "OKP", "crv": "Ed25519", "x": jwk["x"]}
    raise DPoPVerificationError("unsupported algorithm")


def compute_jwk_thumbprint(public_members: Dict[str, Any]) -> str:
    """RFC 7638 SHA-256 thumbprint over the required public members of a JWK."""
    canonical = json.dumps(public_members, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return _b64url_encode(hashlib.sha256(canonical.encode("utf-8")).digest())


def compute_access_token_hash(access_token: str) -> str:
    """Return the base64url (unpadded) SHA-256 of the access token, as used by ``ath``."""
    return _b64url_encode(hashlib.sha256(access_token.encode("ascii")).digest())


def _verify_signature(
    alg: str, jwk: Dict[str, Any], signing_input: bytes, signature: bytes
) -> None:
    """Verify the JWS signature; raises ``DPoPVerificationError`` on any failure."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    except ImportError as exc:
        raise DPoPVerificationError("signature verification backend unavailable") from exc

    hash_classes = {"SHA256": hashes.SHA256, "SHA384": hashes.SHA384, "SHA512": hashes.SHA512}
    try:
        if alg in _RSA_ALGS:
            hash_name, use_pss = _RSA_ALGS[alg]
            hash_alg = hash_classes[hash_name]()
            numbers = rsa.RSAPublicNumbers(
                int.from_bytes(_b64url_decode(jwk["e"]), "big"),
                int.from_bytes(_b64url_decode(jwk["n"]), "big"),
            )
            rsa_key = numbers.public_key()
            if use_pss:
                rsa_padding: Any = padding.PSS(
                    mgf=padding.MGF1(hash_alg), salt_length=hash_alg.digest_size
                )
            else:
                rsa_padding = padding.PKCS1v15()
            rsa_key.verify(signature, signing_input, rsa_padding, hash_alg)
        elif alg in _EC_ALGS:
            curve_name, hash_name, size = _EC_ALGS[alg]
            if len(signature) != 2 * size:
                raise DPoPVerificationError("invalid signature length")
            curves = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}
            ec_numbers = ec.EllipticCurvePublicNumbers(
                int.from_bytes(_b64url_decode(jwk["x"]), "big"),
                int.from_bytes(_b64url_decode(jwk["y"]), "big"),
                curves[curve_name](),
            )
            ec_key = ec_numbers.public_key()
            der = encode_dss_signature(
                int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big")
            )
            ec_key.verify(der, signing_input, ec.ECDSA(hash_classes[hash_name]()))
        elif alg == "EdDSA":
            if len(signature) != 64:
                raise DPoPVerificationError("invalid signature length")
            ed_key = ed25519.Ed25519PublicKey.from_public_bytes(_b64url_decode(jwk["x"]))
            ed_key.verify(signature, signing_input)
        else:
            raise DPoPVerificationError("unsupported algorithm")
    except InvalidSignature as exc:
        raise DPoPVerificationError("DPoP signature verification failed") from exc
    except DPoPVerificationError:
        raise
    except (ValueError, TypeError, KeyError) as exc:
        raise DPoPVerificationError("DPoP public key is invalid") from exc


# ---------------------------------------------------------------------------
# DPoP proof verification
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _VerifiedProof:
    jti: str
    thumbprint: str
    expires_at: datetime


def _verify_dpop_proof(
    proof: str,
    *,
    method: str,
    canonical_uri: str,
    access_token: str,
    config: SecurityBoundaryConfig,
    nonce_provider: Optional[NonceProvider],
    now: datetime,
) -> _VerifiedProof:
    if len(proof) > config.max_proof_bytes or not _JWT_RE.fullmatch(proof):
        raise DPoPVerificationError("malformed DPoP proof")
    header_b64, payload_b64, signature_b64 = proof.split(".")

    header = _loads_strict(_b64url_decode(header_b64))
    if not isinstance(header, dict):
        raise DPoPVerificationError("DPoP header must be a JSON object")
    if header.get("typ") != "dpop+jwt":
        raise DPoPVerificationError("DPoP typ must be dpop+jwt")
    if "crit" in header:
        raise DPoPVerificationError("critical header parameters are not supported")
    alg = header.get("alg")
    if not isinstance(alg, str) or not alg:
        raise DPoPVerificationError("DPoP alg is missing")
    lowered = alg.lower()
    if lowered == "none" or lowered.startswith("hs"):
        raise DPoPVerificationError("symmetric or unsigned algorithms are not permitted")
    if alg not in config.allowed_algorithms:
        raise DPoPVerificationError("algorithm is not permitted")

    jwk = _validate_public_jwk(header.get("jwk"), alg, config)

    signature = _b64url_decode(signature_b64)
    if not signature:
        raise DPoPVerificationError("missing DPoP signature")
    _verify_signature(alg, header["jwk"], f"{header_b64}.{payload_b64}".encode("ascii"), signature)

    claims = _loads_strict(_b64url_decode(payload_b64))
    if not isinstance(claims, dict):
        raise DPoPVerificationError("DPoP claims must be a JSON object")

    jti = claims.get("jti")
    if not isinstance(jti, str) or not _JTI_RE.fullmatch(jti):
        raise DPoPVerificationError("invalid jti claim")

    htm = claims.get("htm")
    if not isinstance(htm, str) or htm != method:
        raise DPoPVerificationError("htm claim does not match the request method")
    if _normalize_htu(claims.get("htu")) != canonical_uri:
        raise DPoPVerificationError("htu claim does not match the request URI")

    iat = claims.get("iat")
    if isinstance(iat, bool) or not isinstance(iat, (int, float)) or not math.isfinite(iat):
        raise DPoPVerificationError("invalid iat claim")
    try:
        issued_at = datetime.fromtimestamp(iat, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise DPoPVerificationError("invalid iat claim") from exc
    window = timedelta(seconds=config.iat_window_seconds)
    if abs(now - issued_at) > window:
        raise DPoPVerificationError("iat is outside the acceptable window")

    if "exp" in claims:
        exp = claims["exp"]
        if isinstance(exp, bool) or not isinstance(exp, (int, float)) or not math.isfinite(exp):
            raise DPoPVerificationError("invalid exp claim")
        if exp <= now.timestamp():
            raise DPoPVerificationError("DPoP proof has expired")

    ath = claims.get("ath")
    if not isinstance(ath, str) or not hmac.compare_digest(
        ath.encode("utf-8"), compute_access_token_hash(access_token).encode("ascii")
    ):
        raise DPoPVerificationError("ath claim does not match the access token")

    if nonce_provider is not None:
        nonce = claims.get("nonce")
        valid = False
        if isinstance(nonce, str) and nonce:
            try:
                valid = nonce_provider.validate_nonce(nonce) is True
            except Exception as exc:
                raise SecurityBoundaryError("nonce provider unavailable") from exc
        if not valid:
            fresh: Optional[str]
            try:
                fresh = nonce_provider.create_nonce()
            except Exception:
                fresh = None
            raise DPoPNonceRequired("a valid DPoP nonce is required", fresh)

    return _VerifiedProof(
        jti=jti,
        thumbprint=compute_jwk_thumbprint(jwk),
        expires_at=issued_at + window,
    )


# ---------------------------------------------------------------------------
# Verification pipeline
# ---------------------------------------------------------------------------


def _extract_access_token(headers: List[Tuple[str, str]], config: SecurityBoundaryConfig) -> str:
    value = _single_header(headers, "authorization")
    if value is None or not value:
        raise AuthenticationRequired("authentication required")
    scheme, separator, token = value.partition(" ")
    if scheme.lower() != "dpop" or not separator:
        raise AuthenticationRequired("DPoP-bound access token required")
    if (
        not token
        or len(token) > config.max_access_token_bytes
        or not _TOKEN68_RE.fullmatch(token)
    ):
        raise AuthenticationRequired("malformed access token")
    return token


def _verify(
    *,
    method: str,
    path: str,
    headers: HeaderInput,
    scheme: str,
    client_host: Optional[str],
    config: SecurityBoundaryConfig,
    session_resolver: SessionResolver,
    replay_store: DPoPReplayStore,
    nonce_provider: Optional[NonceProvider],
    now: Optional[datetime],
    request_id: Optional[str],
) -> VerifiedRequestContext:
    current = now if now is not None else _utcnow()
    if current.tzinfo is None or current.utcoffset() is None:
        raise SecurityBoundaryError("now must be timezone-aware")
    current = current.astimezone(timezone.utc)

    if not isinstance(method, str) or not _METHOD_RE.fullmatch(method):
        raise SecurityBoundaryError("invalid HTTP method")

    normalized = normalize_headers(headers)
    enforce_request_limits(normalized, config)
    canonical_uri = determine_canonical_uri(
        normalized, scheme=scheme, path=path, client_host=client_host, config=config
    )

    access_token = _extract_access_token(normalized, config)

    proofs = [v for n, v in normalized if n == "dpop"]
    if len(proofs) != 1:
        raise DPoPVerificationError("exactly one DPoP header is required")
    proof = _verify_dpop_proof(
        proofs[0],
        method=method,
        canonical_uri=canonical_uri,
        access_token=access_token,
        config=config,
        nonce_provider=nonce_provider,
        now=current,
    )

    try:
        resolved = session_resolver.resolve(access_token)
    except SecurityBoundaryError:
        raise
    except Exception as exc:
        raise AuthenticationRequired("session could not be resolved") from exc
    if resolved is None:
        raise AuthenticationRequired("invalid or expired session")
    try:
        session_id, tenant_id, subject_id, device_thumbprint = resolved
    except (TypeError, ValueError) as exc:
        raise AuthenticationRequired("invalid session data") from exc
    if (
        not isinstance(session_id, UUID)
        or not isinstance(tenant_id, UUID)
        or not isinstance(subject_id, UUID)
        or not isinstance(device_thumbprint, str)
        or not device_thumbprint
    ):
        raise AuthenticationRequired("invalid session data")

    if not hmac.compare_digest(
        proof.thumbprint.encode("utf-8"), device_thumbprint.encode("utf-8")
    ):
        raise DPoPVerificationError("proof key is not bound to the session")

    # Consume the jti last so rejected requests never burn a legitimate proof.
    try:
        fresh = replay_store.consume_jti(proof.jti, proof.expires_at)
    except Exception as exc:
        raise SecurityBoundaryError("replay store unavailable") from exc
    if fresh is not True:
        raise ReplayDetectedError("DPoP proof has already been used")

    safe_request_id = (
        request_id
        if isinstance(request_id, str) and _REQUEST_ID_RE.fullmatch(request_id)
        else uuid.uuid4().hex
    )
    return VerifiedRequestContext(
        session_id=session_id,
        tenant_id=tenant_id,
        subject_id=subject_id,
        device_thumbprint=device_thumbprint,
        request_id=safe_request_id,
        canonical_uri=canonical_uri,
        http_method=method,
        verified_at=current,
    )


def verify_incoming_request(
    *,
    method: str,
    path: str,
    headers: HeaderInput,
    scheme: str,
    client_host: Optional[str],
    config: SecurityBoundaryConfig,
    session_resolver: SessionResolver,
    replay_store: DPoPReplayStore,
    nonce_provider: Optional[NonceProvider] = None,
    now: Optional[datetime] = None,
    request_id: Optional[str] = None,
) -> VerifiedRequestContext:
    """Run the full verification pipeline and return server-authoritative facts.

    ``path`` is the raw request path without the query string. ``scheme`` and
    ``client_host`` come from the server connection (never from the client).
    Every anomaly, including any unexpected internal error, fails closed with a
    ``SecurityBoundaryError`` subclass.
    """
    try:
        return _verify(
            method=method,
            path=path,
            headers=headers,
            scheme=scheme,
            client_host=client_host,
            config=config,
            session_resolver=session_resolver,
            replay_store=replay_store,
            nonce_provider=nonce_provider,
            now=now,
            request_id=request_id,
        )
    except SecurityBoundaryError:
        raise
    except Exception as exc:
        logger.error("unexpected failure in security boundary: %s", _status_error_reason(exc))
        raise SecurityBoundaryError("request verification failed") from exc


# ---------------------------------------------------------------------------
# Security response headers
# ---------------------------------------------------------------------------


def security_headers(*, hsts_max_age: int = 63072000) -> Dict[str, str]:
    """Return the standard security response headers."""
    if isinstance(hsts_max_age, bool) or not isinstance(hsts_max_age, int) or hsts_max_age < 0:
        raise ValueError("hsts_max_age must be a non-negative integer")
    return {
        "Strict-Transport-Security": f"max-age={hsts_max_age}; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Cache-Control": "no-store",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    }


def apply_security_headers(
    raw_headers: Iterable[Tuple[bytes, bytes]],
    extra: Optional[Dict[str, str]] = None,
    *,
    hsts_max_age: int = 63072000,
) -> List[Tuple[bytes, bytes]]:
    """Return ASGI headers with the security headers applied, replacing same-named ones."""
    overrides = security_headers(hsts_max_age=hsts_max_age)
    if extra:
        overrides.update(extra)
    replaced = {name.lower().encode("latin-1") for name in overrides}
    result = [(n, v) for n, v in raw_headers if n.lower() not in replaced]
    for name, value in overrides.items():
        result.append((name.lower().encode("latin-1"), value.encode("latin-1")))
    return result


# ---------------------------------------------------------------------------
# ASGI middleware
# ---------------------------------------------------------------------------

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


def get_verified_context(scope: Scope) -> VerifiedRequestContext:
    """Return the verified context the middleware stored on ``scope``; fails closed if absent."""
    context = scope.get(VERIFIED_CONTEXT_SCOPE_KEY)
    if not isinstance(context, VerifiedRequestContext):
        raise AuthenticationRequired("request has not been verified")
    return context


def _challenge(config: SecurityBoundaryConfig, error: Optional[str] = None) -> str:
    algs = " ".join(sorted(config.allowed_algorithms))
    if error is None:
        return f'DPoP algs="{algs}"'
    return f'DPoP error="{error}", algs="{algs}"'


def _error_response(
    exc: SecurityBoundaryError, config: SecurityBoundaryConfig
) -> Tuple[int, str, Dict[str, str]]:
    """Map a boundary failure to ``(status, error code, extra headers)`` without leaking detail."""
    if isinstance(exc, DPoPNonceRequired):
        headers = {"WWW-Authenticate": _challenge(config, "use_dpop_nonce")}
        if exc.nonce:
            headers["DPoP-Nonce"] = exc.nonce
        return 401, "use_dpop_nonce", headers
    if isinstance(exc, AuthenticationRequired):
        return 401, "authentication_required", {"WWW-Authenticate": _challenge(config)}
    if isinstance(exc, (DPoPVerificationError, ReplayDetectedError)):
        return 401, "invalid_dpop_proof", {"WWW-Authenticate": _challenge(config, "invalid_dpop_proof")}
    if isinstance(exc, UntrustedProxyError):
        return 400, "untrusted_proxy", {}
    if isinstance(exc, RequestLimitExceeded):
        return exc.status_code, "request_too_large", {}
    return 400, "bad_request", {}


class SecurityBoundaryMiddleware:
    """ASGI middleware enforcing the security boundary on every HTTP request.

    * Verifies each request (except ``public_paths``) and stores the resulting
      ``VerifiedRequestContext`` on the scope under ``VERIFIED_CONTEXT_SCOPE_KEY``.
    * Enforces header and streaming body size limits for all requests.
    * Adds the security headers to every response, including error responses.
    * Rejects websocket connections (they are not covered by this boundary).
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        config: SecurityBoundaryConfig,
        session_resolver: SessionResolver,
        replay_store: DPoPReplayStore,
        nonce_provider: Optional[NonceProvider] = None,
        public_paths: FrozenSet[str] = frozenset(),
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        if not callable(app):
            raise TypeError("app must be callable")
        self._app = app
        self._config = config
        self._session_resolver = session_resolver
        self._replay_store = replay_store
        self._nonce_provider = nonce_provider
        self._public_paths = frozenset(public_paths)
        self._clock = clock

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope_type = scope.get("type")
        if scope_type == "lifespan":
            await self._app(scope, receive, send)
            return
        if scope_type == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        if scope_type != "http":
            return

        scope = dict(scope)
        scope.pop(VERIFIED_CONTEXT_SCOPE_KEY, None)
        state = {"started": False}

        async def guarded_send(message: MutableMapping[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                state["started"] = True
                message = dict(message)
                message["headers"] = apply_security_headers(
                    message.get("headers", []), hsts_max_age=self._config.hsts_max_age
                )
            await send(message)

        try:
            raw_headers = list(scope.get("headers") or [])
            normalized = normalize_headers(raw_headers)
            enforce_request_limits(normalized, self._config)
            path = self._raw_path(scope)
            if path not in self._public_paths:
                scope[VERIFIED_CONTEXT_SCOPE_KEY] = verify_incoming_request(
                    method=str(scope.get("method", "")),
                    path=path,
                    headers=raw_headers,
                    scheme=str(scope.get("scheme", "")),
                    client_host=self._client_host(scope),
                    config=self._config,
                    session_resolver=self._session_resolver,
                    replay_store=self._replay_store,
                    nonce_provider=self._nonce_provider,
                    now=self._clock(),
                )
        except SecurityBoundaryError as exc:
            logger.warning("request rejected by security boundary: %s", _status_error_reason(exc))
            await self._reject(exc, send)
            return

        limited_receive = self._limit_body(receive)
        try:
            await self._app(scope, limited_receive, guarded_send)
        except RequestLimitExceeded as exc:
            if state["started"]:
                raise
            await self._reject(exc, send)

    # -- helpers ---------------------------------------------------------------

    @staticmethod
    def _raw_path(scope: Scope) -> str:
        raw = scope.get("raw_path")
        if isinstance(raw, (bytes, bytearray)):
            text = bytes(raw).decode("latin-1")
        else:
            text = quote(str(scope.get("path", "")), safe="/-._~!$&'()*+,;=:@%")
        return text.split("?", 1)[0]

    @staticmethod
    def _client_host(scope: Scope) -> Optional[str]:
        client = scope.get("client")
        if isinstance(client, (tuple, list)) and client and isinstance(client[0], str):
            return client[0]
        return None

    def _limit_body(self, receive: Receive) -> Receive:
        limit = self._config.max_body_bytes
        seen = {"bytes": 0}

        async def limited() -> MutableMapping[str, Any]:
            message = await receive()
            if message.get("type") == "http.request":
                seen["bytes"] += len(message.get("body", b""))
                if seen["bytes"] > limit:
                    raise RequestLimitExceeded("request body exceeds the configured limit", 413)
            return message

        return limited

    async def _reject(self, exc: SecurityBoundaryError, send: Send) -> None:
        status, code, extra = _error_response(exc, self._config)
        body = json.dumps({"error": code}, separators=(",", ":")).encode("utf-8")
        headers: List[Tuple[bytes, bytes]] = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
        ]
        for name, value in extra.items():
            headers.append((name.lower().encode("latin-1"), value.encode("latin-1")))
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": apply_security_headers(headers, hsts_max_age=self._config.hsts_max_age),
            }
        )
        await send({"type": "http.response.body", "body": body})