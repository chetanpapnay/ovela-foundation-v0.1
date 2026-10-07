"""Adversarial test suite for ``app.http.security_boundary``.

Covers RFC 9449 DPoP proof attacks, replay defence, proxy and transport
integrity, identity spoofing, request limits, security headers, the ASGI
middleware and the valid flow. Designed to pass under
``pytest -q -W error -rs``.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
import hmac
import json
import os
import re
import threading
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple
from uuid import UUID

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

from app.http.security_boundary import (  # noqa: E402
    VERIFIED_CONTEXT_SCOPE_KEY,
    AuthenticationRequired,
    DPoPNonceRequired,
    DPoPVerificationError,
    ReplayDetectedError,
    RequestLimitExceeded,
    SecurityBoundaryConfig,
    SecurityBoundaryError,
    SecurityBoundaryMiddleware,
    UntrustedProxyError,
    VerifiedRequestContext,
    apply_security_headers,
    compute_access_token_hash,
    compute_jwk_thumbprint,
    determine_canonical_uri,
    enforce_request_limits,
    get_verified_context,
    normalize_headers,
    security_headers,
    verify_incoming_request,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HOST = "api.example.com"
PATH = "/v1/payments"
URI = f"https://{HOST}{PATH}"
TOKEN = "access-token-abc123"
TRUSTED_PROXY = "10.0.0.1"
UNTRUSTED_PEER = "203.0.113.7"
NOW = datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc)

SESSION_ID = UUID("11111111-1111-4111-8111-111111111111")
TENANT_ID = UUID("22222222-2222-4222-8222-222222222222")
SUBJECT_ID = UUID("33333333-3333-4333-8333-333333333333")
OTHER_TENANT_ID = UUID("99999999-9999-4999-8999-999999999999")
OTHER_SUBJECT_ID = UUID("88888888-8888-4888-8888-888888888888")

MISSING = object()
AUTH_DEFAULT = object()

_HEX32_RE = re.compile(r"^[0-9a-f]{32}$")


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def int_b64(value: int) -> str:
    return b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))


class Signer:
    """A DPoP proof signer holding a public-only JWK and a signing function."""

    def __init__(self, alg: str, jwk: Dict[str, Any], sign_fn: Any) -> None:
        self.alg = alg
        self.jwk = jwk
        self._sign_fn = sign_fn

    @property
    def thumbprint(self) -> str:
        return compute_jwk_thumbprint(self.jwk)

    def sign(self, data: bytes) -> bytes:
        return self._sign_fn(data)


_HASHES = {"SHA256": hashes.SHA256, "SHA384": hashes.SHA384, "SHA512": hashes.SHA512}
_EC_PARAMS = {
    "ES256": ("P-256", ec.SECP256R1, "SHA256", 32),
    "ES384": ("P-384", ec.SECP384R1, "SHA384", 48),
    "ES512": ("P-521", ec.SECP521R1, "SHA512", 66),
}


def make_signer(alg: str = "ES256", rsa_bits: int = 2048) -> Signer:
    if alg in _EC_PARAMS:
        crv, curve_cls, hash_name, size = _EC_PARAMS[alg]
        ec_key = ec.generate_private_key(curve_cls())
        numbers = ec_key.public_key().public_numbers()
        jwk = {
            "kty": "EC",
            "crv": crv,
            "x": b64(numbers.x.to_bytes(size, "big")),
            "y": b64(numbers.y.to_bytes(size, "big")),
        }

        def sign_ec(data: bytes) -> bytes:
            der = ec_key.sign(data, ec.ECDSA(_HASHES[hash_name]()))
            r, s = decode_dss_signature(der)
            return r.to_bytes(size, "big") + s.to_bytes(size, "big")

        return Signer(alg, jwk, sign_ec)

    if alg in ("RS256", "PS256"):
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
        pub = rsa_key.public_key().public_numbers()
        jwk = {"kty": "RSA", "n": int_b64(pub.n), "e": int_b64(pub.e)}

        def sign_rsa(data: bytes) -> bytes:
            if alg == "PS256":
                pad: Any = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
            else:
                pad = padding.PKCS1v15()
            return rsa_key.sign(data, pad, hashes.SHA256())

        return Signer(alg, jwk, sign_rsa)

    if alg == "EdDSA":
        ed_key = ed25519.Ed25519PrivateKey.generate()
        raw_pub = ed_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64(raw_pub)}
        return Signer(alg, jwk, ed_key.sign)

    raise AssertionError(f"unsupported test algorithm {alg}")


def default_claims() -> Dict[str, Any]:
    return {
        "jti": uuid.uuid4().hex,
        "htm": "GET",
        "htu": URI,
        "iat": int(NOW.timestamp()),
        "ath": compute_access_token_hash(TOKEN),
    }


def assemble(signer: Signer, header_bytes: bytes, payload_bytes: bytes) -> str:
    header_b64 = b64(header_bytes)
    payload_b64 = b64(payload_bytes)
    signature = signer.sign(f"{header_b64}.{payload_b64}".encode("ascii"))
    return f"{header_b64}.{payload_b64}.{b64(signature)}"


def build_proof(
    signer: Signer,
    claims: Optional[Dict[str, Any]] = None,
    header: Optional[Dict[str, Any]] = None,
    *,
    signature: Optional[bytes] = None,
) -> str:
    hdr: Dict[str, Any] = {"typ": "dpop+jwt", "alg": signer.alg, "jwk": signer.jwk}
    hdr.update(header or {})
    hdr = {k: v for k, v in hdr.items() if v is not MISSING}
    clm = default_claims()
    clm.update(claims or {})
    clm = {k: v for k, v in clm.items() if v is not MISSING}
    header_b64 = b64(json.dumps(hdr, separators=(",", ":")).encode("utf-8"))
    payload_b64 = b64(json.dumps(clm, separators=(",", ":")).encode("utf-8"))
    if signature is None:
        signature = signer.sign(f"{header_b64}.{payload_b64}".encode("ascii"))
    return f"{header_b64}.{payload_b64}.{b64(signature)}"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class InMemoryReplayStore:
    def __init__(self) -> None:
        self.seen: Dict[str, datetime] = {}
        self._lock = threading.Lock()

    def consume_jti(self, jti: str, expires_at: datetime) -> bool:
        with self._lock:
            if jti in self.seen:
                return False
            self.seen[jti] = expires_at
            return True


class ExplodingReplayStore:
    def consume_jti(self, jti: str, expires_at: datetime) -> bool:
        raise RuntimeError("replay backend down")


class NoneReplayStore:
    def consume_jti(self, jti: str, expires_at: datetime) -> Any:
        return None


class FakeSessionResolver:
    def __init__(self, sessions: Dict[str, Any]) -> None:
        self.sessions = sessions
        self.calls: List[str] = []
        self.raise_exc: Optional[BaseException] = None

    def resolve(self, access_token: str) -> Any:
        self.calls.append(access_token)
        if self.raise_exc is not None:
            raise self.raise_exc
        return self.sessions.get(access_token)


class FakeNonceProvider:
    def validate_nonce(self, nonce: str) -> bool:
        return nonce == "good-nonce"

    def create_nonce(self) -> str:
        return "fresh-nonce"


def make_config(**overrides: Any) -> SecurityBoundaryConfig:
    return SecurityBoundaryConfig(
        allowed_hosts=frozenset({HOST}),
        trusted_proxies=frozenset({TRUSTED_PROXY}),
        **overrides,
    )


class Env:
    """A complete verification environment with fakes wired in."""

    def __init__(
        self,
        signer: Optional[Signer] = None,
        config: Optional[SecurityBoundaryConfig] = None,
    ) -> None:
        self.signer = signer or make_signer("ES256")
        self.config = config or make_config()
        self.store = InMemoryReplayStore()
        self.resolver = FakeSessionResolver(
            {TOKEN: (SESSION_ID, TENANT_ID, SUBJECT_ID, self.signer.thumbprint)}
        )

    def proof(self, claims: Optional[Dict[str, Any]] = None, header: Optional[Dict[str, Any]] = None, **kw: Any) -> str:
        return build_proof(self.signer, claims, header, **kw)

    def headers(
        self,
        proofs: Optional[Sequence[str]] = None,
        *,
        authorization: Any = AUTH_DEFAULT,
        host: Optional[str] = HOST,
        extra: Sequence[Tuple[str, str]] = (),
    ) -> List[Tuple[bytes, bytes]]:
        if proofs is None:
            proofs = [self.proof()]
        result: List[Tuple[bytes, bytes]] = []
        if host is not None:
            result.append((b"host", host.encode("latin-1")))
        if authorization is AUTH_DEFAULT:
            authorization = f"DPoP {TOKEN}"
        if authorization is not None:
            result.append((b"authorization", authorization.encode("latin-1")))
        for item in proofs:
            result.append((b"dpop", item.encode("latin-1")))
        for name, value in extra:
            result.append((name.encode("latin-1"), value.encode("latin-1")))
        return result

    def verify(
        self,
        proofs: Any = None,
        *,
        method: str = "GET",
        path: str = PATH,
        authorization: Any = AUTH_DEFAULT,
        host: Optional[str] = HOST,
        scheme: str = "https",
        client_host: Optional[str] = UNTRUSTED_PEER,
        extra: Sequence[Tuple[str, str]] = (),
        request_id: Optional[str] = None,
        nonce_provider: Any = None,
        now: Optional[datetime] = NOW,
        store: Any = None,
    ) -> VerifiedRequestContext:
        if isinstance(proofs, str):
            proofs = [proofs]
        return verify_incoming_request(
            method=method,
            path=path,
            headers=self.headers(proofs, authorization=authorization, host=host, extra=extra),
            scheme=scheme,
            client_host=client_host,
            config=self.config,
            session_resolver=self.resolver,
            replay_store=store if store is not None else self.store,
            nonce_provider=nonce_provider,
            now=now,
            request_id=request_id,
        )

    def reject(self, exc_type: type, *args: Any, **kwargs: Any) -> BaseException:
        with pytest.raises(exc_type) as info:
            self.verify(*args, **kwargs)
        assert self.store.seen == {}, "a rejected request must not consume the proof jti"
        return info.value


@pytest.fixture()
def env() -> Env:
    return Env()


# ---------------------------------------------------------------------------
# 6. Valid flow
# ---------------------------------------------------------------------------


class TestValidFlow:
    def test_valid_proof_emits_frozen_verified_context(self, env: Env) -> None:
        claims = default_claims()
        ctx = env.verify(env.proof(claims), request_id="req-123")

        assert isinstance(ctx, VerifiedRequestContext)
        assert ctx.session_id == SESSION_ID
        assert ctx.tenant_id == TENANT_ID
        assert ctx.subject_id == SUBJECT_ID
        assert ctx.device_thumbprint == env.signer.thumbprint
        assert ctx.request_id == "req-123"
        assert ctx.canonical_uri == URI
        assert ctx.http_method == "GET"
        assert ctx.verified_at == NOW

        with pytest.raises(dataclasses.FrozenInstanceError):
            ctx.tenant_id = OTHER_TENANT_ID  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            ctx.subject_id = OTHER_SUBJECT_ID  # type: ignore[misc]

    def test_context_has_exactly_the_expected_fields(self) -> None:
        names = {f.name for f in dataclasses.fields(VerifiedRequestContext)}
        assert names == {
            "session_id",
            "tenant_id",
            "subject_id",
            "device_thumbprint",
            "request_id",
            "canonical_uri",
            "http_method",
            "verified_at",
        }

    def test_valid_proof_consumes_jti_with_expiry(self, env: Env) -> None:
        claims = default_claims()
        env.verify(env.proof(claims))
        assert list(env.store.seen) == [claims["jti"]]
        assert env.store.seen[claims["jti"]] == NOW + timedelta(seconds=env.config.iat_window_seconds)
        assert env.resolver.calls == [TOKEN]

    @pytest.mark.parametrize("alg", ["ES256", "ES384", "ES512", "RS256", "PS256", "EdDSA"])
    def test_valid_proof_for_each_supported_algorithm(self, alg: str) -> None:
        local = Env(signer=make_signer(alg))
        ctx = local.verify(local.proof())
        assert ctx.device_thumbprint == local.signer.thumbprint
        assert ctx.tenant_id == TENANT_ID

    def test_post_request_with_matching_htm(self, env: Env) -> None:
        ctx = env.verify(env.proof({"htm": "POST"}), method="POST")
        assert ctx.http_method == "POST"

    def test_htu_query_fragment_default_port_and_host_case_are_normalised(self, env: Env) -> None:
        env.verify(env.proof({"htu": "https://API.example.com:443/v1/payments?x=1#frag"}))

    def test_iat_inside_window_is_accepted(self, env: Env) -> None:
        env.verify(env.proof({"iat": int(NOW.timestamp()) - 299}))
        env.verify(env.proof({"iat": int(NOW.timestamp()) + 299}))

    def test_distinct_jti_values_are_independent(self, env: Env) -> None:
        env.verify(env.proof())
        env.verify(env.proof())
        assert len(env.store.seen) == 2

    def test_extra_proof_claims_are_ignored(self, env: Env) -> None:
        ctx = env.verify(
            env.proof({"tenant_id": str(OTHER_TENANT_ID), "subject_id": str(OTHER_SUBJECT_ID)})
        )
        assert ctx.tenant_id == TENANT_ID
        assert ctx.subject_id == SUBJECT_ID

    def test_valid_nonce_is_accepted(self, env: Env) -> None:
        ctx = env.verify(env.proof({"nonce": "good-nonce"}), nonce_provider=FakeNonceProvider())
        assert ctx.session_id == SESSION_ID

    def test_request_id_is_generated_or_sanitised(self, env: Env) -> None:
        generated = env.verify(env.proof())
        assert _HEX32_RE.fullmatch(generated.request_id)
        bad = env.verify(env.proof(), request_id="bad id\r\nX-Evil: 1")
        assert _HEX32_RE.fullmatch(bad.request_id)
        assert bad.request_id != generated.request_id


# ---------------------------------------------------------------------------
# 1. RFC 9449 DPoP proof attacks
# ---------------------------------------------------------------------------


class TestMissingAndDuplicateProofs:
    def test_missing_dpop_header_is_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, [])

    def test_missing_authorization_requires_authentication(self, env: Env) -> None:
        env.reject(AuthenticationRequired, env.proof(), authorization=None)

    def test_missing_authorization_and_dpop_requires_authentication(self, env: Env) -> None:
        env.reject(AuthenticationRequired, [], authorization=None)

    @pytest.mark.parametrize(
        "authorization",
        [
            f"Bearer {TOKEN}",
            f"bearer {TOKEN}",
            TOKEN,
            "DPoP",
            "DPoP ",
            "DPoP bad token with spaces",
            "DPoP " + "A" * 5000,
            "DPoP tok\u00e9n",
        ],
    )
    def test_non_dpop_or_malformed_authorization_is_rejected(self, env: Env, authorization: str) -> None:
        env.reject(AuthenticationRequired, env.proof(), authorization=authorization)

    def test_duplicate_dpop_headers_are_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, [env.proof(), env.proof()])

    def test_duplicate_identical_dpop_headers_are_rejected(self, env: Env) -> None:
        proof = env.proof()
        env.reject(DPoPVerificationError, [proof, proof])

    def test_duplicate_authorization_headers_are_rejected(self, env: Env) -> None:
        env.reject(
            SecurityBoundaryError,
            env.proof(),
            extra=[("authorization", f"DPoP {TOKEN}")],
        )


class TestMalformedProofs:
    @pytest.mark.parametrize(
        "proof",
        [
            "",
            "garbage",
            "a.b",
            "a.b.c.d",
            "!!!.@@@.###",
            "A.B.C",
            "AAAA.AAAA.AAAA",
            "e30.e30.",
            "e30..AAAA",
            "A" * 9000 + ".b.c",
        ],
    )
    def test_malformed_jwt_strings_are_rejected(self, env: Env, proof: str) -> None:
        env.reject(DPoPVerificationError, [proof])

    @pytest.mark.parametrize("typ", ["JWT", "jwt", "DPOP+JWT", "dpop", "", None, 7])
    def test_wrong_typ_header_is_rejected(self, env: Env, typ: Any) -> None:
        env.reject(DPoPVerificationError, env.proof(header={"typ": typ}))

    def test_missing_typ_header_is_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof(header={"typ": MISSING}))

    def test_crit_header_is_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof(header={"crit": ["exp"]}))

    def test_missing_jwk_is_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof(header={"jwk": MISSING}))

    @pytest.mark.parametrize("jwk", [None, [], "jwk", {}, 5])
    def test_invalid_jwk_shapes_are_rejected(self, env: Env, jwk: Any) -> None:
        env.reject(DPoPVerificationError, env.proof(header={"jwk": jwk}))

    def test_json_array_header_is_rejected(self, env: Env) -> None:
        proof = assemble(env.signer, b"[]", json.dumps(default_claims()).encode("utf-8"))
        env.reject(DPoPVerificationError, [proof])

    def test_duplicate_json_keys_in_header_are_rejected(self, env: Env) -> None:
        raw_header = (
            '{"typ":"JWT","typ":"dpop+jwt","alg":"%s","jwk":%s}'
            % (env.signer.alg, json.dumps(env.signer.jwk, separators=(",", ":")))
        ).encode("utf-8")
        proof = assemble(env.signer, raw_header, json.dumps(default_claims()).encode("utf-8"))
        env.reject(DPoPVerificationError, [proof])

    def test_duplicate_json_keys_in_claims_are_rejected(self, env: Env) -> None:
        claims = default_claims()
        raw_claims = (
            '{"jti":"%s","htm":"POST","htm":"GET","htu":"%s","iat":%d,"ath":"%s"}'
            % (claims["jti"], URI, claims["iat"], claims["ath"])
        ).encode("utf-8")
        header = json.dumps(
            {"typ": "dpop+jwt", "alg": env.signer.alg, "jwk": env.signer.jwk}, separators=(",", ":")
        ).encode("utf-8")
        env.reject(DPoPVerificationError, [assemble(env.signer, header, raw_claims)])

    def test_non_finite_json_constants_are_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof({"iat": float("nan")}))

    def test_tampered_payload_fails_signature_check(self, env: Env) -> None:
        genuine = env.proof()
        header_b64, _payload, signature_b64 = genuine.split(".")
        forged_payload = b64(json.dumps(default_claims(), separators=(",", ":")).encode("utf-8"))
        env.reject(DPoPVerificationError, [f"{header_b64}.{forged_payload}.{signature_b64}"])

    def test_signature_from_a_different_key_is_rejected(self, env: Env) -> None:
        attacker = make_signer("ES256")
        forged = build_proof(attacker, header={"jwk": env.signer.jwk})
        env.reject(DPoPVerificationError, [forged])

    def test_truncated_or_zeroed_signature_is_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof(signature=b"\x00" * 64))
        env.reject(DPoPVerificationError, env.proof(signature=b"\x01" * 10))


class TestAlgorithmAttacks:
    @pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512", "hs256"])
    def test_symmetric_algorithms_are_rejected(self, env: Env, alg: str) -> None:
        secret = os.urandom(32)
        header = {"alg": alg, "jwk": {"kty": "oct", "k": b64(secret)}}
        signature = hmac.new(secret, b"forged", hashlib.sha256).digest()
        env.reject(DPoPVerificationError, env.proof(header=header, signature=signature))

    def test_hmac_with_public_key_material_is_rejected(self, env: Env) -> None:
        signature = hmac.new(b"public-key-material", b"forged", hashlib.sha256).digest()
        env.reject(DPoPVerificationError, env.proof(header={"alg": "HS256"}, signature=signature))

    @pytest.mark.parametrize("alg", ["none", "None", "NONE"])
    def test_none_algorithm_is_rejected(self, env: Env, alg: str) -> None:
        env.reject(DPoPVerificationError, env.proof(header={"alg": alg}, signature=b"\x00\x00\x00"))

    def test_none_algorithm_with_empty_signature_is_rejected(self, env: Env) -> None:
        proof = env.proof(header={"alg": "none"}, signature=b"")
        assert proof.endswith(".")
        env.reject(DPoPVerificationError, [proof])

    @pytest.mark.parametrize("alg", [None, "", 5, "ES256K", "RS1", "PS999", "EdDSA2"])
    def test_unsupported_or_missing_algorithms_are_rejected(self, env: Env, alg: Any) -> None:
        env.reject(DPoPVerificationError, env.proof(header={"alg": alg}))

    def test_missing_alg_is_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof(header={"alg": MISSING}))

    def test_algorithm_outside_configured_allow_list_is_rejected(self) -> None:
        local = Env(config=make_config(allowed_algorithms=frozenset({"ES384"})))
        local.reject(DPoPVerificationError, local.proof())

    def test_jwk_type_not_matching_algorithm_is_rejected(self, env: Env) -> None:
        rsa_signer = make_signer("RS256")
        env.reject(DPoPVerificationError, env.proof(header={"jwk": rsa_signer.jwk}))
        env.reject(DPoPVerificationError, env.proof(header={"jwk": {**env.signer.jwk, "crv": "P-384"}}))

    def test_jwk_alg_mismatch_is_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof(header={"jwk": {**env.signer.jwk, "alg": "ES384"}}))

    def test_jwk_use_enc_and_missing_verify_op_are_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof(header={"jwk": {**env.signer.jwk, "use": "enc"}}))
        env.reject(DPoPVerificationError, env.proof(header={"jwk": {**env.signer.jwk, "key_ops": ["sign"]}}))

    def test_undersized_rsa_key_is_rejected(self) -> None:
        local = Env(signer=make_signer("RS256", rsa_bits=1024))
        local.reject(DPoPVerificationError, local.proof())

    def test_invalid_ec_coordinate_length_is_rejected(self, env: Env) -> None:
        short = {**env.signer.jwk, "x": b64(b"\x01" * 8)}
        env.reject(DPoPVerificationError, env.proof(header={"jwk": short}))

    def test_off_curve_ec_point_is_rejected(self, env: Env) -> None:
        bogus = {**env.signer.jwk, "x": b64(b"\x01" * 32), "y": b64(b"\x02" * 32)}
        env.reject(DPoPVerificationError, env.proof(header={"jwk": bogus}))


class TestPrivateKeyMaterial:
    @pytest.mark.parametrize("param", ["d", "p", "q", "dp", "dq", "qi", "oth", "k"])
    def test_jwk_with_private_parameters_is_rejected(self, env: Env, param: str) -> None:
        leaky = {**env.signer.jwk, param: b64(os.urandom(32))}
        env.reject(DPoPVerificationError, env.proof(header={"jwk": leaky}))

    def test_rsa_jwk_with_private_exponent_is_rejected(self) -> None:
        local = Env(signer=make_signer("RS256"))
        leaky = {**local.signer.jwk, "d": b64(os.urandom(256))}
        local.reject(DPoPVerificationError, local.proof(header={"jwk": leaky}))


class TestTimeClaims:
    def test_expired_iat_is_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof({"iat": int(NOW.timestamp()) - 301}))
        env.reject(DPoPVerificationError, env.proof({"iat": int(NOW.timestamp()) - 86400}))

    def test_far_future_iat_is_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof({"iat": int(NOW.timestamp()) + 301}))
        env.reject(DPoPVerificationError, env.proof({"iat": int((NOW + timedelta(days=3650)).timestamp())}))

    @pytest.mark.parametrize("iat", ["1700000000", True, False, None, [], 1e20, float("nan")])
    def test_invalid_iat_values_are_rejected(self, env: Env, iat: Any) -> None:
        env.reject(DPoPVerificationError, env.proof({"iat": iat}))

    def test_missing_iat_is_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof({"iat": MISSING}))

    def test_expired_exp_claim_is_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof({"exp": int(NOW.timestamp()) - 1}))

    def test_invalid_exp_claim_is_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof({"exp": "never"}))

    def test_future_exp_claim_is_accepted(self, env: Env) -> None:
        env.verify(env.proof({"exp": int(NOW.timestamp()) + 60}))

    def test_naive_now_is_rejected(self, env: Env) -> None:
        env.reject(SecurityBoundaryError, env.proof(), now=NOW.replace(tzinfo=None))


class TestMethodAndUriBinding:
    def test_htm_post_on_get_request_is_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof({"htm": "POST"}), method="GET")

    def test_htm_get_on_post_request_is_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof({"htm": "GET"}), method="POST")

    @pytest.mark.parametrize("htm", ["get", "Get", "", None, 5, ["GET"]])
    def test_invalid_htm_values_are_rejected(self, env: Env, htm: Any) -> None:
        env.reject(DPoPVerificationError, env.proof({"htm": htm}))

    def test_missing_htm_is_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof({"htm": MISSING}))

    @pytest.mark.parametrize("method", ["", "get", "G E T", "GET\r\n", "A" * 17, "G3T"])
    def test_invalid_request_methods_are_rejected(self, env: Env, method: str) -> None:
        env.reject(SecurityBoundaryError, env.proof(), method=method)

    def test_htu_for_a_different_path_is_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof({"htu": "https://api.example.com/v1/other"}))

    @pytest.mark.parametrize(
        "htu",
        [
            "http://api.example.com/v1/payments",
            "https://evil.example.com/v1/payments",
            "https://api.example.com:8443/v1/payments",
            "https://api.example.com/v1/payments/",
            "https://api.example.com/V1/payments",
            "https://api.example.com/v1/%70ayments",
            "https://user@api.example.com/v1/payments",
            "ftp://api.example.com/v1/payments",
            "/v1/payments",
            "",
            None,
            123,
            ["https://api.example.com/v1/payments"],
        ],
    )
    def test_htu_mismatches_are_rejected(self, env: Env, htu: Any) -> None:
        env.reject(DPoPVerificationError, env.proof({"htu": htu}))

    def test_missing_htu_is_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof({"htu": MISSING}))


class TestAccessTokenBinding:
    def test_invalid_ath_is_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof({"ath": compute_access_token_hash("another-token")}))

    @pytest.mark.parametrize("ath", ["", "AAAA", None, 5, ["x"]])
    def test_malformed_ath_is_rejected(self, env: Env, ath: Any) -> None:
        env.reject(DPoPVerificationError, env.proof({"ath": ath}))

    def test_missing_ath_is_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof({"ath": MISSING}))

    def test_proof_for_one_token_cannot_authorise_another(self, env: Env) -> None:
        other = "other-token-xyz"
        env.resolver.sessions[other] = (SESSION_ID, TENANT_ID, SUBJECT_ID, env.signer.thumbprint)
        env.reject(DPoPVerificationError, env.proof(), authorization=f"DPoP {other}")


class TestJtiClaim:
    @pytest.mark.parametrize("jti", ["", " ", "has space", "a" * 257, 123, None, ["x"]])
    def test_invalid_jti_is_rejected(self, env: Env, jti: Any) -> None:
        env.reject(DPoPVerificationError, env.proof({"jti": jti}))

    def test_missing_jti_is_rejected(self, env: Env) -> None:
        env.reject(DPoPVerificationError, env.proof({"jti": MISSING}))


class TestNonce:
    def test_missing_nonce_requires_a_fresh_one(self, env: Env) -> None:
        err = env.reject(DPoPNonceRequired, env.proof(), nonce_provider=FakeNonceProvider())
        assert isinstance(err, DPoPVerificationError)
        assert getattr(err, "nonce") == "fresh-nonce"

    def test_wrong_nonce_requires_a_fresh_one(self, env: Env) -> None:
        err = env.reject(
            DPoPNonceRequired, env.proof({"nonce": "stale"}), nonce_provider=FakeNonceProvider()
        )
        assert getattr(err, "nonce") == "fresh-nonce"


class TestSessionBinding:
    def test_proof_key_must_match_the_session_thumbprint(self, env: Env) -> None:
        attacker = Env(signer=make_signer("ES256"))
        forged = attacker.proof()
        env.reject(DPoPVerificationError, forged)

    def test_unknown_access_token_is_rejected(self, env: Env) -> None:
        env.resolver.sessions.clear()
        env.reject(AuthenticationRequired, env.proof())

    def test_resolver_exception_fails_closed(self, env: Env) -> None:
        env.resolver.raise_exc = RuntimeError("db down")
        env.reject(AuthenticationRequired, env.proof())

    @pytest.mark.parametrize(
        "session",
        [
            ("not-a-uuid", TENANT_ID, SUBJECT_ID, "thumb"),
            (SESSION_ID, str(TENANT_ID), SUBJECT_ID, "thumb"),
            (SESSION_ID, TENANT_ID, SUBJECT_ID, ""),
            (SESSION_ID, TENANT_ID, SUBJECT_ID, None),
            (SESSION_ID, TENANT_ID),
            "garbage",
        ],
    )
    def test_malformed_session_data_is_rejected(self, env: Env, session: Any) -> None:
        env.resolver.sessions[TOKEN] = session
        env.reject(AuthenticationRequired, env.proof())


# ---------------------------------------------------------------------------
# 2. Replay defence
# ---------------------------------------------------------------------------


class TestReplayDefense:
    def test_first_use_consumes_jti_and_replay_is_rejected(self, env: Env) -> None:
        proof = env.proof()
        first = env.verify(proof)
        assert first.tenant_id == TENANT_ID
        assert len(env.store.seen) == 1

        with pytest.raises(ReplayDetectedError):
            env.verify(proof)
        assert len(env.store.seen) == 1

    def test_replay_error_is_not_a_proof_verification_error(self) -> None:
        assert not issubclass(ReplayDetectedError, DPoPVerificationError)
        assert issubclass(ReplayDetectedError, SecurityBoundaryError)

    def test_replay_with_same_jti_and_new_signature_is_rejected(self, env: Env) -> None:
        jti = uuid.uuid4().hex
        env.verify(env.proof({"jti": jti}))
        with pytest.raises(ReplayDetectedError):
            env.verify(env.proof({"jti": jti}))

    def test_rejected_requests_do_not_burn_the_jti(self, env: Env) -> None:
        jti = uuid.uuid4().hex
        with pytest.raises(DPoPVerificationError):
            env.verify(env.proof({"jti": jti, "htm": "POST"}), method="GET")
        assert env.store.seen == {}
        env.verify(env.proof({"jti": jti}))
        assert jti in env.store.seen

    def test_session_failure_does_not_burn_the_jti(self, env: Env) -> None:
        proof = env.proof()
        env.resolver.sessions.clear()
        with pytest.raises(AuthenticationRequired):
            env.verify(proof)
        assert env.store.seen == {}
        env.resolver.sessions[TOKEN] = (SESSION_ID, TENANT_ID, SUBJECT_ID, env.signer.thumbprint)
        env.verify(proof)

    def test_key_binding_failure_does_not_burn_the_jti(self, env: Env) -> None:
        attacker = Env(signer=make_signer("ES256"))
        with pytest.raises(DPoPVerificationError):
            env.verify(attacker.proof())
        assert env.store.seen == {}

    def test_concurrent_replay_admits_exactly_one_request(self, env: Env) -> None:
        proof = env.proof()
        outcomes: List[str] = []
        outcome_lock = threading.Lock()
        barrier = threading.Barrier(16)

        def worker() -> None:
            barrier.wait()
            try:
                env.verify(proof)
                result = "ok"
            except ReplayDetectedError:
                result = "replay"
            except BaseException as exc:  # pragma: no cover - reported via assertion
                result = f"error:{type(exc).__name__}"
            with outcome_lock:
                outcomes.append(result)

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert outcomes.count("ok") == 1
        assert outcomes.count("replay") == 15
        assert len(env.store.seen) == 1

    def test_replay_store_failure_fails_closed(self, env: Env) -> None:
        with pytest.raises(SecurityBoundaryError) as info:
            env.verify(env.proof(), store=ExplodingReplayStore())
        assert not isinstance(info.value, ReplayDetectedError)

    def test_non_true_store_result_is_treated_as_replay(self, env: Env) -> None:
        with pytest.raises(ReplayDetectedError):
            env.verify(env.proof(), store=NoneReplayStore())


# ---------------------------------------------------------------------------
# 3. Proxy and transport integrity
# ---------------------------------------------------------------------------


class TestProxyIntegrity:
    def test_untrusted_x_forwarded_host_is_rejected(self, env: Env) -> None:
        env.reject(
            UntrustedProxyError,
            env.proof(),
            host="evil.example.net",
            extra=[("x-forwarded-host", HOST)],
        )

    def test_untrusted_x_forwarded_proto_is_rejected(self, env: Env) -> None:
        env.reject(UntrustedProxyError, env.proof(), scheme="http", extra=[("x-forwarded-proto", "https")])

    def test_untrusted_x_forwarded_for_is_rejected(self, env: Env) -> None:
        env.reject(UntrustedProxyError, env.proof(), extra=[("x-forwarded-for", "1.2.3.4")])

    def test_forwarded_header_from_untrusted_peer_is_rejected(self, env: Env) -> None:
        env.reject(UntrustedProxyError, env.proof(), extra=[("forwarded", f"host={HOST};proto=https")])

    def test_forwarding_headers_without_peer_address_are_rejected(self, env: Env) -> None:
        env.reject(UntrustedProxyError, env.proof(), client_host=None, extra=[("x-forwarded-proto", "https")])

    def test_trusted_proxy_forwarded_host_and_proto_are_honoured(self, env: Env) -> None:
        ctx = env.verify(
            env.proof(),
            host="internal.svc",
            scheme="http",
            client_host=TRUSTED_PROXY,
            extra=[("x-forwarded-host", HOST), ("x-forwarded-proto", "https")],
        )
        assert ctx.canonical_uri == URI

    def test_trusted_proxy_cannot_smuggle_a_disallowed_host(self, env: Env) -> None:
        env.reject(
            SecurityBoundaryError,
            env.proof({"htu": "https://evil.example.com/v1/payments"}),
            client_host=TRUSTED_PROXY,
            extra=[("x-forwarded-host", "evil.example.com"), ("x-forwarded-proto", "https")],
        )

    def test_trusted_proxy_cannot_downgrade_to_http(self, env: Env) -> None:
        env.reject(
            SecurityBoundaryError,
            env.proof(),
            client_host=TRUSTED_PROXY,
            extra=[("x-forwarded-proto", "http")],
        )

    @pytest.mark.parametrize(
        "name,value",
        [
            ("x-forwarded-host", f"{HOST}, evil.example.com"),
            ("x-forwarded-proto", "https, http"),
            ("x-forwarded-port", "8443"),
            ("x-forwarded-prefix", "/admin"),
            ("forwarded", f"host={HOST}"),
        ],
    )
    def test_ambiguous_or_unsupported_forwarding_from_trusted_proxy_is_rejected(
        self, env: Env, name: str, value: str
    ) -> None:
        env.reject(UntrustedProxyError, env.proof(), client_host=TRUSTED_PROXY, extra=[(name, value)])

    def test_duplicate_forwarded_host_headers_are_rejected(self, env: Env) -> None:
        env.reject(
            SecurityBoundaryError,
            env.proof(),
            client_host=TRUSTED_PROXY,
            extra=[("x-forwarded-host", HOST), ("x-forwarded-host", HOST)],
        )

    def test_http_scheme_is_rejected_when_https_is_required(self, env: Env) -> None:
        env.reject(SecurityBoundaryError, env.proof(), scheme="http")

    def test_unsupported_scheme_is_rejected(self, env: Env) -> None:
        env.reject(SecurityBoundaryError, env.proof(), scheme="ftp")

    def test_http_scheme_is_allowed_only_when_configured(self) -> None:
        local = Env(config=make_config(require_https=False))
        ctx = local.verify(local.proof({"htu": f"http://{HOST}{PATH}"}), scheme="http")
        assert ctx.canonical_uri == f"http://{HOST}{PATH}"


class TestCanonicalUri:
    def _headers(self, host: Optional[str]) -> List[Tuple[str, str]]:
        return [] if host is None else [("host", host)]

    @pytest.mark.parametrize("host", ["api.example.com", "API.EXAMPLE.COM", "api.example.com:443"])
    def test_equivalent_hosts_are_canonicalised(self, host: str) -> None:
        uri = determine_canonical_uri(
            self._headers(host), scheme="https", path=PATH, client_host=None, config=make_config()
        )
        assert uri == URI

    @pytest.mark.parametrize(
        "host",
        [
            "evil.example.com",
            "api.example.com:8443",
            "user@api.example.com",
            "api.example.com.",
            "api.example.com/evil",
            "",
            "api.example.com:99999",
            "api.example.com:abc",
            "api.example.com:0",
            "[::1]",
            "api example com",
            None,
        ],
    )
    def test_invalid_or_disallowed_hosts_are_rejected(self, host: Optional[str]) -> None:
        with pytest.raises(SecurityBoundaryError):
            determine_canonical_uri(
                self._headers(host), scheme="https", path=PATH, client_host=None, config=make_config()
            )

    def test_duplicate_host_headers_are_rejected(self) -> None:
        with pytest.raises(SecurityBoundaryError):
            determine_canonical_uri(
                [("host", HOST), ("host", "evil.example.com")],
                scheme="https",
                path=PATH,
                client_host=None,
                config=make_config(),
            )

    @pytest.mark.parametrize(
        "path",
        ["", "v1/payments", "/v1/pay ments", "/v1/pay\nments", "/v1/pay\x00ments", "/v1/paym\u00e9nts", "/v1/\t"],
    )
    def test_invalid_paths_are_rejected(self, path: str) -> None:
        with pytest.raises(SecurityBoundaryError):
            determine_canonical_uri(
                self._headers(HOST), scheme="https", path=path, client_host=None, config=make_config()
            )

    def test_non_string_path_is_rejected(self) -> None:
        with pytest.raises(SecurityBoundaryError):
            determine_canonical_uri(
                self._headers(HOST), scheme="https", path=None, client_host=None, config=make_config()  # type: ignore[arg-type]
            )

    @pytest.mark.parametrize(
        "path",
        [
            "/v1/other/../payments",
            "/v1/./payments",
            "/v1//payments",
            "/v1/%70ayments",
            "/v1/payments%2f",
            "/v1/payments%2e%2e/",
            "/v1/payments/",
            "/V1/payments",
            "/v1/payments;x=1",
        ],
    )
    def test_traversal_and_encoding_variants_do_not_inherit_a_proof(self, env: Env, path: str) -> None:
        # The proof is bound to the exact canonical URI; a path that merely
        # resolves or decodes to the same resource must not satisfy it.
        env.reject(DPoPVerificationError, env.proof(), path=path)

    def test_traversal_path_with_matching_literal_htu_is_the_only_accepted_form(self, env: Env) -> None:
        literal = "/v1/other/../payments"
        ctx = env.verify(env.proof({"htu": f"https://{HOST}{literal}"}), path=literal)
        assert ctx.canonical_uri == f"https://{HOST}{literal}"
        assert ctx.canonical_uri != URI

    def test_host_header_spoofing_cannot_borrow_another_hosts_proof(self, env: Env) -> None:
        env.reject(SecurityBoundaryError, env.proof(), host="evil.example.com")


# ---------------------------------------------------------------------------
# 4. Identity and authorization spoofing
# ---------------------------------------------------------------------------


class TestIdentitySpoofing:
    def test_spoofed_identity_headers_never_reach_the_context(self, env: Env) -> None:
        ctx = env.verify(
            env.proof(),
            extra=[
                ("x-tenant-id", str(OTHER_TENANT_ID)),
                ("x-subject-id", str(OTHER_SUBJECT_ID)),
                ("x-session-id", str(uuid.uuid4())),
                ("x-request-id", "attacker-controlled-request-id"),
            ],
        )
        assert ctx.tenant_id == TENANT_ID
        assert ctx.subject_id == SUBJECT_ID
        assert ctx.session_id == SESSION_ID
        assert _HEX32_RE.fullmatch(ctx.request_id)

    def test_resolver_receives_only_the_access_token(self, env: Env) -> None:
        env.verify(env.proof(), extra=[("x-tenant-id", str(OTHER_TENANT_ID))])
        assert env.resolver.calls == [TOKEN]

    def test_proof_claims_cannot_override_session_identity(self, env: Env) -> None:
        ctx = env.verify(
            env.proof(
                {
                    "tenant_id": str(OTHER_TENANT_ID),
                    "subject_id": str(OTHER_SUBJECT_ID),
                    "sub": str(OTHER_SUBJECT_ID),
                }
            )
        )
        assert (ctx.tenant_id, ctx.subject_id) == (TENANT_ID, SUBJECT_ID)

    def test_context_reflects_resolver_facts_exactly(self, env: Env) -> None:
        new_session = uuid.uuid4()
        new_tenant = uuid.uuid4()
        new_subject = uuid.uuid4()
        env.resolver.sessions[TOKEN] = (new_session, new_tenant, new_subject, env.signer.thumbprint)
        ctx = env.verify(env.proof())
        assert (ctx.session_id, ctx.tenant_id, ctx.subject_id) == (new_session, new_tenant, new_subject)

    def test_middleware_ignores_body_claims_of_a_different_tenant(self, env: Env) -> None:
        captured: Dict[str, Any] = {}

        async def app(scope: Any, receive: Any, send: Any) -> None:
            body = b""
            while True:
                message = await receive()
                body += message.get("body", b"")
                if not message.get("more_body", False):
                    break
            captured["scope"] = scope
            captured["body"] = body
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        body = json.dumps(
            {"tenant_id": str(OTHER_TENANT_ID), "subject_id": str(OTHER_SUBJECT_ID)}
        ).encode("utf-8")
        mw = make_middleware(env, app)
        scope = make_scope(env, [env.proof({"htm": "POST"})], method="POST")
        sent = drive(mw, scope, [body])

        status, _headers, _body = parse_response(sent)
        assert status == 200
        assert json.loads(captured["body"])["tenant_id"] == str(OTHER_TENANT_ID)
        ctx = get_verified_context(captured["scope"])
        assert ctx.tenant_id == TENANT_ID
        assert ctx.subject_id == SUBJECT_ID

    def test_forged_scope_context_is_stripped_on_public_paths(self, env: Env) -> None:
        captured: Dict[str, Any] = {}

        async def app(scope: Any, receive: Any, send: Any) -> None:
            captured["scope"] = scope
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        forged = VerifiedRequestContext(
            session_id=uuid.uuid4(),
            tenant_id=OTHER_TENANT_ID,
            subject_id=OTHER_SUBJECT_ID,
            device_thumbprint="forged",
            request_id="forged",
            canonical_uri=URI,
            http_method="GET",
            verified_at=NOW,
        )
        mw = make_middleware(env, app)
        scope = make_scope(env, [], path="/public", authorization=None)
        scope[VERIFIED_CONTEXT_SCOPE_KEY] = forged
        sent = drive(mw, scope)

        assert parse_response(sent)[0] == 200
        assert VERIFIED_CONTEXT_SCOPE_KEY not in captured["scope"]
        with pytest.raises(AuthenticationRequired):
            get_verified_context(captured["scope"])

    def test_get_verified_context_fails_closed_without_context(self) -> None:
        with pytest.raises(AuthenticationRequired):
            get_verified_context({})
        with pytest.raises(AuthenticationRequired):
            get_verified_context({VERIFIED_CONTEXT_SCOPE_KEY: {"tenant_id": str(OTHER_TENANT_ID)}})


# ---------------------------------------------------------------------------
# 5. Request limits and security headers
# ---------------------------------------------------------------------------


class TestRequestLimits:
    def test_oversized_header_payload_raises_request_limit_exceeded(self) -> None:
        local = Env(config=make_config(max_header_bytes=1024))
        err = local.reject(RequestLimitExceeded, local.proof(), extra=[("x-big", "A" * 2048)])
        assert getattr(err, "status_code") == 431

    def test_too_many_headers_raise_request_limit_exceeded(self) -> None:
        local = Env(config=make_config(max_header_count=10))
        extra = [(f"x-h{i}", "v") for i in range(20)]
        err = local.reject(RequestLimitExceeded, local.proof(), extra=extra)
        assert getattr(err, "status_code") == 431

    def test_oversized_content_length_raises_request_limit_exceeded(self) -> None:
        local = Env(config=make_config(max_body_bytes=1024))
        err = local.reject(RequestLimitExceeded, local.proof(), extra=[("content-length", "1025")])
        assert getattr(err, "status_code") == 413

    def test_content_length_at_the_limit_is_accepted(self) -> None:
        local = Env(config=make_config(max_body_bytes=1024))
        local.verify(local.proof(), extra=[("content-length", "1024")])

    @pytest.mark.parametrize("value", ["abc", "-1", "1e3", "1 2", "", "9" * 16])
    def test_invalid_content_length_is_rejected(self, env: Env, value: str) -> None:
        env.reject(SecurityBoundaryError, env.proof(), extra=[("content-length", value)])

    def test_conflicting_content_length_headers_are_rejected(self, env: Env) -> None:
        env.reject(
            SecurityBoundaryError,
            env.proof(),
            extra=[("content-length", "10"), ("content-length", "20")],
        )

    def test_enforce_request_limits_directly(self) -> None:
        config = make_config(max_header_bytes=64)
        with pytest.raises(RequestLimitExceeded):
            enforce_request_limits([("x", "A" * 200)], config)
        enforce_request_limits([("x", "ok")], config)

    @pytest.mark.parametrize(
        "name,value",
        [
            (b"x-test", b"a\r\nInjected: 1"),
            (b"x-test", b"a\nb"),
            (b"x-test", b"a\x00b"),
            (b"bad name", b"v"),
            (b"bad:name", b"v"),
            (b"", b"v"),
            (b"x-te\nst", b"v"),
        ],
    )
    def test_header_injection_is_rejected(self, name: bytes, value: bytes) -> None:
        with pytest.raises(SecurityBoundaryError):
            normalize_headers([(name, value)])

    def test_malformed_header_entry_is_rejected(self) -> None:
        with pytest.raises(SecurityBoundaryError):
            normalize_headers([(b"only-a-name",)])  # type: ignore[list-item]

    def test_headers_are_lowercased_and_stripped(self) -> None:
        assert normalize_headers([(b"X-Test", b"  v  "), ("Host", "h")]) == [("x-test", "v"), ("host", "h")]


class TestConfigValidation:
    def test_empty_allowed_hosts_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            SecurityBoundaryConfig(allowed_hosts=frozenset())

    def test_uppercase_or_invalid_allowed_host_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            SecurityBoundaryConfig(allowed_hosts=frozenset({"API.example.com"}))
        with pytest.raises(ValueError):
            SecurityBoundaryConfig(allowed_hosts=frozenset({"bad host"}))

    @pytest.mark.parametrize("algs", [frozenset({"HS256"}), frozenset({"none"}), frozenset({"ES256", "HS256"}), frozenset()])
    def test_symmetric_or_empty_algorithm_sets_are_rejected(self, algs: Any) -> None:
        with pytest.raises(ValueError):
            SecurityBoundaryConfig(allowed_hosts=frozenset({HOST}), allowed_algorithms=algs)

    @pytest.mark.parametrize("name", ["max_header_bytes", "max_header_count", "max_body_bytes", "iat_window_seconds"])
    @pytest.mark.parametrize("value", [0, -1, True, 1.5])
    def test_non_positive_limits_are_rejected(self, name: str, value: Any) -> None:
        with pytest.raises(ValueError):
            SecurityBoundaryConfig(allowed_hosts=frozenset({HOST}), **{name: value})

    def test_config_is_frozen(self) -> None:
        config = make_config()
        with pytest.raises(dataclasses.FrozenInstanceError):
            config.require_https = False  # type: ignore[misc]


EXPECTED_SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}


class TestSecurityHeaders:
    def test_security_headers_output_is_hardened(self) -> None:
        assert security_headers() == EXPECTED_SECURITY_HEADERS

    def test_custom_hsts_max_age(self) -> None:
        assert security_headers(hsts_max_age=60)["Strict-Transport-Security"] == "max-age=60; includeSubDomains"
        assert security_headers(hsts_max_age=0)["Strict-Transport-Security"] == "max-age=0; includeSubDomains"

    @pytest.mark.parametrize("value", [-1, True, 1.5, "100", None])
    def test_invalid_hsts_max_age_is_rejected(self, value: Any) -> None:
        with pytest.raises(ValueError):
            security_headers(hsts_max_age=value)

    def test_apply_replaces_conflicting_headers(self) -> None:
        raw = [
            (b"X-Frame-Options", b"SAMEORIGIN"),
            (b"Content-Security-Policy", b"default-src *"),
            (b"content-type", b"text/plain"),
        ]
        result = apply_security_headers(raw)
        as_dict: Dict[bytes, List[bytes]] = {}
        for name, value in result:
            as_dict.setdefault(name, []).append(value)

        assert as_dict[b"x-frame-options"] == [b"DENY"]
        assert as_dict[b"content-security-policy"] == [b"default-src 'none'; frame-ancestors 'none'"]
        assert as_dict[b"content-type"] == [b"text/plain"]
        for name in EXPECTED_SECURITY_HEADERS:
            assert name.lower().encode("latin-1") in as_dict

    def test_apply_accepts_extra_overrides(self) -> None:
        result = apply_security_headers([], {"X-Custom": "1", "Cache-Control": "private"})
        values = dict(result)
        assert values[b"x-custom"] == b"1"
        assert values[b"cache-control"] == b"private"


# ---------------------------------------------------------------------------
# Fail-closed behaviour
# ---------------------------------------------------------------------------


class TestFailClosed:
    def test_unexpected_internal_error_is_wrapped(self, env: Env) -> None:
        class BrokenConfig:
            max_header_bytes = 1024
            max_header_count = 10
            max_body_bytes = 1024

        with pytest.raises(SecurityBoundaryError):
            verify_incoming_request(
                method="GET",
                path=PATH,
                headers=env.headers(),
                scheme="https",
                client_host=UNTRUSTED_PEER,
                config=BrokenConfig(),  # type: ignore[arg-type]
                session_resolver=env.resolver,
                replay_store=env.store,
                now=NOW,
            )
        assert env.store.seen == {}

    def test_non_ascii_header_bytes_never_authenticate(self, env: Env) -> None:
        env.reject(AuthenticationRequired, env.proof(), authorization="DPoP tok\u00e9n")

    def test_access_token_hash_is_base64url_sha256(self) -> None:
        expected = b64(hashlib.sha256(TOKEN.encode("ascii")).digest())
        assert compute_access_token_hash(TOKEN) == expected
        assert "=" not in expected


# ---------------------------------------------------------------------------
# ASGI middleware
# ---------------------------------------------------------------------------


def make_middleware(env: Env, app: Any, **overrides: Any) -> SecurityBoundaryMiddleware:
    options: Dict[str, Any] = {
        "config": env.config,
        "session_resolver": env.resolver,
        "replay_store": env.store,
        "nonce_provider": None,
        "public_paths": frozenset({"/public"}),
        "clock": lambda: NOW,
    }
    options.update(overrides)
    return SecurityBoundaryMiddleware(app, **options)


def make_scope(
    env: Env,
    proofs: Optional[Sequence[str]] = None,
    *,
    path: str = PATH,
    method: str = "GET",
    authorization: Any = AUTH_DEFAULT,
    host: Optional[str] = HOST,
    extra: Sequence[Tuple[str, str]] = (),
    client: Tuple[str, int] = (UNTRUSTED_PEER, 5555),
) -> Dict[str, Any]:
    return {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode("latin-1"),
        "scheme": "https",
        "client": client,
        "headers": env.headers(proofs, authorization=authorization, host=host, extra=extra),
    }


def drive(mw: Any, scope: Dict[str, Any], chunks: Sequence[bytes] = (b"",)) -> List[Dict[str, Any]]:
    sent: List[Dict[str, Any]] = []
    pending: List[Dict[str, Any]] = [
        {"type": "http.request", "body": chunk, "more_body": index < len(chunks) - 1}
        for index, chunk in enumerate(chunks)
    ]

    async def receive() -> Dict[str, Any]:
        if pending:
            return pending.pop(0)
        return {"type": "http.disconnect"}

    async def send(message: Any) -> None:
        sent.append(dict(message))

    asyncio.run(mw(scope, receive, send))
    return sent


def parse_response(sent: Sequence[Dict[str, Any]]) -> Tuple[int, List[Tuple[str, str]], bytes]:
    start = sent[0]
    assert start["type"] == "http.response.start"
    headers = [(n.decode("latin-1").lower(), v.decode("latin-1")) for n, v in start["headers"]]
    body = b"".join(m.get("body", b"") for m in sent[1:] if m["type"] == "http.response.body")
    return start["status"], headers, body


def assert_security_headers_present(headers: Sequence[Tuple[str, str]]) -> None:
    names = [n for n, _v in headers]
    for expected in EXPECTED_SECURITY_HEADERS:
        assert names.count(expected.lower()) == 1, expected


class RecordingApp:
    def __init__(self) -> None:
        self.calls = 0
        self.scope: Optional[Dict[str, Any]] = None

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        self.calls += 1
        self.scope = scope
        while True:
            message = await receive()
            if message.get("type") != "http.request" or not message.get("more_body", False):
                break
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain"), (b"x-frame-options", b"SAMEORIGIN")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})


class TestMiddleware:
    def test_valid_request_reaches_app_with_verified_context(self, env: Env) -> None:
        app = RecordingApp()
        sent = drive(make_middleware(env, app), make_scope(env))
        status, headers, body = parse_response(sent)

        assert status == 200
        assert body == b"ok"
        assert app.calls == 1
        assert app.scope is not None
        ctx = get_verified_context(app.scope)
        assert (ctx.tenant_id, ctx.subject_id, ctx.session_id) == (TENANT_ID, SUBJECT_ID, SESSION_ID)
        assert ctx.canonical_uri == URI
        assert_security_headers_present(headers)
        assert dict(headers)["x-frame-options"] == "DENY"

    def test_raw_path_query_string_is_not_part_of_the_canonical_uri(self, env: Env) -> None:
        app = RecordingApp()
        scope = make_scope(env)
        scope["raw_path"] = b"/v1/payments?amount=1"
        sent = drive(make_middleware(env, app), scope)
        assert parse_response(sent)[0] == 200
        assert app.scope is not None
        assert get_verified_context(app.scope).canonical_uri == URI

    def test_missing_credentials_return_401_and_skip_the_app(self, env: Env) -> None:
        app = RecordingApp()
        sent = drive(make_middleware(env, app), make_scope(env, [], authorization=None))
        status, headers, body = parse_response(sent)

        assert status == 401
        assert app.calls == 0
        assert json.loads(body) == {"error": "authentication_required"}
        assert dict(headers)["www-authenticate"].startswith("DPoP")
        assert_security_headers_present(headers)

    def test_missing_dpop_proof_returns_401_invalid_dpop_proof(self, env: Env) -> None:
        app = RecordingApp()
        sent = drive(make_middleware(env, app), make_scope(env, []))
        status, headers, body = parse_response(sent)

        assert status == 401
        assert app.calls == 0
        assert json.loads(body) == {"error": "invalid_dpop_proof"}
        assert 'error="invalid_dpop_proof"' in dict(headers)["www-authenticate"]

    def test_replayed_request_is_rejected(self, env: Env) -> None:
        app = RecordingApp()
        mw = make_middleware(env, app)
        proof = env.proof()
        first = drive(mw, make_scope(env, [proof]))
        second = drive(mw, make_scope(env, [proof]))

        assert parse_response(first)[0] == 200
        status, _headers, body = parse_response(second)
        assert status == 401
        assert json.loads(body) == {"error": "invalid_dpop_proof"}
        assert app.calls == 1

    def test_error_bodies_do_not_leak_internal_detail(self, env: Env) -> None:
        app = RecordingApp()
        sent = drive(make_middleware(env, app), make_scope(env, [env.proof({"htm": "POST"})]))
        _status, _headers, body = parse_response(sent)
        assert json.loads(body) == {"error": "invalid_dpop_proof"}
        assert b"htm" not in body

    def test_untrusted_forwarding_header_returns_400(self, env: Env) -> None:
        app = RecordingApp()
        scope = make_scope(env, extra=[("x-forwarded-host", HOST)])
        sent = drive(make_middleware(env, app), scope)
        status, headers, body = parse_response(sent)

        assert status == 400
        assert json.loads(body) == {"error": "untrusted_proxy"}
        assert app.calls == 0
        assert_security_headers_present(headers)

    def test_traversal_path_is_rejected_by_htu_binding(self, env: Env) -> None:
        app = RecordingApp()
        path = "/v1/other/../payments"
        sent = drive(make_middleware(env, app), make_scope(env, path=path))
        assert parse_response(sent)[0] == 401
        assert app.calls == 0

    def test_oversized_headers_return_431(self) -> None:
        local = Env(config=make_config(max_header_bytes=1024))
        app = RecordingApp()
        sent = drive(make_middleware(local, app), make_scope(local, extra=[("x-big", "A" * 2048)]))
        status, headers, body = parse_response(sent)

        assert status == 431
        assert json.loads(body) == {"error": "request_too_large"}
        assert app.calls == 0
        assert_security_headers_present(headers)

    def test_oversized_content_length_returns_413(self) -> None:
        local = Env(config=make_config(max_body_bytes=1024))
        app = RecordingApp()
        sent = drive(make_middleware(local, app), make_scope(local, extra=[("content-length", "4096")]))
        status, _headers, body = parse_response(sent)

        assert status == 413
        assert json.loads(body) == {"error": "request_too_large"}
        assert app.calls == 0

    def test_streamed_body_over_limit_returns_413(self) -> None:
        local = Env(config=make_config(max_body_bytes=1024))
        app = RecordingApp()
        scope = make_scope(local, [], path="/public", authorization=None)
        sent = drive(make_middleware(local, app), scope, [b"a" * 600, b"b" * 600])
        status, headers, body = parse_response(sent)

        assert status == 413
        assert json.loads(body) == {"error": "request_too_large"}
        assert_security_headers_present(headers)

    def test_streamed_body_within_limit_is_delivered(self) -> None:
        local = Env(config=make_config(max_body_bytes=1024))
        app = RecordingApp()
        scope = make_scope(local, [], path="/public", authorization=None)
        sent = drive(make_middleware(local, app), scope, [b"a" * 500, b"b" * 500])
        assert parse_response(sent)[0] == 200
        assert app.calls == 1

    def test_public_path_skips_verification_but_gets_security_headers(self, env: Env) -> None:
        app = RecordingApp()
        sent = drive(make_middleware(env, app), make_scope(env, [], path="/public", authorization=None))
        status, headers, _body = parse_response(sent)

        assert status == 200
        assert app.calls == 1
        assert app.scope is not None
        assert VERIFIED_CONTEXT_SCOPE_KEY not in app.scope
        assert_security_headers_present(headers)

    def test_websocket_connections_are_closed(self, env: Env) -> None:
        app = RecordingApp()
        sent = drive(make_middleware(env, app), {"type": "websocket", "headers": []})
        assert sent == [{"type": "websocket.close", "code": 1008}]
        assert app.calls == 0

    def test_nonce_challenge_is_surfaced(self, env: Env) -> None:
        app = RecordingApp()
        mw = make_middleware(env, app, nonce_provider=FakeNonceProvider())
        sent = drive(mw, make_scope(env))
        status, headers, body = parse_response(sent)

        assert status == 401
        assert json.loads(body) == {"error": "use_dpop_nonce"}
        assert dict(headers)["dpop-nonce"] == "fresh-nonce"
        assert 'error="use_dpop_nonce"' in dict(headers)["www-authenticate"]
        assert app.calls == 0
        assert env.store.seen == {}