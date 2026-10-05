"""
Ovela Trust Boundary
RT-F28

External content is evidence, never authority.

This module performs deterministic pre-processing of untrusted content.
It does NOT execute instructions, follow URLs, open files, scan QR codes,
grant permissions, or establish authority based on document/message content.

Security model:

    SAFE_FOR_DATA_EXTRACTION
        |
        v
    REVIEW_REQUIRED
        |
        v
    BLOCKED

External content can never:
- execute an Ovela instruction
- authorize an Ovela action
- grant Ovela privilege
- override security policy
- establish authority merely by claiming authority
- cause URLs or local resources to be opened automatically
"""

from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Iterable
from urllib.parse import unquote


class TrustClass(str, Enum):
    UNTRUSTED = "UNTRUSTED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    SAFE_FOR_DATA_EXTRACTION = "SAFE_FOR_DATA_EXTRACTION"
    BLOCKED = "BLOCKED"


class ThreatType(str, Enum):
    PROMPT_INJECTION = "PROMPT_INJECTION"
    AUTHORITY_CLAIM = "AUTHORITY_CLAIM"
    SECURITY_BYPASS = "SECURITY_BYPASS"
    PAYMENT_INSTRUCTION = "PAYMENT_INSTRUCTION"
    CREDENTIAL_REQUEST = "CREDENTIAL_REQUEST"
    DANGEROUS_URL = "DANGEROUS_URL"
    EXTERNAL_URL = "EXTERNAL_URL"
    QR_OR_CODE_INSTRUCTION = "QR_OR_CODE_INSTRUCTION"
    URGENT_ACTION = "URGENT_ACTION"
    CONFIRMATION_BYPASS = "CONFIRMATION_BYPASS"
    MALFORMED_ENCODING = "MALFORMED_ENCODING"


_MAX_CONTENT_LENGTH = 1_000_000
_MAX_NORMALIZATION_PASSES = 3


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_DANGEROUS_URL_RE = re.compile(
    r"(?:javascript|vbscript|data|file):",
    re.IGNORECASE,
)


_EXTERNAL_URL_RE = re.compile(
    r"\bhttps?://[^\s<>'\"]+",
    re.IGNORECASE,
)


_PROMPT_INJECTION_PATTERNS = (
    (
        re.compile(
            r"\b(?:ignore|disregard)\s+"
            r"(?:all\s+)?"
            r"(?:previous|prior|earlier|above)\s+instructions\b",
            re.IGNORECASE,
        ),
        "Attempts to override previously established instructions.",
    ),
    (
        re.compile(
            r"\b(?:system|developer)\s+prompt\b",
            re.IGNORECASE,
        ),
        "Attempts to reference or manipulate privileged instructions.",
    ),
    (
        re.compile(
            r"\bdo\s+not\s+tell\s+the\s+user\b",
            re.IGNORECASE,
        ),
        "Attempts to conceal behavior from the user.",
    ),
)


_AUTHORITY_PATTERNS = (
    re.compile(
        r"\bI\s+am\s+(?:the\s+)?"
        r"(?:administrator|admin|owner|security\s+officer)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:authorized|authorised|official)\s+"
        r"(?:instruction|command|request)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:security|system)\s+administrator\s+"
        r"(?:says|said|requests|requested)\b",
        re.IGNORECASE,
    ),
)


_PAYMENT_PATTERNS = (
    re.compile(
        r"\b(?:transfer|send|pay|wire)\b"
        r".{0,120}"
        r"(?:money|amount|₹|rs\.?|inr|\$|usd|eur|€|gbp|£)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"\bpay\s+(?:now|immediately|urgently)\b",
        re.IGNORECASE,
    ),
)


_CREDENTIAL_PATTERNS = (
    re.compile(
        r"\b(?:UPI|ATM|bank|card)\s+PIN\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:password|passcode|OTP|one[-\s]?time\s+password|CVV)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:secret|private|internal)\s+key\b",
        re.IGNORECASE,
    ),
)


_SECURITY_BYPASS_PATTERNS = (
    (
        re.compile(
            r"\b(?:bypass|disable|turn\s+off|circumvent|skip|remove|override)\b"
            r".{0,120}"
            r"\b(?:security|authentication|authorization|authorisation|"
            r"verification|access\s+control|protection)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "Attempts to bypass or disable a security control.",
    ),
)


_PRIVILEGED_INSTRUCTION_PATTERNS = (
    (
        re.compile(
            r"\b(?:grant|give|assign|enable|activate|authorize|authorise)\b"
            r".{0,100}"
            r"\b(?:admin|administrator|privilege|permission|access|authority)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "Attempts to grant or modify privileged access.",
    ),
)


_URGENT_ACTION_PATTERNS = (
    (
        re.compile(
            r"\b(?:do\s+it|execute|proceed|act|perform)\b"
            r".{0,120}"
            r"\b(?:immediately|right\s+now|at\s+once|"
            r"without\s+confirmation|no\s+confirmation|"
            r"without\s+approval|no\s+approval)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "Uses urgency to pressure execution of an action.",
    ),
)


_CONFIRMATION_BYPASS_PATTERNS = (
    (
        re.compile(
            r"\b(?:without|skip|no)\b"
            r".{0,60}"
            r"\b(?:confirmation|approval|verification)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "Attempts to bypass confirmation, approval, or verification.",
    ),
)


_QR_CODE_PATTERNS = (
    (
        re.compile(
            r"\bscan\s+(?:this\s+)?QR\b",
            re.IGNORECASE,
        ),
        "Attempts to direct QR-code use.",
    ),
    (
        re.compile(
            r"\bQR\s+code\b.{0,80}"
            r"\b(?:pay|transfer|login|authorize|authorise)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "Attempts to use a QR code for a sensitive action.",
    ),
)


_MALFORMED_PERCENT_RE = re.compile(
    r"%(?![0-9A-Fa-f]{2})"
)


# ---------------------------------------------------------------------------
# Unicode / obfuscation normalization
# ---------------------------------------------------------------------------

_HOMOGLYPH_MAP = str.maketrans(
    {
        "а": "a",
        "А": "A",
        "с": "c",
        "С": "C",
        "е": "e",
        "Е": "E",
        "і": "i",
        "І": "I",
        "ј": "j",
        "Ј": "J",
        "о": "o",
        "О": "O",
        "р": "p",
        "Р": "P",
        "ѕ": "s",
        "Ѕ": "S",
        "у": "y",
        "У": "Y",
        "х": "x",
        "Х": "X",
    }
)


def _validate_input(text: str) -> None:
    if not isinstance(text, str):
        raise TypeError("untrusted content must be text")

    if len(text) > _MAX_CONTENT_LENGTH:
        raise ValueError(
            f"untrusted content exceeds maximum allowed length "
            f"of {_MAX_CONTENT_LENGTH} characters"
        )


def _bounded_decode(text: str) -> tuple[str, bool]:
    """
    Perform bounded decoding so attacker-controlled encoding cannot
    cause unbounded normalization work.
    """
    current = text
    changed = False

    for _ in range(_MAX_NORMALIZATION_PASSES):
        previous = current

        current = html.unescape(current)
        current = unquote(current)
        current = unicodedata.normalize("NFKC", current)

        if current != previous:
            changed = True
        else:
            break

    return current, changed


def _remove_invisible_formatting(text: str) -> tuple[str, bool]:
    output: list[str] = []
    changed = False

    for character in text:
        if unicodedata.category(character) == "Cf":
            changed = True
            continue

        output.append(character)

    return "".join(output), changed


def _remove_control_characters(text: str) -> tuple[str, bool]:
    output: list[str] = []
    changed = False

    for character in text:
        category = unicodedata.category(character)

        if category.startswith("C") and character not in "\t\n\r":
            changed = True
            continue

        output.append(character)

    return "".join(output), changed


def _normalize_for_detection(text: str) -> tuple[str, bool]:
    normalized, changed = _bounded_decode(text)

    normalized, formatting_changed = _remove_invisible_formatting(
        normalized
    )
    changed = changed or formatting_changed

    normalized, control_changed = _remove_control_characters(
        normalized
    )
    changed = changed or control_changed

    normalized = normalized.translate(_HOMOGLYPH_MAP)

    return normalized, changed


def _scheme_detection_text(text: str) -> str:
    """
    Produce a compact representation specifically for dangerous-scheme
    detection. Whitespace and control characters cannot split a dangerous
    scheme into an apparently harmless form.
    """
    output: list[str] = []

    for character in text:
        if character.isspace():
            continue

        if unicodedata.category(character).startswith("C"):
            continue

        output.append(character)

    return "".join(output).translate(_HOMOGLYPH_MAP)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ThreatFinding:
    threat_type: ThreatType
    reason: str
    evidence: str


@dataclass(frozen=True)
class TrustAssessment:
    trust_class: TrustClass
    findings: tuple[ThreatFinding, ...]
    can_execute_instructions: bool
    can_authorize_action: bool
    can_grant_privilege: bool


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def _snippet(
    text: str,
    match: re.Match[str] | None,
) -> str:
    if match is None:
        return ""

    start = max(0, match.start() - 60)
    end = min(len(text), match.end() + 60)

    return text[start:end].strip()


def _find_pattern(
    text: str,
    patterns: Iterable[tuple[re.Pattern[str], str]],
    threat_type: ThreatType,
) -> list[ThreatFinding]:
    findings: list[ThreatFinding] = []

    for pattern, reason in patterns:
        match = pattern.search(text)

        if match is None:
            continue

        findings.append(
            ThreatFinding(
                threat_type=threat_type,
                reason=reason,
                evidence=_snippet(text, match),
            )
        )

    return findings


def _find_simple_patterns(
    text: str,
    patterns: Iterable[re.Pattern[str]],
    threat_type: ThreatType,
    reason: str,
) -> list[ThreatFinding]:
    findings: list[ThreatFinding] = []

    for pattern in patterns:
        match = pattern.search(text)

        if match is None:
            continue

        findings.append(
            ThreatFinding(
                threat_type=threat_type,
                reason=reason,
                evidence=_snippet(text, match),
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Main trust-boundary assessment
# ---------------------------------------------------------------------------

def assess_untrusted_content(text: str) -> TrustAssessment:
    """
    Deterministically assess externally supplied content.

    Security guarantees:

    - Content is never executed.
    - URLs are detected but never opened.
    - Dangerous URL schemes are detected and require review.
    - Instructions inside content never become Ovela instructions.
    - Authority claims never establish authority.
    - Positive assessment never grants authorization.
    - Documents/messages cannot grant privilege.
    - Security controls cannot be disabled by content.
    - Encoded and obfuscated content is normalized before detection.
    """

    _validate_input(text)

    normalized, was_normalized = _normalize_for_detection(text)
    scheme_text = _scheme_detection_text(normalized)

    findings: list[ThreatFinding] = []

    # Prompt injection
    findings.extend(
        _find_pattern(
            normalized,
            _PROMPT_INJECTION_PATTERNS,
            ThreatType.PROMPT_INJECTION,
        )
    )

    # Authority claims
    findings.extend(
        _find_simple_patterns(
            normalized,
            _AUTHORITY_PATTERNS,
            ThreatType.AUTHORITY_CLAIM,
            "Content claims authority that must be independently verified.",
        )
    )

    # Security bypass
    findings.extend(
        _find_pattern(
            normalized,
            _SECURITY_BYPASS_PATTERNS,
            ThreatType.SECURITY_BYPASS,
        )
    )

    # Privileged instructions
    findings.extend(
        _find_pattern(
            normalized,
            _PRIVILEGED_INSTRUCTION_PATTERNS,
            ThreatType.AUTHORITY_CLAIM,
        )
    )

    # Payment instructions
    findings.extend(
        _find_simple_patterns(
            normalized,
            _PAYMENT_PATTERNS,
            ThreatType.PAYMENT_INSTRUCTION,
            "Content contains a financial-action instruction.",
        )
    )

    # Credential requests
    findings.extend(
        _find_simple_patterns(
            normalized,
            _CREDENTIAL_PATTERNS,
            ThreatType.CREDENTIAL_REQUEST,
            "Content references a credential or authentication secret.",
        )
    )

    # QR / code instructions
    findings.extend(
        _find_pattern(
            normalized,
            _QR_CODE_PATTERNS,
            ThreatType.QR_OR_CODE_INSTRUCTION,
        )
    )

    # Urgent action
    findings.extend(
        _find_pattern(
            normalized,
            _URGENT_ACTION_PATTERNS,
            ThreatType.URGENT_ACTION,
        )
    )

    # Confirmation / approval bypass
    findings.extend(
        _find_pattern(
            normalized,
            _CONFIRMATION_BYPASS_PATTERNS,
            ThreatType.CONFIRMATION_BYPASS,
        )
    )

    # Malformed encoding
    if _MALFORMED_PERCENT_RE.search(text):
        findings.append(
            ThreatFinding(
                threat_type=ThreatType.MALFORMED_ENCODING,
                reason=(
                    "Malformed percent encoding was detected. "
                    "The content cannot be trusted as safely encoded."
                ),
                evidence=text[:200],
            )
        )

    # Dangerous executable/local-resource URL
    dangerous_url_match = _DANGEROUS_URL_RE.search(scheme_text)

    if dangerous_url_match:
        findings.append(
            ThreatFinding(
                threat_type=ThreatType.DANGEROUS_URL,
                reason=(
                    "Dangerous executable or local-resource URL "
                    "scheme detected."
                ),
                evidence=_snippet(scheme_text, dangerous_url_match),
            )
        )

    # Normal external URL
    external_url_match = _EXTERNAL_URL_RE.search(normalized)

    if external_url_match:
        findings.append(
            ThreatFinding(
                threat_type=ThreatType.EXTERNAL_URL,
                reason=(
                    "External URL detected. Ovela must not follow "
                    "or open it automatically."
                ),
                evidence=_snippet(normalized, external_url_match),
            )
        )

    # Normalization evidence
    if was_normalized and not findings:
        findings.append(
            ThreatFinding(
                threat_type=ThreatType.EXTERNAL_URL,
                reason=(
                    "Content required normalization before detection. "
                    "Normalization alone does not make ordinary content "
                    "unsafe."
                ),
                evidence=normalized[:200],
            )
        )

    # Trust classification.
    #
    # This module's existing contract requires dangerous URLs to be
    # REVIEW_REQUIRED rather than BLOCKED.
    has_review_required_threat = any(
        finding.threat_type
        in {
            ThreatType.PROMPT_INJECTION,
            ThreatType.AUTHORITY_CLAIM,
            ThreatType.SECURITY_BYPASS,
            ThreatType.PAYMENT_INSTRUCTION,
            ThreatType.CREDENTIAL_REQUEST,
            ThreatType.DANGEROUS_URL,
            ThreatType.EXTERNAL_URL,
            ThreatType.QR_OR_CODE_INSTRUCTION,
            ThreatType.URGENT_ACTION,
            ThreatType.CONFIRMATION_BYPASS,
            ThreatType.MALFORMED_ENCODING,
        }
        for finding in findings
    )

    if has_review_required_threat:
        trust_class = TrustClass.REVIEW_REQUIRED
    else:
        trust_class = TrustClass.SAFE_FOR_DATA_EXTRACTION

    # Hard security invariants.
    return TrustAssessment(
        trust_class=trust_class,
        findings=tuple(findings),
        can_execute_instructions=False,
        can_authorize_action=False,
        can_grant_privilege=False,
    )


# ---------------------------------------------------------------------------
# Compatibility / fail-closed helpers
# ---------------------------------------------------------------------------

def is_authorization_granting_content(text: str) -> bool:
    """
    External content can never grant authorization.
    """
    _validate_input(text)
    return False


def is_safe_to_use_as_authority(text: str) -> bool:
    """
    External content can never become an authority source merely because
    it claims to be official, administrative, financial, or authoritative.
    """
    _validate_input(text)
    return False


def content_can_authorize_action(text: str) -> bool:
    """
    Compatibility alias for authorization checks.
    """
    _validate_input(text)
    return False


def content_can_grant_privilege(text: str) -> bool:
    """
    External content can never grant Ovela privilege.
    """
    _validate_input(text)
    return False


def content_can_execute_instruction(text: str) -> bool:
    """
    External content can never directly execute an Ovela instruction.
    """
    _validate_input(text)
    return False