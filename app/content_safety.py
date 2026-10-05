from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import html
import re
import unicodedata
from urllib.parse import unquote


class TrustClass(str, Enum):
    SAFE_FOR_DATA_EXTRACTION = "SAFE_FOR_DATA_EXTRACTION"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class ContentAssessment:
    trust_class: TrustClass
    reasons: tuple[str, ...]
    contains_url: bool
    contains_payment_instruction: bool
    contains_privileged_instruction: bool
    contains_prompt_injection: bool
    contains_secret_request: bool


_URL_RE = re.compile(
    r"(?i)\b(?:https?://|www\.)[^\s<>'\"]+"
)


# Detect dangerous schemes even when attackers insert whitespace
# or normalized invisible characters between individual letters.
_DANGEROUS_SCHEME_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"\bj\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:"
    r"|\bv\s*b\s*s\s*c\s*r\s*i\s*p\s*t\s*:"
    r"|\bd\s*a\s*t\s*a\s*:"
    r"|\bf\s*i\s*l\s*e\s*:"
    r")"
)


_PAYMENT_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"\btransfer\b"
    r"|\bsend\s+(?:money|payment|funds)\b"
    r"|\bpay\s+(?:₹|rs\.?|inr|\$|usd)?\s*\d"
    r"|\bpayment\b"
    r"|\bbeneficiary\b"
    r"|\bupi\b"
    r"|\bbank\s+account\b"
    r"|\baccount\s+number\b"
    r"|\bwire\s+transfer\b"
    r")"
)


_PRIVILEGED_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"\bdisable\s+(?:security|authentication|auth|logging|audit)\b"
    r"|\bbypass\s+(?:security|authentication|auth|verification)\b"
    r"|\bturn\s+off\s+(?:security|authentication|logging|audit)\b"
    r"|\bchange\s+(?:security|admin|authorization)\s+settings?\b"
    r"|\bgrant\s+(?:access|admin|privilege)\b"
    r"|\belevate\s+privileges?\b"
    r")"
)


_PROMPT_INJECTION_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"\bignore\s+(?:all\s+)?previous\s+instructions?\b"
    r"|\bignore\s+(?:the\s+)?(?:system|security)\s+instructions?\b"
    r"|\bdisregard\s+(?:all\s+)?previous\s+instructions?\b"
    r"|\bforget\s+(?:the\s+)?(?:previous|system)\s+instructions?\b"
    r"|\byou\s+are\s+now\s+(?:authorized|allowed|admin)\b"
    r"|\bact\s+as\s+(?:administrator|admin|system)\b"
    r"|\boverride\s+(?:security|policy|authorization)\b"
    r")"
)


_SECRET_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"\breveal\b.{0,80}\b"
    r"(?:key|secret|password|pin|otp|token|credential)\b"
    r"|\bshow\b.{0,80}\b"
    r"(?:internal\s+key|secret|password|pin|otp|token)\b"
    r"|\bprovide\b.{0,80}\b"
    r"(?:password|pin|otp|secret|private\s+key)\b"
    r"|\b(?:upi|atm|bank|card)\s+pin\b"
    r"|\b(?:one[-\s]?time\s+password|otp)\b"
    r")"
)


_DANGEROUS_ACTION_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"\bexecute\s+(?:this\s+)?(?:payment|transfer|transaction)\b"
    r"|\bdo\s+it\s+immediately\b"
    r"|\bno\s+confirmation\s+(?:needed|required)\b"
    r"|\bwithout\s+(?:confirmation|verification|authentication)\b"
    r")"
)


_PERCENT_ESCAPE_RE = re.compile(
    r"%(?:[0-9A-Fa-f]{2})"
)


_INVALID_PERCENT_ESCAPE_RE = re.compile(
    r"%(?![0-9A-Fa-f]{2})"
)


_MAX_CONTENT_LENGTH = 1_000_000
_MAX_NORMALIZATION_PASSES = 4


# Common Unicode characters that can visually imitate ASCII
# characters used in security-sensitive schemes and instructions.
#
# This translation is used ONLY for threat detection.
# It never changes the original user content.
_HOMOGLYPH_TRANSLATION = str.maketrans(
    {
        # Cyrillic
        "А": "A",
        "а": "a",
        "В": "B",
        "в": "b",
        "С": "C",
        "с": "c",
        "Е": "E",
        "е": "e",
        "Н": "H",
        "н": "h",
        "І": "I",
        "і": "i",
        "Ј": "J",
        "ј": "j",
        "К": "K",
        "к": "k",
        "М": "M",
        "м": "m",
        "О": "O",
        "о": "o",
        "Р": "P",
        "р": "p",
        "Ѕ": "S",
        "ѕ": "s",
        "Т": "T",
        "т": "t",
        "Х": "X",
        "х": "x",
        "У": "Y",
        "у": "y",

        # Greek
        "Α": "A",
        "α": "a",
        "Β": "B",
        "β": "b",
        "Ε": "E",
        "ε": "e",
        "Η": "H",
        "η": "h",
        "Ι": "I",
        "ι": "i",
        "Κ": "K",
        "κ": "k",
        "Μ": "M",
        "μ": "m",
        "Ν": "N",
        "ν": "n",
        "Ο": "O",
        "ο": "o",
        "Ρ": "P",
        "ρ": "p",
        "Τ": "T",
        "τ": "t",
        "Χ": "X",
        "χ": "x",
        "Υ": "Y",
        "υ": "y",
        "Ζ": "Z",
        "ζ": "z",

        # Common mathematical/script lookalikes
        "K": "K",
        "Å": "A",
    }
)


def _has_match(
    pattern: re.Pattern[str],
    text: str,
) -> bool:
    return pattern.search(text) is not None


def _contains_percent_encoding(text: str) -> bool:
    return _PERCENT_ESCAPE_RE.search(text) is not None


def _contains_invalid_percent_encoding(text: str) -> bool:
    return _INVALID_PERCENT_ESCAPE_RE.search(text) is not None


def _remove_invisible_characters(text: str) -> str:
    """
    Replace Unicode control and formatting characters with spaces
    in the detection representation.

    This preserves word boundaries across:
        - tab
        - carriage return
        - line feed
        - zero-width space
        - zero-width joiner/non-joiner
        - bidirectional formatting controls

    The original content is never modified.
    """

    return "".join(
        " "
        if unicodedata.category(character) in {"Cc", "Cf"}
        else character
        for character in text
    )


def _canonicalize_homoglyphs(text: str) -> str:
    """
    Convert common Unicode lookalikes into ASCII equivalents.

    Detection only. The original content remains untouched.
    """

    return text.translate(_HOMOGLYPH_TRANSLATION)


def _normalize_for_detection(
    content: str,
) -> tuple[str, bool]:
    """
    Normalize hostile content for detection only.

    The original input is never executed, opened, followed,
    interpreted as authority, or otherwise acted upon.

    Normalization is strictly bounded and includes:

    - Unicode NFKC normalization
    - HTML entity decoding
    - bounded percent decoding
    - replacement of invisible control/format characters
    - common Unicode homoglyph canonicalization
    """

    if len(content) > _MAX_CONTENT_LENGTH:
        return content, True

    current = content
    malformed_encoding = False

    for _ in range(_MAX_NORMALIZATION_PASSES):
        previous = current

        current = unicodedata.normalize(
            "NFKC",
            current,
        )

        current = html.unescape(current)

        if _contains_invalid_percent_encoding(current):
            malformed_encoding = True

        current = unquote(current)

        current = unicodedata.normalize(
            "NFKC",
            current,
        )

        current = _remove_invisible_characters(
            current
        )

        current = _canonicalize_homoglyphs(
            current
        )

        if current == previous:
            break

    return current, malformed_encoding


def assess_untrusted_content(
    content: str,
) -> ContentAssessment:
    """
    Classify external/untrusted content.

    Security invariants:

    - External content never grants authorization.
    - External content never grants privilege.
    - External content never authenticates a user.
    - Instructions inside external content are never executed.
    - URLs are detected but never followed.
    - Dangerous URL schemes are blocked.
    - Encoded dangerous content is normalized before classification.
    - Invisible-character obfuscation is normalized before classification.
    - Unicode homoglyph obfuscation is normalized before classification.
    - Malformed encoding fails closed into review.
    - Normalization has a strict upper bound.
    """

    if not isinstance(content, str):
        raise TypeError("content must be a string")

    original = content.strip()

    if not original:
        return ContentAssessment(
            trust_class=TrustClass.SAFE_FOR_DATA_EXTRACTION,
            reasons=("EMPTY_CONTENT",),
            contains_url=False,
            contains_payment_instruction=False,
            contains_privileged_instruction=False,
            contains_prompt_injection=False,
            contains_secret_request=False,
        )

    normalized, malformed_encoding = _normalize_for_detection(
        original
    )

    contains_url = _has_match(
        _URL_RE,
        normalized,
    )

    contains_dangerous_scheme = _has_match(
        _DANGEROUS_SCHEME_RE,
        normalized,
    )

    contains_payment = _has_match(
        _PAYMENT_RE,
        normalized,
    )

    contains_privileged = _has_match(
        _PRIVILEGED_RE,
        normalized,
    )

    contains_injection = _has_match(
        _PROMPT_INJECTION_RE,
        normalized,
    )

    contains_secret = _has_match(
        _SECRET_RE,
        normalized,
    )

    contains_dangerous_action = _has_match(
        _DANGEROUS_ACTION_RE,
        normalized,
    )

    original_contains_encoding = (
        _contains_percent_encoding(original)
        or original != normalized
    )

    reasons: list[str] = []

    if contains_url:
        reasons.append("URL_PRESENT")

    if contains_dangerous_scheme:
        reasons.append("DANGEROUS_URL_SCHEME")

    if malformed_encoding:
        reasons.append(
            "MALFORMED_OR_SUSPICIOUS_ENCODING"
        )

    if original_contains_encoding:
        reasons.append(
            "ENCODED_OR_NORMALIZED_CONTENT"
        )

    if contains_payment:
        reasons.append(
            "PAYMENT_OR_FINANCIAL_INSTRUCTION"
        )

    if contains_privileged:
        reasons.append(
            "PRIVILEGED_SECURITY_INSTRUCTION"
        )

    if contains_injection:
        reasons.append(
            "PROMPT_INJECTION_PATTERN"
        )

    if contains_secret:
        reasons.append(
            "SECRET_OR_CREDENTIAL_REQUEST"
        )

    if contains_dangerous_action:
        reasons.append(
            "IRREVERSIBLE_ACTION_LANGUAGE"
        )

    # Highest-risk classification wins.
    #
    # Dangerous executable/local-resource schemes are BLOCKED.
    # Malformed encoding is REVIEW_REQUIRED.
    # Security/credential/payment/injection language is REVIEW_REQUIRED.
    #
    # Nothing here grants authority.

    if contains_dangerous_scheme:
        trust_class = TrustClass.BLOCKED

    elif malformed_encoding:
        trust_class = TrustClass.REVIEW_REQUIRED

    elif contains_injection:
        trust_class = TrustClass.REVIEW_REQUIRED

    elif contains_secret:
        trust_class = TrustClass.REVIEW_REQUIRED

    elif contains_privileged:
        trust_class = TrustClass.REVIEW_REQUIRED

    elif contains_payment:
        trust_class = TrustClass.REVIEW_REQUIRED

    elif contains_dangerous_action:
        trust_class = TrustClass.REVIEW_REQUIRED

    else:
        trust_class = TrustClass.SAFE_FOR_DATA_EXTRACTION

    if not reasons:
        reasons.append(
            "NO_KNOWN_AUTHORITY_ESCALATION_PATTERN"
        )

    return ContentAssessment(
        trust_class=trust_class,
        reasons=tuple(reasons),
        contains_url=contains_url,
        contains_payment_instruction=contains_payment,
        contains_privileged_instruction=contains_privileged,
        contains_prompt_injection=contains_injection,
        contains_secret_request=contains_secret,
    )


def is_authorization_granting_content(
    content: str,
) -> bool:
    """
    Hard security boundary.

    No externally supplied content can ever grant
    authorization.

    Always returns False by design.
    """

    return False


def is_safe_to_use_as_authority(
    content: str,
) -> bool:
    """
    Hard security boundary.

    External content may be evidence, but it can never
    become security authority.

    Always returns False by design.
    """

    return False