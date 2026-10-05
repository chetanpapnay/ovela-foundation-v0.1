from __future__ import annotations

from dataclasses import dataclass
import html
import re
import unicodedata
from urllib.parse import unquote


@dataclass(frozen=True)
class ThreatFinding:
    category: str
    severity: str
    reason: str


@dataclass(frozen=True)
class ThreatScanResult:
    trusted_for_instructions: bool
    findings: tuple[ThreatFinding, ...]


_MAX_CONTENT_LENGTH = 1_000_000
_MAX_NORMALIZATION_PASSES = 3


# Common Unicode lookalikes used to disguise security-sensitive words.
_HOMOGLYPH_MAP = str.maketrans(
    {
        "а": "a",
        "А": "A",
        "е": "e",
        "Е": "E",
        "і": "i",
        "І": "I",
        "о": "o",
        "О": "O",
        "р": "p",
        "Р": "P",
        "с": "c",
        "С": "C",
        "х": "x",
        "Х": "X",
        "у": "y",
        "У": "Y",
        "ѕ": "s",
        "Ѕ": "S",
        "і": "i",
        "І": "I",
    }
)


def _normalize_content(content: str) -> str:
    """
    Produce a bounded canonical representation for threat detection.

    This function does not execute or interpret the content as instructions.
    It only creates additional representations for deterministic scanning.
    """
    normalized = content

    for _ in range(_MAX_NORMALIZATION_PASSES):
        previous = normalized

        normalized = html.unescape(normalized)
        normalized = unquote(normalized)
        normalized = unicodedata.normalize("NFKC", normalized)
        normalized = normalized.translate(_HOMOGLYPH_MAP)

        # Remove invisible formatting characters that can split attack words.
        normalized = "".join(
            char
            for char in normalized
            if unicodedata.category(char) != "Cf"
        )

        # Convert control characters into spaces instead of allowing them
        # to hide dangerous phrases.
        normalized = "".join(
            char if char in "\n\r\t" or ord(char) >= 32 else " "
            for char in normalized
        )

        if normalized == previous:
            break

    return normalized


INJECTION_PATTERNS = (
    (
        "PROMPT_INJECTION",
        "HIGH",
        re.compile(
            r"\b(ignore|disregard|forget|override)\b.{0,120}"
            r"\b(previous|prior|system|developer|security|instructions?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "Content attempts to override existing instructions.",
    ),
    (
        "PROMPT_INJECTION",
        "HIGH",
        re.compile(
            r"\b(?:follow|obey|execute|act\s+on)\b.{0,120}"
            r"\b(?:these|the)\s+(?:instructions?|commands?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "Content attempts to make untrusted text function as instructions.",
    ),
    (
        "PRIVILEGE_ESCALATION",
        "HIGH",
        re.compile(
            r"\b(bypass|disable|turn\s+off|remove|circumvent)\b.{0,120}"
            r"\b(security|authentication|verification|authorization|protection)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "Content attempts to weaken or bypass security controls.",
    ),
    (
        "SECRET_REQUEST",
        "CRITICAL",
        re.compile(
            r"\b(reveal|provide|send|share|enter|give\s+me|disclose)\b"
            r".{0,120}"
            r"\b(password|passcode|pin|upi\s+pin|otp|cvv|secret|"
            r"private\s+key|token|api\s+key|access\s+key)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "Content requests a credential or security secret.",
    ),
    (
        "FALSE_AUTHORITY",
        "HIGH",
        re.compile(
            r"\b(system\s+message|developer\s+message|"
            r"administrator\s+instruction|security\s+administrator|"
            r"system\s+administrator)\b",
            re.IGNORECASE,
        ),
        "Untrusted content claims privileged authority.",
    ),
    (
        "AUTHORITY_CLAIM",
        "HIGH",
        re.compile(
            r"\bI\s+am\s+(?:the\s+)?"
            r"(?:administrator|admin|owner|security\s+officer)\b",
            re.IGNORECASE,
        ),
        "Content attempts to establish authority without trusted verification.",
    ),
    (
        "URGENT_FINANCIAL_ACTION",
        "HIGH",
        re.compile(
            r"\b(urgent|immediately|right\s+now|act\s+now|"
            r"asap|within\s+\d+\s+(?:minutes?|hours?))\b"
            r".{0,120}"
            r"\b(transfer|pay|send|wire|payment|money|funds)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "Content combines urgency with a financial action.",
    ),
    (
        "CONFIRMATION_BYPASS",
        "HIGH",
        re.compile(
            r"\b(?:skip|bypass|disable|avoid|do\s+not\s+require)\b"
            r".{0,100}"
            r"\b(?:confirmation|approval|verification|review)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "Content attempts to bypass an approval or confirmation control.",
    ),
    (
        "DANGEROUS_SCHEME",
        "HIGH",
        re.compile(
            r"\b(?:javascript|vbscript|data|file):",
            re.IGNORECASE,
        ),
        "Content contains a potentially dangerous URL scheme.",
    ),
)


URL_PATTERN = re.compile(
    r"\bhttps?://[^\s<>'\"]+",
    re.IGNORECASE,
)


MALFORMED_ENCODING_PATTERN = re.compile(
    r"%(?![0-9A-Fa-f]{2})",
)


def _finding_exists(
    findings: list[ThreatFinding],
    category: str,
) -> bool:
    return any(finding.category == category for finding in findings)


def scan_untrusted_content(
    content: str,
    *,
    source_type: str = "unknown",
) -> ThreatScanResult:
    """
    Scan external/untrusted content.

    Security guarantees:

    - Never executes instructions from content.
    - Never follows URLs.
    - Never grants authority based on content.
    - Never treats external content as trusted instructions.
    - Uses bounded normalization to detect common obfuscation.
    - Fails closed by returning trusted_for_instructions=False.
    """
    if not isinstance(content, str):
        raise TypeError("content must be a string")

    if len(content) > _MAX_CONTENT_LENGTH:
        raise ValueError(
            f"content exceeds maximum allowed length of "
            f"{_MAX_CONTENT_LENGTH} characters"
        )

    if not isinstance(source_type, str):
        raise TypeError("source_type must be a string")

    normalized = _normalize_content(content)

    findings: list[ThreatFinding] = []

    for category, severity, pattern, reason in INJECTION_PATTERNS:
        if pattern.search(normalized):
            findings.append(
                ThreatFinding(
                    category=category,
                    severity=severity,
                    reason=f"{reason} Source: {source_type}.",
                )
            )

    if URL_PATTERN.search(normalized):
        findings.append(
            ThreatFinding(
                category="EXTERNAL_URL",
                severity="MEDIUM",
                reason=(
                    "Content contains an external URL. "
                    "Ovela must not automatically follow it."
                ),
            )
        )

    if MALFORMED_ENCODING_PATTERN.search(content):
        if not _finding_exists(findings, "MALFORMED_ENCODING"):
            findings.append(
                ThreatFinding(
                    category="MALFORMED_ENCODING",
                    severity="MEDIUM",
                    reason=(
                        "Content contains malformed percent encoding "
                        "and requires additional review."
                    ),
                )
            )

    return ThreatScanResult(
        trusted_for_instructions=False,
        findings=tuple(findings),
    )