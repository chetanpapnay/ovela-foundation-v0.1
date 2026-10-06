from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from enum import Enum
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class TemporalSource(str, Enum):
    SERVER_SYSTEM_CLOCK = "SERVER_SYSTEM_CLOCK"
    INJECTED_CLOCK = "INJECTED_CLOCK"


class TemporalConfidence(str, Enum):
    TRUSTED = "TRUSTED"
    UNVERIFIED = "UNVERIFIED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class TemporalContext:
    """
    Authoritative temporal context supplied to application logic.

    Security invariants:

    1. Application logic must not silently call datetime.now().
    2. All security-relevant consumers receive an explicit temporal context.
    3. Datetimes must be timezone-aware.
    4. UTC is the canonical storage/comparison timezone.
    5. Local dates are derived only after an explicit IANA timezone is supplied.
    6. Temporal context is never an authentication or authorization mechanism.
    """

    timestamp_utc: datetime
    timezone_name: str
    source: TemporalSource
    confidence: TemporalConfidence

    def __post_init__(self) -> None:
        if not isinstance(self.timestamp_utc, datetime):
            raise TypeError("timestamp_utc must be a datetime")

        if self.timestamp_utc.tzinfo is None:
            raise ValueError("timestamp_utc must be timezone-aware")

        if self.timestamp_utc.utcoffset() is None:
            raise ValueError("timestamp_utc must have a valid UTC offset")

        if not isinstance(self.timezone_name, str):
            raise TypeError("timezone_name must be a string")

        if not self.timezone_name.strip():
            raise ValueError("timezone_name cannot be empty")

        try:
            ZoneInfo(self.timezone_name)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(
                f"unknown IANA timezone: {self.timezone_name}"
            ) from exc

        if not isinstance(self.source, TemporalSource):
            raise TypeError("source must be a TemporalSource")

        if not isinstance(self.confidence, TemporalConfidence):
            raise TypeError(
                "confidence must be a TemporalConfidence"
            )

        normalized = self.timestamp_utc.astimezone(timezone.utc)

        object.__setattr__(
            self,
            "timestamp_utc",
            normalized,
        )

    @property
    def local_datetime(self) -> datetime:
        """Return the authoritative timestamp in the configured timezone."""

        return self.timestamp_utc.astimezone(
            ZoneInfo(self.timezone_name)
        )

    @property
    def local_date(self) -> date:
        """Return the authoritative calendar date in the configured timezone."""

        return self.local_datetime.date()

    @property
    def is_trusted(self) -> bool:
        """
        Return whether this temporal reading is explicitly trusted.

        This flag describes temporal evidence only. It grants no
        identity, authentication, authorization, or financial authority.
        """

        return self.confidence is TemporalConfidence.TRUSTED


def from_datetime(
    timestamp: datetime,
    timezone_name: str,
    *,
    source: TemporalSource = TemporalSource.INJECTED_CLOCK,
    confidence: TemporalConfidence = TemporalConfidence.TRUSTED,
) -> TemporalContext:
    """
    Construct temporal context from an explicitly supplied datetime.

    This is the primary deterministic/testable boundary.

    Naive datetimes are rejected rather than silently assuming a timezone.
    """

    if not isinstance(timestamp, datetime):
        raise TypeError("timestamp must be a datetime")

    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError(
            "timestamp must be timezone-aware"
        )

    return TemporalContext(
        timestamp_utc=timestamp.astimezone(timezone.utc),
        timezone_name=timezone_name,
        source=source,
        confidence=confidence,
    )


def from_server_clock(
    timezone_name: str,
) -> TemporalContext:
    """
    Read the current server clock and create temporal context.

    The server clock is an infrastructure dependency. It is not treated
    as proof of identity or authorization.

    Higher-assurance deployments can replace this boundary with a
    synchronized or independently verified time source without changing
    consumers such as owner_context.py.
    """

    timestamp = datetime.now(timezone.utc)

    return from_datetime(
        timestamp=timestamp,
        timezone_name=timezone_name,
        source=TemporalSource.SERVER_SYSTEM_CLOCK,
        confidence=TemporalConfidence.TRUSTED,
    )


def current_date(
    timezone_name: str,
) -> date:
    """
    Return the current server-derived calendar date in an IANA timezone.

    Consumers should prefer receiving TemporalContext directly when the
    exact timestamp and provenance are relevant.
    """

    return from_server_clock(
        timezone_name=timezone_name,
    ).local_date


def date_from_context(
    context: TemporalContext,
) -> date:
    """
    Extract the authoritative local calendar date from temporal context.
    """

    if not isinstance(context, TemporalContext):
        raise TypeError(
            "context must be a TemporalContext"
        )

    return context.local_date


def utc_timestamp(
    context: TemporalContext,
) -> datetime:
    """
    Return the canonical UTC timestamp from temporal context.
    """

    if not isinstance(context, TemporalContext):
        raise TypeError(
            "context must be a TemporalContext"
        )

    return context.timestamp_utc