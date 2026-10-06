from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo

import pytest

from app.temporal_context import (
    TemporalConfidence,
    TemporalContext,
    TemporalSource,
    current_date,
    date_from_context,
    from_server_clock,
    utc_timestamp,
)


def test_temporal_context_preserves_trusted_timestamp() -> None:
    timestamp = datetime(
        2026,
        10,
        6,
        12,
        30,
        tzinfo=timezone.utc,
    )

    context = TemporalContext(
        timestamp_utc=timestamp,
        timezone_name="UTC",
        source=TemporalSource.INJECTED_CLOCK,
        confidence=TemporalConfidence.TRUSTED,
    )

    assert context.timestamp_utc == timestamp
    assert context.timezone_name == "UTC"
    assert context.source is TemporalSource.INJECTED_CLOCK
    assert context.confidence is TemporalConfidence.TRUSTED
    assert context.local_date == date(2026, 10, 6)


def test_temporal_context_rejects_non_datetime_timestamp() -> None:
    with pytest.raises(TypeError):
        TemporalContext(
            timestamp_utc="2026-10-06T12:30:00+00:00",
            timezone_name="UTC",
            source=TemporalSource.INJECTED_CLOCK,
            confidence=TemporalConfidence.TRUSTED,
        )


def test_temporal_context_rejects_naive_timestamp() -> None:
    with pytest.raises(ValueError):
        TemporalContext(
            timestamp_utc=datetime(2026, 10, 6, 12, 30),
            timezone_name="UTC",
            source=TemporalSource.INJECTED_CLOCK,
            confidence=TemporalConfidence.TRUSTED,
        )


def test_temporal_context_rejects_non_string_timezone() -> None:
    with pytest.raises(TypeError):
        TemporalContext(
            timestamp_utc=datetime(
                2026,
                10,
                6,
                12,
                30,
                tzinfo=timezone.utc,
            ),
            timezone_name=123,
            source=TemporalSource.INJECTED_CLOCK,
            confidence=TemporalConfidence.TRUSTED,
        )


def test_temporal_context_rejects_empty_timezone() -> None:
    with pytest.raises(ValueError):
        TemporalContext(
            timestamp_utc=datetime(
                2026,
                10,
                6,
                12,
                30,
                tzinfo=timezone.utc,
            ),
            timezone_name="",
            source=TemporalSource.INJECTED_CLOCK,
            confidence=TemporalConfidence.TRUSTED,
        )


def test_temporal_context_rejects_unknown_timezone() -> None:
    with pytest.raises(ValueError):
        TemporalContext(
            timestamp_utc=datetime(
                2026,
                10,
                6,
                12,
                30,
                tzinfo=timezone.utc,
            ),
            timezone_name="Not/A/Real_Timezone",
            source=TemporalSource.INJECTED_CLOCK,
            confidence=TemporalConfidence.TRUSTED,
        )


def test_temporal_context_requires_timezone_aware_timestamp() -> None:
    with pytest.raises(ValueError):
        TemporalContext(
            timestamp_utc=datetime(
                2026,
                10,
                6,
                12,
                30,
            ),
            timezone_name="Asia/Kolkata",
            source=TemporalSource.INJECTED_CLOCK,
            confidence=TemporalConfidence.TRUSTED,
        )


def test_temporal_context_requires_valid_source() -> None:
    with pytest.raises(TypeError):
        TemporalContext(
            timestamp_utc=datetime(
                2026,
                10,
                6,
                12,
                30,
                tzinfo=timezone.utc,
            ),
            timezone_name="UTC",
            source="INJECTED_CLOCK",
            confidence=TemporalConfidence.TRUSTED,
        )


def test_temporal_context_requires_valid_confidence() -> None:
    with pytest.raises(TypeError):
        TemporalContext(
            timestamp_utc=datetime(
                2026,
                10,
                6,
                12,
                30,
                tzinfo=timezone.utc,
            ),
            timezone_name="UTC",
            source=TemporalSource.INJECTED_CLOCK,
            confidence="TRUSTED",
        )


def test_local_date_respects_timezone_conversion() -> None:
    timestamp = datetime(
        2026,
        10,
        5,
        20,
        0,
        tzinfo=timezone.utc,
    )

    context = TemporalContext(
        timestamp_utc=timestamp,
        timezone_name="Asia/Kolkata",
        source=TemporalSource.INJECTED_CLOCK,
        confidence=TemporalConfidence.TRUSTED,
    )

    assert context.local_date == date(2026, 10, 6)


def test_date_from_context_returns_authoritative_local_date() -> None:
    timestamp = datetime(
        2026,
        10,
        5,
        20,
        0,
        tzinfo=timezone.utc,
    )

    context = TemporalContext(
        timestamp_utc=timestamp,
        timezone_name="Asia/Kolkata",
        source=TemporalSource.INJECTED_CLOCK,
        confidence=TemporalConfidence.TRUSTED,
    )

    assert date_from_context(context) == date(2026, 10, 6)


def test_date_from_context_rejects_invalid_context() -> None:
    with pytest.raises(TypeError):
        date_from_context("not-a-temporal-context")


def test_utc_timestamp_returns_context_timestamp() -> None:
    timestamp = datetime(
        2026,
        10,
        6,
        12,
        30,
        tzinfo=timezone.utc,
    )

    context = TemporalContext(
        timestamp_utc=timestamp,
        timezone_name="UTC",
        source=TemporalSource.INJECTED_CLOCK,
        confidence=TemporalConfidence.TRUSTED,
    )

    assert utc_timestamp(context) == timestamp


def test_utc_timestamp_rejects_invalid_context() -> None:
    with pytest.raises(TypeError):
        utc_timestamp("not-a-temporal-context")


def test_current_date_returns_calendar_date() -> None:
    result = current_date("Asia/Kolkata")

    assert isinstance(result, date)


def test_current_date_rejects_empty_timezone() -> None:
    with pytest.raises(ValueError):
        current_date("")


def test_current_date_rejects_unknown_timezone() -> None:
    with pytest.raises(ValueError):
        current_date("Not/A/Real_Timezone")


def test_from_server_clock_returns_trusted_context() -> None:
    context = from_server_clock("Asia/Kolkata")

    assert isinstance(context, TemporalContext)
    assert context.timezone_name == "Asia/Kolkata"
    assert context.source is TemporalSource.SERVER_SYSTEM_CLOCK
    assert context.confidence is TemporalConfidence.TRUSTED
    assert context.timestamp_utc.tzinfo is not None
    assert ZoneInfo("Asia/Kolkata")


def test_from_server_clock_rejects_invalid_timezone() -> None:
    with pytest.raises(ValueError):
        from_server_clock("Not/A/Real_Timezone")