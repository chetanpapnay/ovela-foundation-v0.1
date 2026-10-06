from __future__ import annotations

from app.runtime_health import (
    RuntimeComponent,
    RuntimeHealthState,
    degraded,
    healthy,
    offline,
    summarize_health,
    unavailable,
    unknown,
)


def test_healthy_result_preserves_component_and_evidence() -> None:
    result = healthy(
        RuntimeComponent.SERVER,
        message="Server is responding normally.",
        evidence="health endpoint returned successfully",
    )

    assert result.component is RuntimeComponent.SERVER
    assert result.state is RuntimeHealthState.HEALTHY
    assert result.message == "Server is responding normally."
    assert result.evidence == "health endpoint returned successfully"


def test_degraded_result_is_explicit() -> None:
    result = degraded(
        RuntimeComponent.LIVE_MODEL,
        message="Live model response is slower than expected.",
        evidence="measured response latency exceeded threshold",
    )

    assert result.component is RuntimeComponent.LIVE_MODEL
    assert result.state is RuntimeHealthState.DEGRADED
    assert result.message == "Live model response is slower than expected."
    assert result.evidence == "measured response latency exceeded threshold"


def test_offline_result_is_explicit() -> None:
    result = offline(
        RuntimeComponent.NETWORK,
        message="Network connection is unavailable.",
        evidence="network connectivity check failed",
    )

    assert result.component is RuntimeComponent.NETWORK
    assert result.state is RuntimeHealthState.OFFLINE
    assert result.message == "Network connection is unavailable."
    assert result.evidence == "network connectivity check failed"


def test_unavailable_result_is_explicit() -> None:
    result = unavailable(
        RuntimeComponent.VOICE,
        message="Voice provider is currently unavailable.",
        evidence="provider health check returned unavailable",
    )

    assert result.component is RuntimeComponent.VOICE
    assert result.state is RuntimeHealthState.UNAVAILABLE
    assert result.message == "Voice provider is currently unavailable."
    assert result.evidence == "provider health check returned unavailable"


def test_unknown_result_does_not_claim_health() -> None:
    result = unknown(
        RuntimeComponent.API,
        message="API health could not be determined.",
        evidence="insufficient evidence",
    )

    assert result.component is RuntimeComponent.API
    assert result.state is RuntimeHealthState.UNKNOWN
    assert result.message == "API health could not be determined."
    assert result.evidence == "insufficient evidence"


def test_empty_health_results_are_unknown() -> None:
    assert summarize_health([]) is RuntimeHealthState.UNKNOWN


def test_unknown_takes_precedence_over_degraded_and_healthy() -> None:
    results = [
        healthy(RuntimeComponent.SERVER),
        degraded(
            RuntimeComponent.LIVE_MODEL,
            "Model is slower.",
            "latency measurement",
        ),
        unknown(RuntimeComponent.API),
    ]

    assert summarize_health(results) is RuntimeHealthState.UNKNOWN


def test_offline_takes_precedence_over_unknown_and_degraded() -> None:
    results = [
        degraded(
            RuntimeComponent.FRONTEND,
            "Frontend performance is degraded.",
            "performance measurement",
        ),
        unknown(RuntimeComponent.API),
        offline(
            RuntimeComponent.NETWORK,
            "Network is unavailable.",
            "connectivity check failed",
        ),
    ]

    assert summarize_health(results) is RuntimeHealthState.OFFLINE


def test_unavailable_takes_precedence_over_degraded_and_healthy() -> None:
    results = [
        healthy(RuntimeComponent.SERVER),
        degraded(
            RuntimeComponent.AVATAR,
            "Avatar rendering is degraded.",
            "render timing measurement",
        ),
        unavailable(
            RuntimeComponent.VOICE,
            "Voice provider is unavailable.",
            "provider health check",
        ),
    ]

    assert summarize_health(results) is RuntimeHealthState.UNAVAILABLE


def test_degraded_takes_precedence_over_healthy() -> None:
    results = [
        healthy(RuntimeComponent.SERVER),
        healthy(RuntimeComponent.NETWORK),
        degraded(
            RuntimeComponent.DEVICE,
            "Device performance is degraded.",
            "runtime performance measurement",
        ),
    ]

    assert summarize_health(results) is RuntimeHealthState.DEGRADED


def test_all_healthy_results_are_healthy() -> None:
    results = [
        healthy(RuntimeComponent.SERVER),
        healthy(RuntimeComponent.NETWORK),
        healthy(RuntimeComponent.API),
        healthy(RuntimeComponent.FRONTEND),
        healthy(RuntimeComponent.LIVE_MODEL),
        healthy(RuntimeComponent.VOICE),
        healthy(RuntimeComponent.AVATAR),
        healthy(RuntimeComponent.DEVICE),
    ]

    assert summarize_health(results) is RuntimeHealthState.HEALTHY