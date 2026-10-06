from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RuntimeHealthState(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"


class RuntimeComponent(str, Enum):
    SERVER = "SERVER"
    NETWORK = "NETWORK"
    API = "API"
    FRONTEND = "FRONTEND"
    LIVE_MODEL = "LIVE_MODEL"
    VOICE = "VOICE"
    AVATAR = "AVATAR"
    DEVICE = "DEVICE"


@dataclass(frozen=True)
class RuntimeHealth:
    component: RuntimeComponent
    state: RuntimeHealthState
    message: str
    evidence: str


def healthy(
    component: RuntimeComponent,
    message: str = "Component is operating normally.",
    evidence: str = "positive health signal",
) -> RuntimeHealth:
    return RuntimeHealth(
        component=component,
        state=RuntimeHealthState.HEALTHY,
        message=message,
        evidence=evidence,
    )


def degraded(
    component: RuntimeComponent,
    message: str,
    evidence: str,
) -> RuntimeHealth:
    return RuntimeHealth(
        component=component,
        state=RuntimeHealthState.DEGRADED,
        message=message,
        evidence=evidence,
    )


def offline(
    component: RuntimeComponent,
    message: str,
    evidence: str,
) -> RuntimeHealth:
    return RuntimeHealth(
        component=component,
        state=RuntimeHealthState.OFFLINE,
        message=message,
        evidence=evidence,
    )


def unavailable(
    component: RuntimeComponent,
    message: str,
    evidence: str,
) -> RuntimeHealth:
    return RuntimeHealth(
        component=component,
        state=RuntimeHealthState.UNAVAILABLE,
        message=message,
        evidence=evidence,
    )


def unknown(
    component: RuntimeComponent,
    message: str = "Health could not be determined.",
    evidence: str = "insufficient evidence",
) -> RuntimeHealth:
    return RuntimeHealth(
        component=component,
        state=RuntimeHealthState.UNKNOWN,
        message=message,
        evidence=evidence,
    )


def summarize_health(
    results: list[RuntimeHealth],
) -> RuntimeHealthState:
    """
    Produce one conservative overall runtime state.

    Security principle:
    uncertainty must never be converted into HEALTHY.
    """

    if not results:
        return RuntimeHealthState.UNKNOWN

    states = {result.state for result in results}

    if RuntimeHealthState.OFFLINE in states:
        return RuntimeHealthState.OFFLINE

    if RuntimeHealthState.UNAVAILABLE in states:
        return RuntimeHealthState.UNAVAILABLE

    if RuntimeHealthState.UNKNOWN in states:
        return RuntimeHealthState.UNKNOWN

    if RuntimeHealthState.DEGRADED in states:
        return RuntimeHealthState.DEGRADED

    return RuntimeHealthState.HEALTHY