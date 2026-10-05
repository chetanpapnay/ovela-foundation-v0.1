from __future__ import annotations

from threading import RLock
from uuid import UUID

from .models import FinancialEvent


class LedgerConflict(Exception):
    """Raised when an event violates ledger append-only invariants."""


class AppendOnlyLedger:
    """
    Thread-safe append-only ledger.

    Events may be appended exactly once according to their
    (source_id, source_event_id) identity.

    The ledger never exposes its internally stored model instances
    directly, preventing callers from mutating stored state after
    insertion.

    Security boundary:
    External FinancialEvent subclasses are treated as untrusted input.

    The ledger canonicalizes every incoming event into the exact
    FinancialEvent base type using trusted base-class serialization
    and validation. This prevents malicious subclasses from overriding
    model_copy() or model_dump() and changing ledger data during
    insertion or retrieval.
    """

    @staticmethod
    def _canonicalize_event(event: FinancialEvent) -> FinancialEvent:
        """
        Convert an incoming event into an exact FinancialEvent instance.

        Security rationale:

        Do NOT call:
            event.model_copy()
            event.model_dump()

        directly, because FinancialEvent may have been subclassed by
        caller-controlled code that overrides those methods.

        Calling the trusted FinancialEvent implementation directly
        bypasses subclass overrides.

        The serialized data is then validated again through the exact
        FinancialEvent model so the ledger stores only canonical,
        validated base-model instances.
        """

        event_data = FinancialEvent.model_dump(event)

        return FinancialEvent.model_validate(event_data)

    @classmethod
    def _copy_event(cls, event: FinancialEvent) -> FinancialEvent:
        """
        Return an independent exact FinancialEvent copy.

        The event is canonicalized first so no caller-controlled
        subclass implementation can alter the returned data.
        """

        canonical_event = cls._canonicalize_event(event)

        return FinancialEvent.model_copy(
            canonical_event,
            deep=True,
        )

    def __init__(self) -> None:
        self._events: list[FinancialEvent] = []
        self._source_keys: set[tuple[str, str]] = set()
        self._lock = RLock()

    def append(self, event: FinancialEvent) -> FinancialEvent:
        """
        Append an event exactly once.

        Duplicate or replayed source events are rejected atomically
        under the ledger lock.

        The incoming event is canonicalized before it becomes part
        of the ledger's internal state.
        """

        if not isinstance(event, FinancialEvent):
            raise TypeError("event must be a FinancialEvent")

        with self._lock:
            stored_event = self._canonicalize_event(event)

            key = (
                stored_event.source_id,
                stored_event.source_event_id,
            )

            if key in self._source_keys:
                raise LedgerConflict(
                    "duplicate or replayed source event"
                )

            self._source_keys.add(key)
            self._events.append(stored_event)

            return self._copy_event(stored_event)

    def all(self) -> list[FinancialEvent]:
        """
        Return an independent snapshot of all ledger events.

        Every returned object is an exact FinancialEvent base-model
        instance and cannot mutate internal ledger state.
        """

        with self._lock:
            return [
                self._copy_event(event)
                for event in self._events
            ]

    def get(self, event_id: UUID) -> FinancialEvent | None:
        """
        Return an independent copy of the requested event.

        Returns None when the event does not exist.
        """

        if not isinstance(event_id, UUID):
            raise TypeError("event_id must be a UUID")

        with self._lock:
            for event in self._events:
                if event.event_id == event_id:
                    return self._copy_event(event)

        return None