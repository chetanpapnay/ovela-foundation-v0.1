from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator


class EvidenceStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    EXTRACTED = "EXTRACTED"
    USER_CONFIRMED = "USER_CONFIRMED"
    SOURCE_VERIFIED = "SOURCE_VERIFIED"
    CROSS_VERIFIED = "CROSS_VERIFIED"
    CONFLICTED = "CONFLICTED"
    STALE = "STALE"
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"


class EventType(str, Enum):
    INCOME = "INCOME"
    EXPENSE = "EXPENSE"
    TRANSFER = "TRANSFER"
    REFUND = "REFUND"
    LOAN_PROCEED = "LOAN_PROCEED"
    LOAN_PAYMENT = "LOAN_PAYMENT"
    ADJUSTMENT = "ADJUSTMENT"


class FinancialEvent(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)

    account_id: str = Field(
        min_length=1,
        max_length=128,
    )

    source_id: str = Field(
        min_length=1,
        max_length=128,
    )

    source_event_id: str = Field(
        min_length=1,
        max_length=256,
    )

    event_type: EventType

    amount: Decimal

    currency: str = Field(
        min_length=3,
        max_length=3,
        pattern=r"^[A-Za-z]{3}$",
    )

    direction: str = Field(
        pattern=r"^(CREDIT|DEBIT)$",
    )

    event_date: datetime

    recorded_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )

    evidence_status: EvidenceStatus = EvidenceStatus.UNVERIFIED

    parent_event_id: UUID | None = None

    note: str | None = Field(
        default=None,
        max_length=1000,
    )

    @field_validator("account_id", "source_id", "source_event_id")
    @classmethod
    def validate_nonblank_identifier(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("identifier must not be blank")

        return value

    @field_validator("amount")
    @classmethod
    def validate_amount(cls, value: Decimal) -> Decimal:
        if not value.is_finite():
            raise ValueError("amount must be finite")

        if value <= 0:
            raise ValueError(
                "amount must be strictly positive"
            )

        return value

    @field_validator("currency")
    @classmethod
    def normalize_currency(cls, value: str) -> str:
        return value.upper()


class ActionRequest(BaseModel):
    """
    Exact intent for a requested action.

    Security-sensitive fields are part of the action identity.

    The action_id is immutable after creation because it is the
    transaction identity used by the execution boundary and ledger.

    Assignment validation is enabled so fields cannot silently change
    to values that violate their declared types or validators.

    Strict booleans are used for security-sensitive confirmation and
    destination-verification fields so values such as "yes", "true",
    "1", or 1 cannot be silently coerced into True.

    model_copy() is additionally restricted so the frozen action_id
    cannot be replaced through Pydantic's unvalidated update mechanism.
    """

    model_config = ConfigDict(
        validate_assignment=True,
    )

    action_id: UUID = Field(
        default_factory=uuid4,
        frozen=True,
    )

    session_id: str = Field(
        min_length=1,
        max_length=128,
    )

    action_type: str = Field(
        min_length=1,
        max_length=64,
    )

    authorization_state: str = Field(
        pattern=r"^(UNVERIFIED|AUTHENTICATED|STEP_UP_VERIFIED)$",
    )

    amount: Decimal | None = None

    currency: str | None = Field(
        default=None,
        min_length=3,
        max_length=3,
        pattern=r"^[A-Za-z]{3}$",
    )

    destination_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=256,
    )

    user_confirmation: StrictBool = False

    confirmation_action_id: UUID | None = None

    destination_verified: StrictBool = False

    @field_validator("session_id", "action_type", "destination_id")
    @classmethod
    def validate_nonblank_text(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        if not value.strip():
            raise ValueError("value must not be blank")

        return value

    @field_validator("amount")
    @classmethod
    def validate_amount(
        cls,
        value: Decimal | None,
    ) -> Decimal | None:
        if value is None:
            return None

        if not value.is_finite():
            raise ValueError("amount must be finite")

        if value < 0:
            raise ValueError(
                "amount must be non-negative"
            )

        return value

    @field_validator("currency")
    @classmethod
    def normalize_currency(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        return value.upper()

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> "ActionRequest":
        """
        Copy the request while preserving immutable transaction identity.

        Pydantic's default model_copy(update=...) does not validate update
        values and can bypass frozen-field assignment protection.

        action_id is the transaction identity and therefore cannot be
        supplied through the update mechanism at all.
        """

        if update is not None and "action_id" in update:
            raise TypeError(
                "action_id cannot be changed through model_copy()"
            )

        return super().model_copy(
            update=update,
            deep=deep,
        )