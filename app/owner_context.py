from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import Enum
from typing import Generic, TypeVar


T = TypeVar("T")


class ProfileProvenance(str, Enum):
    VERIFIED = "VERIFIED"
    USER_PROVIDED = "USER_PROVIDED"
    SYSTEM_DERIVED = "SYSTEM_DERIVED"
    UNVERIFIED = "UNVERIFIED"
    CONFLICTED = "CONFLICTED"
    UNKNOWN = "UNKNOWN"


class OwnerProfileField(str, Enum):
    DISPLAY_NAME = "DISPLAY_NAME"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    EDUCATION = "EDUCATION"
    GRADUATION_YEAR = "GRADUATION_YEAR"
    CAREER_CONTEXT = "CAREER_CONTEXT"
    NATIONALITY = "NATIONALITY"


class LeapDayPolicy(str, Enum):
    """
    Calendar convention for people born on February 29
    when the current year is not a leap year.
    """

    FEBRUARY_28 = "FEBRUARY_28"
    MARCH_1 = "MARCH_1"


@dataclass(frozen=True)
class ProfileValue(Generic[T]):
    """
    A profile value together with its provenance.

    Provenance is informational metadata. It is never an
    authentication or authorization mechanism.
    """

    value: T
    provenance: ProfileProvenance

    def __post_init__(self) -> None:
        if self.provenance is None:
            raise ValueError("profile provenance is required")

        if not isinstance(self.provenance, ProfileProvenance):
            raise TypeError(
                "provenance must be a ProfileProvenance"
            )


@dataclass(frozen=True)
class OwnerProfile:
    """
    Canonical owner profile.

    Security invariants:

    1. Profile knowledge is never authentication.
    2. Profile knowledge is never authorization.
    3. Age is never stored as canonical identity data.
    4. Age is derived from date_of_birth and a trusted date.
    5. Identity-critical fields must not be changed by model output.
    """

    display_name: ProfileValue[str]
    date_of_birth: ProfileValue[date]
    education: ProfileValue[str]
    graduation_year: ProfileValue[int]
    career_context: ProfileValue[str]
    nationality: ProfileValue[str]

    def __post_init__(self) -> None:
        if not isinstance(self.display_name, ProfileValue):
            raise TypeError("display_name must be a ProfileValue")

        if not isinstance(self.date_of_birth, ProfileValue):
            raise TypeError("date_of_birth must be a ProfileValue")

        if not isinstance(self.education, ProfileValue):
            raise TypeError("education must be a ProfileValue")

        if not isinstance(self.graduation_year, ProfileValue):
            raise TypeError(
                "graduation_year must be a ProfileValue"
            )

        if not isinstance(self.career_context, ProfileValue):
            raise TypeError(
                "career_context must be a ProfileValue"
            )

        if not isinstance(self.nationality, ProfileValue):
            raise TypeError(
                "nationality must be a ProfileValue"
            )

        if not isinstance(self.display_name.value, str):
            raise TypeError("display_name must contain a string")

        if not self.display_name.value.strip():
            raise ValueError("display_name cannot be empty")

        if not isinstance(self.education.value, str):
            raise TypeError("education must contain a string")

        if not self.education.value.strip():
            raise ValueError("education cannot be empty")

        if not isinstance(self.career_context.value, str):
            raise TypeError(
                "career_context must contain a string"
            )

        if not self.career_context.value.strip():
            raise ValueError("career_context cannot be empty")

        if not isinstance(self.nationality.value, str):
            raise TypeError("nationality must contain a string")

        if not self.nationality.value.strip():
            raise ValueError("nationality cannot be empty")

        if not isinstance(self.date_of_birth.value, date):
            raise TypeError(
                "date_of_birth must be a datetime.date"
            )

        if type(self.graduation_year.value) is not int:
            raise TypeError(
                "graduation_year must contain an integer"
            )

        if self.graduation_year.value < self.date_of_birth.value.year:
            raise ValueError(
                "graduation_year cannot be earlier than birth year"
            )

        if not 1 <= self.graduation_year.value <= 9999:
            raise ValueError(
                "graduation_year is outside supported range"
            )


@dataclass(frozen=True)
class OwnerAge:
    """
    Deterministically derived age.

    This value must not be persisted as the canonical owner age.
    """

    years: int
    as_of: date

    def __post_init__(self) -> None:
        if type(self.years) is not int:
            raise TypeError("age years must be an integer")

        if self.years < 0:
            raise ValueError("age cannot be negative")

        if not isinstance(self.as_of, date):
            raise TypeError("as_of must be a datetime.date")


@dataclass(frozen=True)
class BirthdayInfo:
    """
    Information about the owner's next birthday.
    """

    next_birthday: date
    age_turning: int
    days_until: int

    def __post_init__(self) -> None:
        if not isinstance(self.next_birthday, date):
            raise TypeError(
                "next_birthday must be a datetime.date"
            )

        if type(self.age_turning) is not int:
            raise TypeError(
                "birthday age must be an integer"
            )

        if self.age_turning < 0:
            raise ValueError("birthday age cannot be negative")

        if type(self.days_until) is not int:
            raise TypeError(
                "days_until must be an integer"
            )

        if self.days_until < 0:
            raise ValueError("days_until cannot be negative")


def _validate_temporal_inputs(
    date_of_birth: date,
    as_of: date,
) -> None:
    if not isinstance(date_of_birth, date):
        raise TypeError("date_of_birth must be a datetime.date")

    if not isinstance(as_of, date):
        raise TypeError("as_of must be a datetime.date")

    if as_of < date_of_birth:
        raise ValueError(
            "as_of date cannot be earlier than date_of_birth"
        )


def _birthday_for_year(
    date_of_birth: date,
    year: int,
    leap_day_policy: LeapDayPolicy,
) -> date:
    """
    Resolve the birthday date for a particular calendar year.

    February 29 requires an explicit policy in non-leap years.
    """

    if not isinstance(leap_day_policy, LeapDayPolicy):
        raise TypeError(
            "leap_day_policy must be a LeapDayPolicy"
        )

    if date_of_birth.month == 2 and date_of_birth.day == 29:
        if year % 4 == 0 and (
            year % 100 != 0 or year % 400 == 0
        ):
            return date(year, 2, 29)

        if leap_day_policy is LeapDayPolicy.FEBRUARY_28:
            return date(year, 2, 28)

        if leap_day_policy is LeapDayPolicy.MARCH_1:
            return date(year, 3, 1)

        raise ValueError(
            "unsupported leap-day birthday policy"
        )

    return date(
        year,
        date_of_birth.month,
        date_of_birth.day,
    )


def calculate_age(
    date_of_birth: date,
    as_of: date,
    leap_day_policy: LeapDayPolicy = LeapDayPolicy.FEBRUARY_28,
) -> OwnerAge:
    """
    Calculate completed calendar years at a supplied date.

    The function never reads the machine clock.

    The caller is responsible for supplying an authoritative
    date from the trusted temporal subsystem.
    """

    _validate_temporal_inputs(
        date_of_birth=date_of_birth,
        as_of=as_of,
    )

    birthday_this_year = _birthday_for_year(
        date_of_birth=date_of_birth,
        year=as_of.year,
        leap_day_policy=leap_day_policy,
    )

    years = as_of.year - date_of_birth.year

    if as_of < birthday_this_year:
        years -= 1

    return OwnerAge(
        years=years,
        as_of=as_of,
    )


def next_birthday(
    date_of_birth: date,
    as_of: date,
    leap_day_policy: LeapDayPolicy = LeapDayPolicy.FEBRUARY_28,
) -> BirthdayInfo:
    """
    Calculate the next birthday relative to a supplied date.

    No system clock is consulted.
    """

    _validate_temporal_inputs(
        date_of_birth=date_of_birth,
        as_of=as_of,
    )

    birthday_this_year = _birthday_for_year(
        date_of_birth=date_of_birth,
        year=as_of.year,
        leap_day_policy=leap_day_policy,
    )

    if birthday_this_year >= as_of:
        candidate = birthday_this_year
    else:
        candidate = _birthday_for_year(
            date_of_birth=date_of_birth,
            year=as_of.year + 1,
            leap_day_policy=leap_day_policy,
        )

    current_age = calculate_age(
        date_of_birth=date_of_birth,
        as_of=as_of,
        leap_day_policy=leap_day_policy,
    )

    if candidate == as_of:
        age_turning = current_age.years
    else:
        age_turning = current_age.years + 1

    return BirthdayInfo(
        next_birthday=candidate,
        age_turning=age_turning,
        days_until=(candidate - as_of).days,
    )


def age_on_date(
    date_of_birth: date,
    target_date: date,
    leap_day_policy: LeapDayPolicy = LeapDayPolicy.FEBRUARY_28,
) -> int:
    """
    Return completed age on an arbitrary calendar date.
    """

    return calculate_age(
        date_of_birth=date_of_birth,
        as_of=target_date,
        leap_day_policy=leap_day_policy,
    ).years


def days_until_birthday(
    date_of_birth: date,
    as_of: date,
    leap_day_policy: LeapDayPolicy = LeapDayPolicy.FEBRUARY_28,
) -> int:
    """
    Return calendar days until the next birthday.
    """

    return next_birthday(
        date_of_birth=date_of_birth,
        as_of=as_of,
        leap_day_policy=leap_day_policy,
    ).days_until


def create_canonical_owner_profile() -> OwnerProfile:
    """
    Create the current canonical owner profile baseline.

    This function establishes profile data only.

    It does NOT:
    - authenticate a person
    - authorize an operation
    - create a session
    - grant privileges
    - expose secrets
    - determine current time
    - determine current location
    """

    return OwnerProfile(
        display_name=ProfileValue(
            value="Chetan",
            provenance=ProfileProvenance.USER_PROVIDED,
        ),
        date_of_birth=ProfileValue(
            value=date(2006, 3, 4),
            provenance=ProfileProvenance.USER_PROVIDED,
        ),
        education=ProfileValue(
            value="BBA",
            provenance=ProfileProvenance.USER_PROVIDED,
        ),
        graduation_year=ProfileValue(
            value=2026,
            provenance=ProfileProvenance.USER_PROVIDED,
        ),
        career_context=ProfileValue(
            value="Aspiring Business Analyst",
            provenance=ProfileProvenance.USER_PROVIDED,
        ),
        nationality=ProfileValue(
            value="Indian",
            provenance=ProfileProvenance.USER_PROVIDED,
        ),
    )