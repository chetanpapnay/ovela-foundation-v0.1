from __future__ import annotations

from datetime import date

import pytest

from app.owner_context import (
    BirthdayInfo,
    LeapDayPolicy,
    OwnerAge,
    OwnerProfile,
    ProfileProvenance,
    ProfileValue,
    age_on_date,
    calculate_age,
    create_canonical_owner_profile,
    days_until_birthday,
    next_birthday,
)


def test_canonical_owner_profile_contains_expected_owner_context() -> None:
    profile = create_canonical_owner_profile()

    assert profile.display_name.value == "Chetan"
    assert profile.display_name.provenance is ProfileProvenance.USER_PROVIDED

    assert profile.date_of_birth.value == date(2006, 3, 4)
    assert profile.date_of_birth.provenance is ProfileProvenance.USER_PROVIDED

    assert profile.education.value == "BBA"
    assert profile.graduation_year.value == 2026
    assert profile.career_context.value == "Aspiring Business Analyst"
    assert profile.nationality.value == "Indian"


def test_age_is_derived_deterministically_from_date_of_birth() -> None:
    date_of_birth = date(2006, 3, 4)

    assert calculate_age(
        date_of_birth,
        date(2026, 3, 3),
    ) == OwnerAge(
        years=19,
        as_of=date(2026, 3, 3),
    )

    assert calculate_age(
        date_of_birth,
        date(2026, 3, 4),
    ) == OwnerAge(
        years=20,
        as_of=date(2026, 3, 4),
    )

    assert calculate_age(
        date_of_birth,
        date(2026, 10, 6),
    ) == OwnerAge(
        years=20,
        as_of=date(2026, 10, 6),
    )

    assert calculate_age(
        date_of_birth,
        date(2027, 3, 4),
    ) == OwnerAge(
        years=21,
        as_of=date(2027, 3, 4),
    )


def test_age_on_date_matches_calculate_age() -> None:
    date_of_birth = date(2006, 3, 4)

    assert age_on_date(
        date_of_birth,
        date(2026, 10, 6),
    ) == 20

    assert age_on_date(
        date_of_birth,
        date(2027, 3, 4),
    ) == 21


def test_age_calculation_never_uses_machine_clock() -> None:
    date_of_birth = date(2006, 3, 4)

    first = calculate_age(
        date_of_birth,
        date(2026, 3, 4),
    )

    second = calculate_age(
        date_of_birth,
        date(2026, 3, 4),
    )

    assert first == second
    assert first.as_of == date(2026, 3, 4)
    assert first.years == 20


def test_future_as_of_date_is_rejected() -> None:
    with pytest.raises(ValueError, match="earlier than date_of_birth"):
        calculate_age(
            date(2006, 3, 4),
            date(2006, 3, 3),
        )


def test_invalid_temporal_types_fail_closed() -> None:
    with pytest.raises(TypeError, match="datetime.date"):
        calculate_age(
            "2006-03-04",  # type: ignore[arg-type]
            date(2026, 10, 6),
        )

    with pytest.raises(TypeError, match="datetime.date"):
        calculate_age(
            date(2006, 3, 4),
            "2026-10-06",  # type: ignore[arg-type]
        )


def test_next_birthday_before_birthday() -> None:
    result = next_birthday(
        date(2006, 3, 4),
        date(2026, 3, 3),
    )

    assert result == BirthdayInfo(
        next_birthday=date(2026, 3, 4),
        age_turning=20,
        days_until=1,
    )


def test_next_birthday_on_birthday() -> None:
    result = next_birthday(
        date(2006, 3, 4),
        date(2026, 3, 4),
    )

    assert result == BirthdayInfo(
        next_birthday=date(2026, 3, 4),
        age_turning=20,
        days_until=0,
    )


def test_next_birthday_after_birthday() -> None:
    result = next_birthday(
        date(2006, 3, 4),
        date(2026, 10, 6),
    )

    assert result.next_birthday == date(2027, 3, 4)
    assert result.age_turning == 21
    assert result.days_until == (
        date(2027, 3, 4) - date(2026, 10, 6)
    ).days


def test_days_until_birthday_matches_next_birthday() -> None:
    date_of_birth = date(2006, 3, 4)
    as_of = date(2026, 10, 6)

    result = next_birthday(
        date_of_birth,
        as_of,
    )

    assert days_until_birthday(
        date_of_birth,
        as_of,
    ) == result.days_until


def test_leap_day_february_28_policy_is_deterministic() -> None:
    date_of_birth = date(2004, 2, 29)

    result = next_birthday(
        date_of_birth,
        date(2025, 1, 1),
        LeapDayPolicy.FEBRUARY_28,
    )

    assert result.next_birthday == date(2025, 2, 28)
    assert result.age_turning == 21


def test_leap_day_march_1_policy_is_deterministic() -> None:
    date_of_birth = date(2004, 2, 29)

    result = next_birthday(
        date_of_birth,
        date(2025, 1, 1),
        LeapDayPolicy.MARCH_1,
    )

    assert result.next_birthday == date(2025, 3, 1)
    assert result.age_turning == 21


def test_leap_day_policy_changes_age_boundary_deterministically() -> None:
    date_of_birth = date(2004, 2, 29)

    february_policy = calculate_age(
        date_of_birth,
        date(2025, 2, 28),
        LeapDayPolicy.FEBRUARY_28,
    )

    march_policy = calculate_age(
        date_of_birth,
        date(2025, 2, 28),
        LeapDayPolicy.MARCH_1,
    )

    assert february_policy.years == 21
    assert march_policy.years == 20


def test_invalid_leap_day_policy_type_is_rejected() -> None:
    with pytest.raises(TypeError, match="LeapDayPolicy"):
        calculate_age(
            date(2004, 2, 29),
            date(2025, 2, 28),
            "FEBRUARY_28",  # type: ignore[arg-type]
        )


def test_profile_rejects_empty_identity_fields() -> None:
    base = create_canonical_owner_profile()

    with pytest.raises(ValueError, match="display_name"):
        OwnerProfile(
            display_name=ProfileValue(
                value="   ",
                provenance=ProfileProvenance.USER_PROVIDED,
            ),
            date_of_birth=base.date_of_birth,
            education=base.education,
            graduation_year=base.graduation_year,
            career_context=base.career_context,
            nationality=base.nationality,
        )

    with pytest.raises(ValueError, match="education"):
        OwnerProfile(
            display_name=base.display_name,
            date_of_birth=base.date_of_birth,
            education=ProfileValue(
                value="",
                provenance=ProfileProvenance.USER_PROVIDED,
            ),
            graduation_year=base.graduation_year,
            career_context=base.career_context,
            nationality=base.nationality,
        )


def test_profile_rejects_graduation_year_before_birth_year() -> None:
    with pytest.raises(
        ValueError,
        match="graduation_year cannot be earlier than birth year",
    ):
        OwnerProfile(
            display_name=ProfileValue(
                value="Test",
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
                value=1999,
                provenance=ProfileProvenance.USER_PROVIDED,
            ),
            career_context=ProfileValue(
                value="Business Analyst",
                provenance=ProfileProvenance.USER_PROVIDED,
            ),
            nationality=ProfileValue(
                value="Indian",
                provenance=ProfileProvenance.USER_PROVIDED,
            ),
        )


def test_profile_rejects_missing_provenance() -> None:
    with pytest.raises(ValueError, match="profile provenance is required"):
        ProfileValue(
            value="Chetan",
            provenance=None,  # type: ignore[arg-type]
        )


def test_profile_age_is_not_stored_as_a_mutable_field() -> None:
    profile = create_canonical_owner_profile()

    assert not hasattr(profile, "age")
    assert not hasattr(profile, "current_age")

    derived_age = calculate_age(
        profile.date_of_birth.value,
        date(2026, 10, 6),
    )

    assert derived_age.years == 20