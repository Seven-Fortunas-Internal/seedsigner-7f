"""
    Tests for models/sevenf/ceremony_clock.py -- operator-confirmed date/time
    for certificate flows. The production image has no RTC, no NTP and no
    boot-time date (found 2026-10-07): an air-gapped unit boots in 1970, and a
    Root self-cert stamped then is valid 1970-1990, which the node's
    count_deputy_quorum silently skips.
"""
from datetime import datetime, timezone

import pytest

from seedsigner.models.sevenf.ceremony_clock import (
    CLOCK_FLOOR_FALLBACK,
    ClockEntryError,
    ConfirmedClock,
    DateTimeFields,
    check_entry,
    floor_timestamp,
    initial_fields,
)


def ts(*args) -> int:
    return int(datetime(*args, tzinfo=timezone.utc).timestamp())


FLOOR = ts(2026, 10, 7, 0, 0)


def test_round_trips_a_timestamp_dropping_seconds():
    f = DateTimeFields.from_timestamp(ts(2026, 10, 7, 21, 30, 59))
    assert (f.year, f.month, f.day, f.hour, f.minute) == (2026, 10, 7, 21, 30)
    assert f.to_timestamp() == ts(2026, 10, 7, 21, 30)


def test_reads_back_with_weekday_in_utc():
    assert DateTimeFields(2026, 10, 7, 21, 30).describe() == "Wednesday 7 October 2026, 21:30 UTC"
    assert DateTimeFields(2027, 1, 2, 3, 4).describe() == "Saturday 2 January 2027, 03:04 UTC"


@pytest.mark.parametrize("start, field, delta, expected", [
    ((2026, 10, 7, 21, 30), "minute", +1, (2026, 10, 7, 21, 31)),
    ((2026, 10, 7, 21, 59), "minute", +1, (2026, 10, 7, 21, 0)),     # wraps, doesn't carry
    ((2026, 10, 7, 0, 0), "hour", -1, (2026, 10, 7, 23, 0)),
    ((2026, 12, 7, 0, 0), "month", +1, (2026, 1, 7, 0, 0)),
    ((2026, 10, 31, 0, 0), "day", +1, (2026, 10, 1, 0, 0)),
    ((2026, 10, 1, 0, 0), "day", -1, (2026, 10, 31, 0, 0)),
    ((2026, 3, 31, 0, 0), "month", -1, (2026, 2, 28, 0, 0)),         # day clamped to the month
    ((2028, 2, 29, 0, 0), "year", +1, (2029, 2, 28, 0, 0)),          # leap day clamped
    ((2026, 10, 7, 0, 0), "year", +1, (2027, 10, 7, 0, 0)),
    ((2099, 10, 7, 0, 0), "year", +1, (2099, 10, 7, 0, 0)),          # year clamps, no wrap
    ((2026, 10, 7, 0, 0), "year", -1, (2025, 10, 7, 0, 0)),          # the floor is checked at confirm, not here
])
def test_adjusting_one_field(start, field, delta, expected):
    f = DateTimeFields(*start)
    out = f.adjusted(DateTimeFields.FIELDS.index(field), delta)
    assert (out.year, out.month, out.day, out.hour, out.minute) == expected
    assert (f.year, f.month, f.day, f.hour, f.minute) == start  # immutable


def test_floor_is_the_later_of_the_build_date_and_the_fallback():
    assert floor_timestamp(None) == CLOCK_FLOOR_FALLBACK
    assert floor_timestamp(datetime(2020, 1, 1)) == CLOCK_FLOOR_FALLBACK
    assert floor_timestamp(datetime(2027, 3, 4, 5, 6)) == ts(2027, 3, 4, 5, 6)
    assert floor_timestamp(datetime(2027, 3, 4, 5, 6, tzinfo=timezone.utc)) == ts(2027, 3, 4, 5, 6)


def test_prefill_uses_a_plausible_system_clock_otherwise_the_floor():
    assert initial_fields(ts(2026, 11, 2, 8, 15, 42), FLOOR).to_timestamp() == ts(2026, 11, 2, 8, 15)
    assert initial_fields(0, FLOOR).to_timestamp() == FLOOR          # a fresh boot: 1970
    assert initial_fields(FLOOR - 60, FLOOR).to_timestamp() == FLOOR


def test_refuses_a_date_before_the_floor():
    check_entry(FLOOR, FLOOR)
    with pytest.raises(ClockEntryError, match="before"):
        check_entry(FLOOR - 60, FLOOR)


def test_refuses_a_date_more_than_five_years_past_the_floor():
    check_entry(ts(2031, 10, 6, 23, 59), FLOOR)
    with pytest.raises(ClockEntryError, match="years"):
        check_entry(ts(2031, 10, 8, 0, 0), FLOOR)


def test_confirmed_clock_advances_with_the_monotonic_counter():
    clock = ConfirmedClock(utc=FLOOR, monotonic=1000.0)
    assert clock.now(1000.0) == FLOOR
    assert clock.now(1090.7) == FLOOR + 90
