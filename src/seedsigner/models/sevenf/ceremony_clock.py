"""
    Operator-confirmed date and time for the 7F certificate flows (Root
    self-certification, Deputy cross-certification), which stamp "now" into
    the certificate's validity window.

    The production image has no RTC, no NTP and no boot-time date (found
    2026-10-07; only the dev image's S30devdata/S35network set one), so an
    air-gapped unit boots believing it is 1970. A Root self-cert stamped then
    is valid 1970-1990 and the node's count_deputy_quorum silently skips it;
    a Deputy cross-cert is refused or, with a clock ahead, not yet valid.

    Decision (Jorge, 2026-10-07): prompt for the date and time, as friendly
    as possible. The confirmed value lives in memory only (nothing is stored
    on the device) and advances with time.monotonic(), so it is asked once
    per boot. The system clock itself is never changed.
"""
import calendar
from dataclasses import dataclass, replace
from datetime import datetime, timezone

# Never accept a date before this, even without a build timestamp.
CLOCK_FLOOR_FALLBACK = int(datetime(2026, 10, 7, tzinfo=timezone.utc).timestamp())
MAX_YEAR = 2099
# A date this far past the floor is almost certainly a typo (wrong year).
MAX_YEARS_PAST_FLOOR = 5


class ClockEntryError(ValueError):
    """ The entered date/time can't be used. """


@dataclass(frozen=True)
class DateTimeFields:
    """ A UTC date and time to the minute, edited one field at a time. """
    year: int
    month: int
    day: int
    hour: int
    minute: int

    FIELDS = ("year", "month", "day", "hour", "minute")

    @classmethod
    def from_timestamp(cls, timestamp: int) -> "DateTimeFields":
        d = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return cls(d.year, d.month, d.day, d.hour, d.minute)

    def to_timestamp(self) -> int:
        return int(datetime(self.year, self.month, self.day, self.hour, self.minute, tzinfo=timezone.utc).timestamp())

    def describe(self) -> str:
        """ e.g. "Wednesday 7 October 2026, 21:30 UTC" -- the weekday is a
            quick check that the date is the one the operator meant. """
        d = datetime(self.year, self.month, self.day, self.hour, self.minute, tzinfo=timezone.utc)
        return f"{d:%A} {d.day} {d:%B %Y}, {d:%H:%M} UTC"

    def adjusted(self, field_index: int, delta: int) -> "DateTimeFields":
        """ A copy with one field moved by `delta`. Month, day, hour and minute
            wrap within their own range without carrying into the next field
            (each field is set independently); the year clamps to 1970-2099.
            The day is clamped to the resulting month's length. """
        field = self.FIELDS[field_index]
        if field == "year":
            out = replace(self, year=min(max(self.year + delta, 1970), MAX_YEAR))
        elif field == "month":
            out = replace(self, month=(self.month - 1 + delta) % 12 + 1)
        elif field == "day":
            days = calendar.monthrange(self.year, self.month)[1]
            out = replace(self, day=(self.day - 1 + delta) % days + 1)
        elif field == "hour":
            out = replace(self, hour=(self.hour + delta) % 24)
        else:
            out = replace(self, minute=(self.minute + delta) % 60)
        days = calendar.monthrange(out.year, out.month)[1]
        return replace(out, day=min(out.day, days))


@dataclass(frozen=True)
class ConfirmedClock:
    """ The operator-confirmed UTC time, anchored to the monotonic counter
        read when it was confirmed. """
    utc: int
    monotonic: float

    def now(self, monotonic_now: float) -> int:
        return self.utc + int(monotonic_now - self.monotonic)


def floor_timestamp(version_timestamp: datetime | None) -> int:
    """ The earliest acceptable date: this firmware's build/commit time
        (Version.get_version_timestamp(), naive values taken as UTC), or the
        fallback if that is missing or older. """
    if version_timestamp is None:
        return CLOCK_FLOOR_FALLBACK
    if version_timestamp.tzinfo is None:
        version_timestamp = version_timestamp.replace(tzinfo=timezone.utc)
    return max(CLOCK_FLOOR_FALLBACK, int(version_timestamp.timestamp()))


def initial_fields(system_now: int, floor: int) -> DateTimeFields:
    """ What the editor starts on: the system clock if it is plausible (e.g.
        the networked dev unit), otherwise the floor, so the operator usually
        changes only the day and time. """
    return DateTimeFields.from_timestamp(system_now if system_now >= floor else floor)


def check_entry(timestamp: int, floor: int) -> None:
    """ Refuse a date before this firmware's build, or more than
        MAX_YEARS_PAST_FLOOR years after it. """
    if timestamp < floor:
        raise ClockEntryError(
            f"That is before this firmware was built ({DateTimeFields.from_timestamp(floor).describe()}).")
    f = DateTimeFields.from_timestamp(floor)
    ceiling = DateTimeFields(min(f.year + MAX_YEARS_PAST_FLOOR, MAX_YEAR), f.month, min(f.day, 28), f.hour, f.minute)
    if timestamp > ceiling.to_timestamp():
        raise ClockEntryError(
            f"That is more than {MAX_YEARS_PAST_FLOOR} years after this firmware was built. Check the year.")
