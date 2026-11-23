"""When the dataset plays: the schedule questions the engine and runner ask.

A schedule numbers its periods (loops, or days) and says when each one starts. In period k, an
event at dataset time t is due at start(k) + (t - first), so the period's offset is
start(k) - first. Each period plays the dataset window once, at real speed.
"""

import math
import re
from datetime import datetime, timedelta


class Loop:
    """The dataset repeats back to back from the anchor: period k starts at anchor + k * length."""

    mode = "loop"

    def __init__(self, anchor, length):
        self.anchor = int(anchor)
        self.length = int(length)

    def period_of(self, wall):
        return math.floor((wall - self.anchor) / self.length)

    def start(self, k):
        return self.anchor + k * self.length

    def label(self, wall):
        return datetime.fromtimestamp(wall).astimezone().strftime("%Y-%m-%d %H:%M %Z")


class Daily:
    """The dataset plays once per local calendar day, starting at a fixed local clock time.

    Days are numbered from the anchor's local date. Each start is that date's clock time in the
    zone, so it stays at, say, 9:00 local across daylight saving changes (a 23 or 25 h gap). A start
    inside a daylight saving gap or overlap (02:00 to 03:00 in US zones) takes the first reading.
    """

    mode = "daily"

    def __init__(self, anchor, length, start="09:00", zone="America/New_York"):
        self.anchor = int(anchor)
        self.length = int(length)
        m = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", str(start).strip())
        if not m:
            raise ValueError(f"daily_start must be HH:MM, not {start!r}")
        self.hour, self.minute = int(m[1]), int(m[2])
        if self.length > 22 * 3600:
            raise ValueError("a daily schedule needs a window shorter than 22 hours")
        self.zone = _zone(zone)
        self.day0 = self._date(self.anchor)

    def _date(self, wall):
        return datetime.fromtimestamp(wall, self.zone).date()

    def _start_on(self, day):
        return int(datetime(day.year, day.month, day.day, self.hour, self.minute, tzinfo=self.zone).timestamp())

    def period_of(self, wall):
        day = self._date(wall)
        if wall < self._start_on(day):
            day -= timedelta(days=1)
        return (day - self.day0).days

    def start(self, k):
        return self._start_on(self.day0 + timedelta(days=k))

    def label(self, wall):
        moment = datetime.fromtimestamp(wall, self.zone)
        return (moment if self.zone else moment.astimezone()).strftime("%Y-%m-%d %H:%M %Z")


def _zone(name):
    """A zone name, or "local" for the indexer's own zone (None: naive datetimes are local)."""
    name = (name or "local").strip()
    if name.lower() == "local":
        return None
    from zoneinfo import ZoneInfo
    return ZoneInfo(name)


def build(replay, anchor, length):
    """The schedule [replay] asks for: schedule = loop (the default) or daily."""
    mode = (replay.get("schedule") or "loop").strip().lower()
    if mode == "loop":
        return Loop(anchor, length)
    if mode == "daily":
        return Daily(anchor, length, replay.get("daily_start") or "09:00",
                     replay.get("schedule_timezone") or "America/New_York")
    raise ValueError(f"[replay] schedule must be loop or daily, not {mode!r}")
