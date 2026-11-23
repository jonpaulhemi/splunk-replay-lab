"""Rewrite the timestamps written inside a raw event by a fixed number of seconds.

Only timestamps that fall inside the dataset's window (with a day's margin, for
time zones) are rewritten, so unrelated numbers and dates are left alone. Each
rewritten value keeps its original format: digits of fraction, AM/PM, zone
suffix, padding.

The BOTS datasets' in-text times are UTC. A time written without a zone is read by the indexer in
its own zone, so for sourcetypes whose _time comes from such text, the shifter can write
it in another zone (text_timezone): "local" for the indexer's, or a zone name.

For those feeds the event's first zoneless time is the one Splunk reads as _time, so it is
anchored to the event's own time. Some BOTS logs write that clock off by whole hours
(Windows event logs are often 12 h behind, with a wrong AM/PM); that offset is measured per
event and taken out, so the text shows the real time. A first time that is far from the
event's time (a stale date) is replaced by the event's time.
"""

import calendar
import re
from datetime import datetime, timedelta, timezone

MARGIN = 86400
# Times that carry a year are also moved when they are up to this long before the window
# (login times in `who`, install dates): with a year in them, they are unlikely to be anything else.
DATED_LOOKBACK = 400 * 86400
CLOCK_LIMIT = 14 * 3600  # larger gaps between the first time and the event's time are stale dates

_ISO = re.compile(
    r"(?<![\d])(?P<date>\d{4}-\d{2}-\d{2})(?P<sep>[T ])(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?P<frac>\.\d{1,9})?(?P<zone>Z|[+-]\d{2}:?\d{2})?(?![\d])"
)
# Minute precision ("2018-08-17 14:03" in Splunk_TA_nix's who).
_ISO_MIN = re.compile(r"(?<![\d])(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2})(?![:\d])")
_US = re.compile(
    r"(?<![\d])(?P<mo>\d{2})/(?P<d>\d{2})/(?P<y>\d{4}) (?P<h>\d{1,2}):(?P<mi>\d{2}):(?P<s>\d{2})"
    r"(?P<frac>\.\d{1,9})?(?: (?P<ampm>AM|PM))?(?![\d])"
)
_SYSLOG = re.compile(
    r"(?<![\w])(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (?P<d>[ \d]\d) "
    r"(?P<t>\d{2}:\d{2}:\d{2})(?![\d])"
)
# Weekday-led dates like "Mon Aug 20 13:00:01 2018" (osquery calendarTime, ctime), with an
# optional zone before the year as `date` prints it ("Mon Aug 20 14:59:14 UTC 2018").
_CTIME = re.compile(
    r"(?P<wd>Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
    r"(?P<d>[ \d]\d) (?P<t>\d{2}:\d{2}:\d{2})(?P<tz> [A-Z]{2,5})? (?P<y>\d{4})"
)
# Apache/S3 access logs: "20/Aug/2018:15:17:39 +0000".
_CLF = re.compile(
    r"(?<!\d)(?P<d>\d{2})/(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/(?P<y>\d{4}):"
    r"(?P<t>\d{2}:\d{2}:\d{2})(?![\d])"
)
# Mail headers (RFC 2822): "Mon, 20 Aug 2018 15:14:56 +0000", folded lines included, which
# appear as a literal backslash-r-backslash-n plus space inside JSON-escaped events.
_RFC2822 = re.compile(
    r"(?P<wd>Mon|Tue|Wed|Thu|Fri|Sat|Sun), (?P<d>\d{1,2})(?P<s1> |\\r\\n )(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"(?P<s2> |\\r\\n |)(?P<y>\d{4})(?P<s3> |\\r\\n )(?P<t>\d{2}:\d{2}:\d{2})"
)
# MySQL/RDS audit: "20180820 15:18:00".
_COMPACT = re.compile(r"(?<![\d])(?P<date>\d{8}) (?P<t>\d{2}:\d{2}:\d{2})(?![\d])")
# glog (osquery INFO): "I0820 15:17:55.951526" at a line start; no year.
_GLOG = re.compile(r"(?m)^(?P<lvl>[IWEF])(?P<md>\d{4}) (?P<t>\d{2}:\d{2}:\d{2})")
_EPOCH = re.compile(r"(?<![\d.])(?P<sec>1\d{9})(?P<rest>\d{3}|\.\d{1,6})?(?![\d])")
_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
_DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

FORMATS = ("iso", "us", "clf", "rfc2822", "compact", "glog", "syslog", "ctime", "epoch")


def _parse(text, fmt):
    try:
        return datetime.strptime(text, fmt)
    except ValueError:
        return None


def _us_hour(m):
    """The 24-hour hour of a US-format match, and whether its text uses a real 12-hour clock.

    The BOTS Windows logs write a 24-hour clock with an AM/PM suffix ("22:08:17 PM",
    "03:18:00 AM"). Only "01-11 PM" or "12 AM" mean a real 12-hour clock.
    """
    hour = int(m["h"])
    twelve = bool(m["ampm"]) and ((m["ampm"] == "PM" and 1 <= hour <= 11) or (m["ampm"] == "AM" and hour == 12))
    if twelve:
        hour = hour % 12 + (12 if m["ampm"] == "PM" else 0)
    return hour, twelve


def _zone(name):
    name = (name or "utc").strip()
    if name.lower() == "utc":
        return None
    if name.lower() == "local":
        return "local"
    from zoneinfo import ZoneInfo
    return ZoneInfo(name)


class Shifter:
    def __init__(self, first, last, formats=FORMATS, text_timezone="utc"):
        self.lo = first - MARGIN
        self.hi = last + MARGIN
        self.dated_lo = first - DATED_LOOKBACK
        self.year = datetime.fromtimestamp(first, timezone.utc).year
        self.formats = tuple(formats)
        self.zone = _zone(text_timezone)
        self._clock = 0
        self._anywhere = False

    def _wall(self, utc_naive):
        """A shifted UTC time as the indexer should read it, for text that carries no zone."""
        if self.zone is None:
            return utc_naive
        aware = (utc_naive - timedelta(seconds=self._clock)).replace(tzinfo=timezone.utc)
        local = aware.astimezone() if self.zone == "local" else aware.astimezone(self.zone)
        return local.replace(tzinfo=None)

    def _inside(self, naive, dated=True):
        if self._anywhere:
            return True
        epoch = calendar.timegm(naive.timetuple())
        return (self.dated_lo if dated else self.lo) <= epoch <= self.hi

    def shift(self, raw, seconds, t=None):
        self._clock = 0
        if self.zone is not None and t is not None:
            raw = self._anchor_first(raw, seconds, t)
        delta = timedelta(seconds=seconds)
        # ctime before syslog: a ctime date contains a syslog-looking date.
        for name in ("iso", "us", "clf", "rfc2822", "compact", "glog", "ctime", "syslog", "epoch"):
            if name in self.formats:
                raw = getattr(self, "_" + name)(raw, delta, seconds)
        return raw

    def _first_zoneless(self, raw):
        """The earliest zoneless time in raw: (start, end, format name, naive UTC value)."""
        found = []
        for name, pattern in (("iso", _ISO), ("us", _US), ("syslog", _SYSLOG), ("compact", _COMPACT),
                              ("glog", _GLOG), ("ctime", _CTIME)):
            if name not in self.formats:
                continue
            for m in pattern.finditer(raw):
                if (name == "iso" and m["zone"]) or (name == "ctime" and m["tz"]):
                    continue
                naive = self._naive(name, m)
                if naive is not None:
                    found.append((m.start(), -m.end(), name, naive))
                    break
        if not found:
            return None
        start, end, name, naive = min(found)
        return start, -end, name, naive

    def _naive(self, name, m):
        if name == "iso":
            return _parse(f"{m['date']} {m['time']}", "%Y-%m-%d %H:%M:%S")
        if name == "us":
            hour, _ = _us_hour(m)
            try:
                return datetime(int(m["y"]), int(m["mo"]), int(m["d"]), hour, int(m["mi"]), int(m["s"]))
            except ValueError:
                return None
        if name == "syslog":
            return _parse(f"{self.year} {m['mon']} {m['d'].strip()} {m['t']}", "%Y %b %d %H:%M:%S")
        if name == "compact":
            return _parse(f"{m['date']} {m['t']}", "%Y%m%d %H:%M:%S")
        if name == "glog":
            return _parse(f"{self.year}{m['md']} {m['t']}", "%Y%m%d %H:%M:%S")
        return _parse(f"{m['y']} {m['mon']} {m['d'].strip()} {m['t']}", "%Y %b %d %H:%M:%S")

    def _anchor_first(self, raw, seconds, t):
        first = self._first_zoneless(raw)
        if first is None:
            return raw
        start, end, name, naive = first
        gap = calendar.timegm(naive.timetuple()) - t
        if abs(gap) <= CLOCK_LIMIT:
            self._clock = round(gap / 900) * 900  # the log's clock offset, in quarter hours
            return raw
        # A stale date: write the event's own time there, since Splunk takes _time from it.
        moved = int(t + seconds) - calendar.timegm(naive.timetuple())
        self._anywhere = True
        try:
            text = getattr(self, "_" + name)(raw[start:end], timedelta(seconds=moved), moved)
        finally:
            self._anywhere = False
        return raw[:start] + text + raw[end:]

    def _iso(self, raw, delta, seconds):
        def sub(m):
            naive = _parse(f"{m['date']} {m['time']}", "%Y-%m-%d %H:%M:%S")
            if naive is None or not self._inside(naive):
                return m.group(0)
            new = naive + delta if m["zone"] else self._wall(naive + delta)
            return (new.strftime("%Y-%m-%d") + m["sep"] + new.strftime("%H:%M:%S")
                    + (m["frac"] or "") + (m["zone"] or ""))
        raw = _ISO.sub(sub, raw)

        def sub_min(m):
            naive = _parse(f"{m['date']} {m['time']}", "%Y-%m-%d %H:%M")
            if naive is None or not self._inside(naive):
                return m.group(0)
            new = self._wall(naive + delta)
            return new.strftime("%Y-%m-%d") + " " + new.strftime("%H:%M")
        return _ISO_MIN.sub(sub_min, raw)

    def _us(self, raw, delta, seconds):
        def sub(m):
            hour, twelve = _us_hour(m)
            try:
                naive = datetime(int(m["y"]), int(m["mo"]), int(m["d"]), hour, int(m["mi"]), int(m["s"]))
            except ValueError:
                return m.group(0)
            if not self._inside(naive):
                return m.group(0)
            new = self._wall(naive + delta)
            if m["ampm"] and (twelve or self.zone is not None):
                h12 = new.hour % 12 or 12
                hour_text = f"{h12:0{len(m['h'])}d}"
                tail = " " + ("PM" if new.hour >= 12 else "AM")
            elif m["ampm"]:
                hour_text = f"{new.hour:0{len(m['h'])}d}"
                tail = " " + ("PM" if new.hour >= 12 else "AM")
            else:
                hour_text = f"{new.hour:0{len(m['h'])}d}"
                tail = ""
            return (f"{new.month:02d}/{new.day:02d}/{new.year:04d} {hour_text}:{new.minute:02d}:{new.second:02d}"
                    + (m["frac"] or "") + tail)
        return _US.sub(sub, raw)

    def _syslog(self, raw, delta, seconds):
        def sub(m):
            naive = _parse(f"{self.year} {m['mon']} {m['d'].strip()} {m['t']}", "%Y %b %d %H:%M:%S")
            if naive is None or not self._inside(naive, dated=False):
                return m.group(0)
            new = self._wall(naive + delta)
            day = f"{new.day:2d}" if m["d"][0] == " " else f"{new.day:02d}"
            return f"{_MONTHS[new.month - 1]} {day} {new.strftime('%H:%M:%S')}"
        return _SYSLOG.sub(sub, raw)

    def _ctime(self, raw, delta, seconds):
        def sub(m):
            naive = _parse(f"{m['y']} {m['mon']} {m['d'].strip()} {m['t']}", "%Y %b %d %H:%M:%S")
            if naive is None or not self._inside(naive):
                return m.group(0)
            new = naive + delta if m["tz"] else self._wall(naive + delta)
            day = f"{new.day:2d}" if m["d"][0] == " " else f"{new.day:02d}"
            return (f"{_DAYS[new.weekday()]} {_MONTHS[new.month - 1]} {day} {new.strftime('%H:%M:%S')}"
                    f"{m['tz'] or ''} {new.year}")
        return _CTIME.sub(sub, raw)

    def _clf(self, raw, delta, seconds):
        def sub(m):
            naive = _parse(f"{m['y']} {m['mon']} {m['d']} {m['t']}", "%Y %b %d %H:%M:%S")
            if naive is None or not self._inside(naive):
                return m.group(0)
            new = naive + delta
            return f"{new.day:02d}/{_MONTHS[new.month - 1]}/{new.year}:{new.strftime('%H:%M:%S')}"
        return _CLF.sub(sub, raw)

    def _rfc2822(self, raw, delta, seconds):
        def sub(m):
            naive = _parse(f"{m['y']} {m['mon']} {m['d']} {m['t']}", "%Y %b %d %H:%M:%S")
            if naive is None or not self._inside(naive):
                return m.group(0)
            new = naive + delta
            day = f"{new.day:02d}" if len(m["d"]) == 2 else str(new.day)
            return (f"{_DAYS[new.weekday()]}, {day}{m['s1']}{_MONTHS[new.month - 1]}{m['s2']}{new.year}"
                    f"{m['s3']}{new.strftime('%H:%M:%S')}")
        return _RFC2822.sub(sub, raw)

    def _compact(self, raw, delta, seconds):
        def sub(m):
            naive = _parse(f"{m['date']} {m['t']}", "%Y%m%d %H:%M:%S")
            if naive is None or not self._inside(naive):
                return m.group(0)
            return self._wall(naive + delta).strftime("%Y%m%d %H:%M:%S")
        return _COMPACT.sub(sub, raw)

    def _glog(self, raw, delta, seconds):
        def sub(m):
            naive = _parse(f"{self.year}{m['md']} {m['t']}", "%Y%m%d %H:%M:%S")
            if naive is None or not self._inside(naive, dated=False):
                return m.group(0)
            new = self._wall(naive + delta)
            return f"{m['lvl']}{new.strftime('%m%d %H:%M:%S')}"
        return _GLOG.sub(sub, raw)

    def _epoch(self, raw, delta, seconds):
        whole = int(seconds)

        def sub(m):
            sec = int(m["sec"])
            if not self.lo <= sec <= self.hi:
                return m.group(0)
            return str(sec + whole) + (m["rest"] or "")
        return _EPOCH.sub(sub, raw)
