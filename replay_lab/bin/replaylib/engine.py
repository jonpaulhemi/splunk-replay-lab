"""Real-time replay: which dataset events are due in a wall-clock window, and how they look now.

A schedule (see schedule.py) says when each period starts. In period k, an event
originally at time t is due at start(k) + (t - F), where F is the dataset's first
second, so its offset is start(k) - F. Each period plays the window of P seconds
once. A window [w0, w1) emits every event due in it, across period boundaries. The
offset is whole seconds, so fractions in the raw text keep their digits.
"""

import math

from . import relabel
from .store import HOUR
from .schedule import Loop
from .timeshift import FORMATS, Shifter


class Engine:
    def __init__(self, dataset, feeds, index, schedule):
        """dataset: one store.Dataset, or a list of them (segments) that play in turn, period k
        playing segment k mod n. schedule: a schedule.Loop or schedule.Daily, or an anchor
        epoch for a loop from it."""
        self.segments = list(dataset) if isinstance(dataset, (list, tuple)) else [dataset]
        self.data = self.segments[0]
        names = set().union(*(set(d.feeds) for d in self.segments))
        self.feeds = {f.name: f for f in feeds if f.enabled and f.name in names}
        self.index = index
        self.schedule = schedule if hasattr(schedule, "start") else Loop(schedule, self.data.loop_seconds)
        self.json_sets = {name: relabel.parse_json_set(feed.json_set) for name, feed in self.feeds.items()}
        self.shifters = {
            (i, name): Shifter(d.first, d.last, feed.timestamp_formats or FORMATS, feed.text_timezone)
            for i, d in enumerate(self.segments) for name, feed in self.feeds.items()
        }

    def period_of(self, wall):
        return self.schedule.period_of(wall)

    def segment_of(self, k):
        return k % len(self.segments)

    def offset(self, k):
        return self.schedule.start(k) - self.segments[self.segment_of(k)].first

    def wraps(self, w0, w1):
        """Periods after the anchor whose start falls in [w0, w1): where per-period state resets."""
        return [k for k in range(self.period_of(w0), self.period_of(w1) + 1)
                if self.schedule.anchor < self.schedule.start(k) and w0 <= self.schedule.start(k) < w1]

    def status(self, wall):
        """Where the replay is at wall: period, position in it, and whether the window is playing."""
        k = self.period_of(wall)
        position = wall - self.schedule.start(k)
        following = self.schedule.start(k + 1)
        data = self.segments[self.segment_of(k)]
        return {"mode": self.schedule.mode, "loop": k, "segment": self.segment_of(k), "position": position,
                "loop_seconds": data.loop_seconds, "playing": position < data.loop_seconds,
                "next_start": following, "next_start_text": self.schedule.label(following)}

    def due(self, w0, w1):
        """Events due in [w0, w1), in time order, rewritten for now."""
        if w1 <= w0:
            return []
        out = []
        for k in range(self.period_of(w0), self.period_of(w1) + 1):
            seg = self.segment_of(k)
            data = self.segments[seg]
            first = data.first
            offset = self.offset(k)
            lo = max(first, w0 - offset)
            hi = min(first + data.loop_seconds, w1 - offset)
            if hi <= lo:
                continue
            for hour in range(int((lo - first) // HOUR), int(math.ceil((hi - first) / HOUR))):
                for name in sorted(self.feeds):
                    if name not in data.feeds:
                        continue
                    for event in data.hour(name, hour):
                        if lo <= event["t"] < hi:
                            rewritten = self._rewrite(name, event, offset, seg)
                            if rewritten is not None:
                                out.append(rewritten)
        out.sort(key=lambda e: e["time"])
        return out

    def _rewrite(self, name, event, offset, seg=0):
        feed = self.feeds[name]
        sourcetype = feed.set_sourcetype or event["sourcetype"]
        if feed.set_sourcetype and event["sourcetype"].lower() == feed.set_sourcetype.lower():
            sourcetype = event["sourcetype"]  # the export resolved the exact indexed case
        source = feed.set_source or event["source"]
        if feed.translate:  # a translation decides its own sourcetype and source
            event = relabel.translate(feed.translate, {**event, "sourcetype": sourcetype, "source": source})
            if event is None:
                return None
            sourcetype, source = event["sourcetype"], event["source"]
        return {
            "time": event["t"] + offset,
            "index": self.index,
            "sourcetype": sourcetype,
            "source": source,
            "host": event["host"],
            "raw": self.shifters[(seg, name)].shift(relabel.apply_json_set(event["raw"], self.json_sets[name]), offset,
                                                     event["t"]),
        }
