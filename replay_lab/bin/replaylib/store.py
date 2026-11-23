"""The exported dataset: one folder per feed, one gzipped JSON-lines file per hour.

    data/manifest.json             {"first": F, "last": L, "hours": H, "loop_seconds": P, "feeds": {name: count}}
    data/<feed>/<hour:05d>.jsonl.gz  events whose time is in [F + 3600*hour, F + 3600*(hour+1))

Each event is {"t": <epoch float>, "raw", "sourcetype", "source", "host"}, sorted
by (t, raw). Files are written with a zero gzip mtime and no name, so the same
events always give the same bytes.
"""

import gzip
import json
import math
from collections import OrderedDict
from pathlib import Path

HOUR = 3600


def hour_of(t, first):
    return int((t - first) // HOUR)


def write_feed(data_dir, feed, events, first):
    """Write events (any iterable, consumed once) as sorted hourly files. Events spill to one
    plain temp file per hour first, so a feed with millions of events (DEDALE's auditd, about
    3M a day) never sits in memory whole; each hour is then sorted on its own."""
    folder = Path(data_dir) / feed
    folder.mkdir(parents=True, exist_ok=True)
    for old in list(folder.glob("*.jsonl.gz")) + list(folder.glob("*.spill")):
        old.unlink()
    spills, count = {}, 0
    try:
        for event in events:
            hour = hour_of(event["t"], first)
            fh = spills.get(hour)
            if fh is None:
                fh = spills[hour] = open(folder / f"{hour:05d}.spill", "w")
            fh.write(json.dumps(event, sort_keys=True) + "\n")
            count += 1
    finally:
        for fh in spills.values():
            fh.close()
    for hour in sorted(spills):
        spill = folder / f"{hour:05d}.spill"
        with open(spill) as f:
            items = [json.loads(line) for line in f]
        items.sort(key=lambda e: (e["t"], e["raw"]))
        body = "".join(json.dumps(e, sort_keys=True) + "\n" for e in items).encode()
        with open(folder / f"{hour:05d}.jsonl.gz", "wb") as raw, \
                gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
            gz.write(body)
        spill.unlink()
    return count


def write_manifest(data_dir, first, last, counts, loop_seconds=None):
    """`loop_seconds` defaults to the whole hours that cover [first, last]."""
    hours = loop_hours(first, last)
    manifest = {"first": first, "last": last, "hours": hours, "feeds": counts,
                "loop_seconds": int(loop_seconds) if loop_seconds else hours * HOUR}
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    (Path(data_dir) / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    return manifest


def loop_hours(first, last):
    """Whole hours that cover [first, last], so the last event is inside the loop."""
    return max(1, math.ceil((last - first + 1) / HOUR))


def open_all(data_dir, cache_size=8):
    """The exported segments, in play order. A rotating export's top manifest lists segment
    folders ({"segments": ["seg00", ...]}); a single-window export is one segment."""
    top = json.loads((Path(data_dir) / "manifest.json").read_text())
    if "segments" in top:
        return [Dataset(Path(data_dir) / name, cache_size) for name in top["segments"]]
    return [Dataset(data_dir, cache_size)]


def write_segments(data_dir, names, labels=None):
    manifest = {"segments": list(names)}
    if labels:
        manifest["labels"] = list(labels)
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    (Path(data_dir) / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    return manifest


class Dataset:
    def __init__(self, data_dir, cache_size=8):
        self.dir = Path(data_dir)
        manifest = json.loads((self.dir / "manifest.json").read_text())
        self.first = int(manifest["first"])
        self.last = manifest["last"]
        self.hours = int(manifest["hours"])
        self.loop_seconds = int(manifest.get("loop_seconds") or self.hours * HOUR)
        self.feeds = dict(manifest["feeds"])
        self._cache = OrderedDict()
        self._cache_size = cache_size

    def hour(self, feed, hour):
        key = (feed, hour)
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        path = self.dir / feed / f"{hour:05d}.jsonl.gz"
        events = []
        if path.exists():
            with gzip.open(path, "rt") as f:
                events = [json.loads(line) for line in f if line.strip()]
        self._cache[key] = events
        while len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)
        return events
