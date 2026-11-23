"""Export one dataset's feeds from its source index into its data folder (Prepare's export step).

The window is [dataset] window_start to window_end, each of the segments in turn, or all of the
source index rounded to whole hours when neither is set. Each [feed] stanza's `search` is added to
`search index=<source_index>`. The same data always gives the same files.

The export is written to a folder beside the data folder and swapped in only when complete, so a
failed or interrupted export leaves the previous one in place.
"""

import re
import shutil
from pathlib import Path

from . import config as config_mod
from . import store


class ExportError(RuntimeError):
    pass


def _value(result, key):
    value = result.get(key)
    return value[0] if isinstance(value, list) else value


def span(client, index):
    rows = list(client.export(f"| tstats min(_time) as first max(_time) as last where index={index}"))
    if not rows or rows[0].get("first") in (None, ""):
        raise ExportError(f"index={index} has no events: load the dataset into it first")
    return int(float(rows[0]["first"])), int(float(rows[0]["last"]))


def count(client, index, first, last):
    rows = list(client.export(f"| tstats count where index={index}", str(first), str(last + 1)))
    return int(float(rows[0].get("count") or 0)) if rows else 0


def sourcetype_cases(client, index):
    """Indexed sourcetype names by their lowercase form. tstats reports them lowercased, but props
    stanzas (Splunk_TA_windows' renames and extractions) match the exact case."""
    rows = client.export(f"| metadata type=sourcetypes index={index} | fields sourcetype")
    return {r["sourcetype"].lower(): r["sourcetype"] for r in rows if r.get("sourcetype")}


def indexed_name(feed, cases):
    """The exact-case indexed sourcetype for a feed's set_sourcetype."""
    name = feed.set_sourcetype
    # Windows event logs: the indexed sourcetype is the source (WinEventLog:Security, ...), which
    # metadata reports renamed (WinEventLog), so take the case from the source.
    sources = [feed.set_source] if feed.set_source else []
    sources += re.findall(r'(?<!\w)source="([^"]+)"', feed.search)
    for source in sources:
        if source and source.lower() == name.lower():
            return source
    return cases.get(name.lower(), name)


def windows(cfg, client=None):
    """[(first, last, loop_seconds or None)]: the segments, the window, or the whole index."""
    segments = config_mod.segments(cfg.replay)
    if segments:
        return [(start, end - 1, end - start) for start, end in segments]
    start, end = cfg.replay.get("window_start", "").strip(), cfg.replay.get("window_end", "").strip()
    if start and end:
        return [(int(float(start)), int(float(end)) - 1, int(float(end)) - int(float(start)))]
    first, last = span(client, cfg.replay["source_index"])
    return [(first, last, None)]


def export(client, cfg, data_dir=None, log=print):
    """Export every enabled feed; returns the top manifest. Raises ExportError when the source index
    has nothing in the window (the dataset isn't loaded yet)."""
    data_dir = Path(data_dir) if data_dir else config_mod.data_dir(cfg.replay)
    index = cfg.replay["source_index"]
    spans = windows(cfg, client)
    if not count(client, index, min(s[0] for s in spans), max(s[1] for s in spans)):
        raise ExportError(f"index={index} has no events in the replay window: load the dataset into it first")
    cases = sourcetype_cases(client, index)
    work = data_dir.with_name(data_dir.name + ".new")
    if work.exists():
        shutil.rmtree(work)  # an earlier export that didn't finish
    work.mkdir(parents=True)
    if len(spans) == 1 and not config_mod.segments(cfg.replay):
        first, last, loop = spans[0]
        manifest = export_window(client, cfg, index, cases, first, last, loop, work, log)
    else:
        names = []
        for i, (first, last, loop) in enumerate(spans):
            name = f"seg{i:02d}"
            log({"step": "export", "segment": name, "first": first, "last": last})
            export_window(client, cfg, index, cases, first, last, loop, work / name, log)
            names.append(name)
        manifest = store.write_segments(work, names, [f"{f}-{l + 1}" for f, l, _ in spans])
    old = data_dir.with_name(data_dir.name + ".old")
    if old.exists():
        shutil.rmtree(old)
    if data_dir.exists():
        data_dir.rename(old)
    work.rename(data_dir)
    if old.exists():
        shutil.rmtree(old)
    return manifest


def export_window(client, cfg, index, cases, first, last, loop_seconds, data_dir, log=print):
    counts = {}
    for feed in cfg.feeds:
        if not feed.enabled:
            continue
        # The export endpoint's JSON gives _time as formatted text, so carry it as epoch seconds.
        search = (f"search index={index} {feed.search} | eval epoch=_time"
                  f" | fields epoch _raw _cd sourcetype source host")
        indexed = indexed_name(feed, cases) if feed.set_sourcetype else None
        seen = set()

        def events(results=client.export(search, str(first), str(last + 1)), seen=seen, indexed=indexed,
                   name=feed.name):
            # Streamed: a busy feed (DEDALE's auditd) is millions of events a day.
            for r in results:
                cd = _value(r, "_cd")
                if cd in seen:
                    raise ExportError(f"{name}: more results than events (_cd {cd} repeats); its sourcetype "
                                      "needs KV_MODE = none in the pack's props.conf")
                seen.add(cd)
                e = {"t": float(_value(r, "epoch")), "raw": _value(r, "_raw"),
                     "sourcetype": _value(r, "sourcetype"), "source": _value(r, "source"), "host": _value(r, "host")}
                if not first <= e["t"] <= last:
                    continue
                if indexed:  # write the indexed name; search-time renames then apply as usual
                    e["sourcetype"] = indexed
                yield e

        counts[feed.name] = store.write_feed(data_dir, feed.name, events(), first)
        log({"step": "export", "feed": feed.name, "events": counts[feed.name]})
    return store.write_manifest(data_dir, first, last, counts, loop_seconds)
