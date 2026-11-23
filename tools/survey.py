#!/usr/bin/env python3
"""Survey a dataset for a pack: which sourcetypes it has, and which ESCU detections fire on it.

    SPLUNK_PASSWORD=... python3 tools/survey.py feeds botsv3 https://sh.example.com:8089 --ca-file ca.pem
    SPLUNK_PASSWORD=... python3 tools/survey.py rules botsv3 https://sh.example.com:8089 --raw --out raw.jsonl
    SPLUNK_PASSWORD=... python3 tools/survey.py rules botsv2 https://sh.example.com:8089 --raw --per-segment
    SPLUNK_PASSWORD=... python3 tools/survey.py rules botsv3 https://sh.example.com:8089 --earliest -7h

feeds: the source index's sourcetypes and sources next to the pack's [feed] stanzas, so none is
missed or matched twice.

rules: every saved search named "ESCU - <name> - Rule" with a risk action, run as an ad hoc search
job in ESCU's app context, so no alert action runs. Searches that write (outputlookup, collect,
sendemail, ...) are skipped. One JSON line per detection goes to --out; the summary lists those
with results, marking NEW the ones the pack's [rules] names doesn't list.
  --raw         over the source index (searches that name no index get `index=<source_index>`),
                in the pack's window. Default: over the live index's data, as the replay plays
                it, for the last window length.
  --per-segment with --raw: one run per segment, and a matrix of results per segment.

Read-only. The pack argument is a name under datasets/ or a path to a pack folder.
"""

import argparse
import configparser
import json
import os
import re
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "replay_lab" / "bin"))

from replaylib.splunkd import Client  # noqa: E402

ESCU = "DA-ESS-ContentUpdate"
WRITES = re.compile(r"\|\s*(outputlookup|outputcsv|collect|mcollect|meventcollect|tscollect|sendemail|sendalert|"
                    r"delete|dbxoutput)\b", re.I)


# -- the pack --

class Pack:
    def __init__(self, ref, root=ROOT):
        folder = Path(ref) if ("/" in str(ref) or Path(ref).is_dir()) else Path(root) / "datasets" / ref
        if not (folder / "pack.conf").is_file():
            raise SystemExit(f"no pack at {folder}")
        self.name = folder.name
        parser = configparser.RawConfigParser(strict=False, interpolation=None)
        parser.optionxform = str
        parser.read(folder / "pack.conf")
        self.dataset = dict(parser.items("dataset")) if parser.has_section("dataset") else {}
        self.feeds = {s[5:]: dict(parser.items(s)) for s in parser.sections() if s.startswith("feed:")}
        names = parser.get("rules", "names", fallback="") if parser.has_section("rules") else ""
        self.rules = {n.strip() for n in names.replace("\\\n", "\n").replace("\\", "\n").splitlines()
                      if n.strip() and not n.strip().startswith("@")}
        self.source_index = self.dataset.get("source_index", "").strip() or self.name
        self.index = self.dataset.get("index", "").strip() or f"{self.name}_live"

    def windows(self):
        """[(start, end)]: the segments, else the window, else []."""
        text = self.dataset.get("segments", "").replace("\\", " ").replace(",", " ")
        spans = [tuple(int(float(x)) for x in item.split("-", 1)) for item in text.split()]
        if spans:
            return spans
        start, end = self.dataset.get("window_start", "").strip(), self.dataset.get("window_end", "").strip()
        return [(int(float(start)), int(float(end)))] if start and end else []


# -- feeds --

def feed_match(feed, sourcetype, source):
    """Does the feed's search select events with this sourcetype and source? (key="value" terms only)"""
    terms = re.findall(r'(sourcetype|source)="([^"]+)"', feed.get("search", ""))
    if not terms:
        return False
    for key, value in terms:
        actual = sourcetype if key == "sourcetype" else source
        pattern = "^" + re.escape(value.lower()).replace(r"\*", ".*") + "$"
        if not re.match(pattern, actual.lower()):
            return False
    return True


def survey_feeds(client, pack):
    rows = list(client.export(f"| tstats count where index={pack.source_index} by sourcetype source"))
    report = []
    for r in sorted(rows, key=lambda r: (r.get("sourcetype", ""), r.get("source", ""))):
        st, src = r.get("sourcetype", ""), r.get("source", "")
        feeds = [name for name, f in pack.feeds.items() if feed_match(f, st, src)]
        report.append({"sourcetype": st, "source": src, "count": int(float(r.get("count") or 0)), "feeds": feeds})
    used = {f for r in report for f in r["feeds"]}
    return report, sorted(set(pack.feeds) - used)


# -- rules --

def detections(client):
    status, body = client.call("GET", f"/servicesNS/-/{ESCU}/saved/searches", query={"count": "0"})
    if status != 200:
        raise SystemExit(f"couldn't list saved searches (HTTP {status})")
    out = []
    for entry in body.get("entry", []):
        content, name = entry.get("content") or {}, entry["name"]
        risky = "risk" in str(content.get("actions", "")).split(",") or \
            str(content.get("action.risk", "")).lower() in ("1", "true")
        if (entry.get("acl") or {}).get("app") == ESCU and name.startswith("ESCU - ") and name.endswith(" - Rule") \
                and risky:
            out.append((name, content.get("search", "")))
    return sorted(out)


def prepare(search, index=None):
    """(the search to run, whether an index was added)."""
    search = search.strip()
    if search.startswith("|"):
        return search, False
    if index and "index=" not in search.replace(" ", ""):
        return f"search index={index} {search}", True
    return f"search {search}", False


def run_one(client, name, search, earliest, latest, index, timeout, poll, now=time.time, sleep=time.sleep):
    record = {"rule": name, "earliest": earliest, "latest": latest}
    if WRITES.search(search):
        return {**record, "state": "SKIPPED", "count": 0}
    spl, prefixed = prepare(search, index)
    started = now()
    status, body = client.call("POST", f"/servicesNS/{urllib.parse.quote(client.owner, safe='')}/{ESCU}/search/jobs",
                               form={"search": spl, "earliest_time": str(earliest), "latest_time": str(latest),
                                     "exec_mode": "normal"})
    sid = body.get("sid") if status in (200, 201) else None
    if not sid:
        return {**record, "state": "FAILED", "count": 0, "msgs": [m.get("text") for m in body.get("messages", [])]}
    path = f"/servicesNS/{urllib.parse.quote(client.owner, safe='')}/{ESCU}/search/jobs/{sid}"
    state, content = "TIMEOUT", {}
    while now() - started < timeout:
        _, body = client.call("GET", path)
        content = ((body.get("entry") or [{}])[0].get("content") or {})
        if content.get("dispatchState") in ("DONE", "FAILED"):
            state = content["dispatchState"]
            break
        sleep(poll)
    client.call("POST", path + "/control", form={"action": "cancel"}) if state == "TIMEOUT" else \
        client.call("DELETE", path)
    return {**record, "state": state, "count": int(content.get("resultCount") or 0),
            "scan": int(content.get("scanCount") or 0), "secs": round(now() - started, 1), "prefixed": prefixed,
            "msgs": [m.get("text") for m in content.get("messages", []) if isinstance(m, dict)][:3]}


def survey_rules(client, pack, spans, raw, jobs=4, timeout=120, poll=1.0, out=None, log=print):
    found = detections(client)
    log(f"{len(found)} ESCU detections with a risk action; {len(spans)} window(s)")
    results = []
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        for seg, (earliest, latest) in enumerate(spans):
            futures = [pool.submit(run_one, client, name, search, earliest, latest,
                                   pack.source_index if raw else None, timeout, poll) for name, search in found]
            for future in futures:
                record = {**future.result(), "segment": seg}
                results.append(record)
                if out:
                    out.write(json.dumps(record, sort_keys=True) + "\n")
    return results


def summary(results, pack, segments):
    lines, fired = [], {}
    for r in results:
        if r["state"] == "DONE" and r["count"]:
            fired.setdefault(r["rule"], [0] * segments)[r["segment"]] = r["count"]
    head = "  ".join(f"seg{i:02d}" for i in range(segments)) if segments > 1 else "results"
    lines.append(f"{len(fired)} detections with results ({head}):")
    for name in sorted(fired, key=lambda n: -sum(fired[n])):
        counts = "  ".join(f"{c:5d}" for c in fired[name])
        lines.append(f"  {counts}  {name}{'' if name in pack.rules else '  NEW'}")
    quiet = sorted(pack.rules - set(fired))
    if quiet:
        lines.append(f"{len(quiet)} listed in the pack with no results: " + "; ".join(quiet))
    trouble = sorted({(r["rule"], r["state"]) for r in results if r["state"] != "DONE"})
    if trouble:
        lines.append(f"{len(trouble)} incomplete: " + "; ".join(f"{n} ({s})" for n, s in trouble))
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("what", choices=["feeds", "rules"])
    parser.add_argument("pack")
    parser.add_argument("url", help="splunkd management URL")
    parser.add_argument("--user", default="admin")
    parser.add_argument("--ca-file")
    parser.add_argument("--insecure", action="store_true", help="skip TLS verification (a throwaway lab only)")
    parser.add_argument("--raw", action="store_true", help="survey the source index in the pack's window")
    parser.add_argument("--per-segment", action="store_true", help="with --raw: each segment on its own")
    parser.add_argument("--earliest")
    parser.add_argument("--latest")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--out", default="survey.jsonl")
    args = parser.parse_args(argv)
    password = os.environ.get("SPLUNK_PASSWORD")
    if not password:
        parser.error("set SPLUNK_PASSWORD")
    pack = Pack(args.pack)
    client = Client(args.url, user=args.user, password=password, ca_file=args.ca_file, verify=not args.insecure)

    if args.what == "feeds":
        report, unused = survey_feeds(client, pack)
        for r in report:
            mark = ", ".join(r["feeds"]) or "NO FEED"
            if len(r["feeds"]) > 1:
                mark += "  (MATCHED TWICE)"
            print(f"{r['count']:>10}  {r['sourcetype']}  {r['source']}  -> {mark}")
        if unused:
            print("feeds that match nothing: " + ", ".join(unused))
        return 0

    windows = pack.windows()
    if args.earliest or args.latest:
        spans = [(args.earliest or "0", args.latest or "now")]
    elif args.raw:
        if not windows:
            parser.error("the pack sets no window or segments: give --earliest and --latest")
        spans = windows if args.per_segment else [(min(s for s, _ in windows), max(e for _, e in windows))]
    else:  # the replay: the last window's length, up to now
        length = (windows[0][1] - windows[0][0]) if windows else 86400
        spans = [(f"-{int(length)}s", "now")]
    with open(args.out, "w") as out:
        results = survey_rules(client, pack, spans, args.raw, args.jobs, args.timeout, out=out,
                               log=lambda m: print(m, file=sys.stderr))
    print(summary(results, pack, len(spans)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
