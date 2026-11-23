"""Datasets side by side: each plays in its own process, and rules they share stay on until the last stops.

FakeSplunkd answers the saved-search endpoints and a small KV store. Its KV store can lag the way a
search head cluster member's copy lags the leader: reads return an older copy while writes (and the
leader's refusal of a taken claim) are current.
"""

import copy
import io
import json
import re
import sys
import urllib.parse
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "replay_lab" / "bin"))

from replaylib import ledger as ledger_mod  # noqa: E402
from replaylib import store  # noqa: E402
from replaylib.ledger import Busy, KvLedger  # noqa: E402
from replaylib.rules import SKIP_MARK, Rules  # noqa: E402
from replaylib.runner import Runner  # noqa: E402

RISK = "Risk - 24 Hour Risk Threshold Exceeded - Rule"
SHARED = "ESCU - Shared - Rule"
ONLY_A = "ESCU - Only Alpha - Rule"


class FakeSplunkd:
    def __init__(self):
        self.searches = {
            RISK: {"app": "SA-ThreatIntelligence", "disabled": "1", "is_scheduled": "1",
                   "dispatch.earliest_time": "-1450m@m", "search": "| tstats count"},
            SHARED: {"app": "DA-ESS-ContentUpdate", "disabled": "1", "is_scheduled": "0"},
            ONLY_A: {"app": "DA-ESS-ContentUpdate", "disabled": "1", "is_scheduled": "0"},
        }
        self.kv = {}  # collection -> {key: doc}, as the leader has it
        self.replica = None  # an older copy, when this member lags
        self.lag_reads = 0
        self.writes = []

    # -- the KV store --

    def lag(self, reads):
        """The next `reads` reads come from a copy taken now."""
        self.replica, self.lag_reads = copy.deepcopy(self.kv), reads

    def _read(self):
        if self.lag_reads > 0:
            self.lag_reads -= 1
            return self.replica
        return self.kv

    @staticmethod
    def _match(doc, where):
        if "$and" in where:
            return all(FakeSplunkd._match(doc, w) for w in where["$and"])
        for field, want in where.items():
            if isinstance(want, dict):
                if not (field in doc and doc[field] < want["$lt"]):
                    return False
            elif doc.get(field) != want:
                return False
        return True

    def _kv(self, method, parts, query, body):
        collection = parts[6]
        key = parts[7] if len(parts) > 7 else None
        if method == "GET":
            docs = self._read().get(collection, {})
            if key is not None:
                return (200, copy.deepcopy(docs[key])) if key in docs else (404, {})
            return 200, copy.deepcopy(list(docs.values()))
        docs = self.kv.setdefault(collection, {})
        if method == "DELETE":
            where = json.loads(query["query"])
            for k in [k for k, d in docs.items() if self._match(d, where)]:
                del docs[k]
            return 200, {}
        if key is None:  # insert
            if body["_key"] in docs:
                return 409, {}
            docs[body["_key"]] = copy.deepcopy(body)
            return 201, {}
        if key not in docs:
            return 404, {}
        docs[key] = {**copy.deepcopy(body), "_key": key}
        return 200, {}

    # -- saved searches --

    def call(self, method, path, query=None, form=None, timeout=120, body=None):
        parts = [urllib.parse.unquote(p) for p in path.split("/") if p]
        if parts[3:6] == ["storage", "collections", "data"]:
            return self._kv(method, parts, query or {}, body)
        if path == "/services/search/jobs":
            return 200, {}
        if parts[3:5] == ["saved", "searches"]:
            if len(parts) == 5:
                patterns = re.findall(r'name="([^"]+)"', (query or {}).get("search", ""))
                hits = [n for n in self.searches
                        if any(re.fullmatch(p.replace("*", ".*"), n.lower()) for p in patterns)]
                return 200, {"entry": [self._entry(n) for n in hits]}
            name = parts[5]
            if name not in self.searches:
                return 404, {}
            if method == "GET":
                return 200, {"entry": [self._entry(name)]}
            search = self.searches[name]
            self.writes.append((name, parts[6] if len(parts) > 6 else dict(form)))
            if len(parts) > 6:
                search["disabled"] = "1" if parts[6] == "disable" else "0"
            for k, v in (form or {}).items():
                if k != "output_mode":
                    search[k] = v
            return 200, {}
        return 404, {}

    def _entry(self, name):
        s = self.searches[name]
        return {"name": name, "acl": {"app": s["app"]}, "content": {k: v for k, v in s.items() if k != "app"}}

    def on(self, name):
        return self.searches[name]["disabled"] == "0" and self.searches[name]["is_scheduled"] == "1"

    def record(self, name):
        return self.kv.get(ledger_mod.RULES, {}).get(KvLedger.key(name))


class Clock:
    def __init__(self, t=1_800_000_000):
        self.t = t

    def __call__(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


@pytest.fixture
def splunkd():
    return FakeSplunkd()


def rules_for(splunkd, names, **tuning):
    return Rules(splunkd, names, **tuning)


def switch_on(splunkd, dataset, names, clock=None, **tuning):
    clock = clock or Clock()
    return list(rules_for(splunkd, names, **tuning).enable(KvLedger(dataset, splunkd, clock, clock.sleep), dataset))


def switch_off(splunkd, dataset, clock=None):
    clock = clock or Clock()
    return list(Rules(splunkd, []).put_back(KvLedger(dataset, splunkd, clock, clock.sleep), dataset))


# --- the shared ledger ---

def test_a_shared_rule_stays_on_until_both_datasets_stop(splunkd):
    switch_on(splunkd, "alpha", [SHARED, ONLY_A])
    assert splunkd.on(SHARED) and splunkd.on(ONLY_A)
    switch_on(splunkd, "beta", [SHARED])
    assert splunkd.record(SHARED)["holders"] == ["alpha", "beta"]
    assert json.loads(splunkd.record(SHARED)["original"]) == {"disabled": "1", "is_scheduled": "0"}

    switch_off(splunkd, "alpha")
    assert splunkd.on(SHARED) and not splunkd.on(ONLY_A)  # beta still holds the shared one
    assert splunkd.record(SHARED)["holders"] == ["beta"]

    switch_off(splunkd, "beta")
    assert splunkd.searches[SHARED]["disabled"] == "1" and splunkd.searches[SHARED]["is_scheduled"] == "0"
    assert splunkd.record(SHARED)["holders"] == [] and splunkd.record(SHARED)["original"] == "{}"


def test_the_order_of_stopping_does_not_matter(splunkd):
    switch_on(splunkd, "alpha", [SHARED])
    switch_on(splunkd, "beta", [SHARED])
    switch_off(splunkd, "beta")
    assert splunkd.on(SHARED)
    switch_off(splunkd, "alpha")
    assert not splunkd.on(SHARED)


def test_a_rule_that_was_on_before_is_never_held_or_touched(splunkd):
    splunkd.searches[SHARED].update(disabled="0", is_scheduled="1")
    switch_on(splunkd, "alpha", [SHARED])
    switch_off(splunkd, "alpha")
    assert splunkd.on(SHARED) and splunkd.writes == []


def test_risk_tuning_from_the_latest_dataset_wins_and_the_last_puts_the_original_back(splunkd):
    switch_on(splunkd, "alpha", ["@risk_rule"], risk_earliest="-490m@m", skip_risk_objects=["unknown"])
    risk = splunkd.searches[RISK]
    assert risk["dispatch.earliest_time"] == "-490m@m" and SKIP_MARK in risk["search"]
    switch_on(splunkd, "beta", ["@risk_rule"], risk_earliest="-24h@h")
    assert risk["dispatch.earliest_time"] == "-24h@h" and risk["search"].count(SKIP_MARK) == 1
    original = json.loads(splunkd.record(RISK)["original"])
    assert original["dispatch.earliest_time"] == "-1450m@m" and original["search"] == "| tstats count"

    switch_off(splunkd, "alpha")
    switch_off(splunkd, "beta")
    assert (risk["dispatch.earliest_time"], risk["search"], risk["disabled"]) == ("-1450m@m", "| tstats count", "1")


def test_a_lagging_copy_cannot_record_a_switched_on_rule_as_its_original(splunkd):
    clock = Clock()
    switch_on(splunkd, "alpha", [SHARED], clock)  # the leader has alpha's record (version 1); the rule is on
    splunkd.lag(3)
    splunkd.replica[ledger_mod.RULES] = {}  # this member's copy hasn't seen that record yet

    switch_on(splunkd, "beta", [SHARED], clock)

    record = splunkd.record(SHARED)
    assert record["holders"] == ["alpha", "beta"] and record["version"] == 2
    assert json.loads(record["original"]) == {"disabled": "1", "is_scheduled": "0"}  # not "on"
    assert clock.t > 1_800_000_000  # it waited for its copy to catch up


def test_a_claim_left_by_a_process_that_died_is_taken_over(splunkd):
    clock = Clock()
    key = KvLedger.key(SHARED)
    splunkd.kv[ledger_mod.CLAIMS] = {f"{key}@1": {"_key": f"{key}@1", "rule": key, "version": 1,
                                                 "at": clock.t - 3600, "by": "gamma"}}
    switch_on(splunkd, "alpha", [SHARED], clock)
    assert splunkd.on(SHARED) and splunkd.record(SHARED)["holders"] == ["alpha"]


def test_a_live_claim_makes_the_other_wait_then_give_up(splunkd):
    clock = Clock()
    key = KvLedger.key(SHARED)
    splunkd.kv[ledger_mod.CLAIMS] = {f"{key}@1": {"_key": f"{key}@1", "rule": key, "version": 1,
                                                 "at": clock.t + 3600, "by": "gamma"}}
    with pytest.raises(Busy):
        switch_on(splunkd, "alpha", [SHARED], clock)
    assert not splunkd.on(SHARED)


def test_a_crash_after_the_record_is_saved_still_lets_the_dataset_put_back(splunkd, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("splunkd went away")
    rules = rules_for(splunkd, [SHARED])
    monkeypatch.setattr(rules, "_set", boom)
    with pytest.raises(RuntimeError):
        list(rules.enable(KvLedger("alpha", splunkd), "alpha"))
    assert splunkd.record(SHARED)["holders"] == ["alpha"]  # the original is safe before any change
    switch_off(splunkd, "alpha")
    assert splunkd.record(SHARED)["holders"] == [] and not splunkd.on(SHARED)


# --- two datasets ticking side by side ---

FIRST = 1_500_000_000


def make_app(tmp_path, datasets):
    app = tmp_path / "app"
    (app / "default").mkdir(parents=True)
    (app / "local").mkdir()
    text = ""
    for name, rules in datasets.items():
        names = " \\\n    ".join(rules)  # one per line, continued with a backslash
        text += (f"[dataset:{name}]\nenabled = 1\nmax_catchup_seconds = 86400\n[feed:{name}:f]\nsearch = x\n"
                 f"[rules:{name}]\nnames = {names}\n")
        data = tmp_path / "home" / "var" / "lib" / "replay_lab" / name
        events = [{"t": FIRST + 10.0 * i, "raw": f"{name} event {i}", "sourcetype": "st", "source": "s",
                   "host": "h"} for i in range(1, 6)]
        count = store.write_feed(data, "f", events, FIRST)
        store.write_manifest(data, FIRST, FIRST + 99, {"f": count})
    (app / "default" / "replay_lab.conf").write_text(text)
    return app


def runner(app, tmp_path, splunkd, name, out, clock):
    return Runner(app, tmp_path / f"{name}.json", out, now=clock, sleep=lambda s: None, dataset=name,
                  rules=lambda cfg: Rules(splunkd, cfg.rules), ledger=lambda: KvLedger(name, splunkd, clock))


def test_two_datasets_tick_in_turn_each_event_once_to_its_index_and_share_a_rule(tmp_path, splunkd, monkeypatch):
    monkeypatch.setenv("SPLUNK_HOME", str(tmp_path / "home"))
    app = make_app(tmp_path, {"alpha": [SHARED, ONLY_A], "beta": [SHARED]})
    clock = Clock(1_800_000_000)
    outs = {"alpha": io.StringIO(), "beta": io.StringIO()}
    runners = {n: runner(app, tmp_path, splunkd, n, outs[n], clock) for n in outs}
    for _ in range(5):
        for r in runners.values():
            r.tick()
        clock.t += 30
    for name, out in outs.items():
        events = re.findall(r'stanza="replay_lab://(\w+)">.*?<index>(\w+)</index>.*?<data>([^<]*)</data>',
                            out.getvalue())
        assert len(events) == 5 and len(set(events)) == 5
        assert all(e[0] == name and e[1] == f"{name}_live" and e[2].startswith(name) for e in events)
    assert splunkd.on(SHARED) and splunkd.record(SHARED)["holders"] == ["alpha", "beta"]

    (app / "local" / "replay_lab.conf").write_text("[dataset:alpha]\nenabled = 0\n")
    for r in runners.values():
        r.tick()
    assert splunkd.on(SHARED) and not splunkd.on(ONLY_A)

    (app / "local" / "replay_lab.conf").write_text("[dataset:alpha]\nenabled = 0\n[dataset:beta]\nenabled = 0\n")
    for r in runners.values():
        r.tick()
    assert not splunkd.on(SHARED) and splunkd.record(SHARED)["holders"] == []


def test_rules_mode_is_per_dataset(tmp_path, splunkd, monkeypatch):
    monkeypatch.setenv("SPLUNK_HOME", str(tmp_path / "home"))
    app = make_app(tmp_path, {"alpha": [SHARED], "beta": [ONLY_A]})
    (app / "local" / "replay_lab.conf").write_text("[dataset:beta]\nrules_mode = none\n")
    clock = Clock(1_800_000_000)
    for name in ("alpha", "beta"):
        runner(app, tmp_path, splunkd, name, io.StringIO(), clock).tick()
    assert splunkd.on(SHARED) and not splunkd.on(ONLY_A)
