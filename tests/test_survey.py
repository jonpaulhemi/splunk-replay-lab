"""tools/survey.py against any pack, with a fake splunkd."""

import io
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "replay_lab" / "bin"))
sys.path.insert(0, str(REPO))

import build  # noqa: E402
import survey  # noqa: E402
from replaylib import config as config_mod  # noqa: E402


class FakeSplunkd:
    owner = "admin"

    def __init__(self, searches, hits, rows=()):
        self.searches = searches  # name -> (search, actions)
        self.hits = hits  # substring of the dispatched search -> results
        self.rows = list(rows)
        self.jobs, self.deleted = {}, []

    def export(self, search, earliest="0", latest="+10y"):
        return iter(self.rows)

    def call(self, method, path, query=None, form=None, timeout=120, body=None):
        if path.endswith("/saved/searches"):
            return 200, {"entry": [{"name": n, "acl": {"app": app}, "content": {"search": s, "actions": a}}
                                   for n, (s, a, app) in self.searches.items()]}
        if path.endswith("/search/jobs") and method == "POST":
            sid = f"job{len(self.jobs)}"
            self.jobs[sid] = form
            return 201, {"sid": sid}
        sid = path.rsplit("/", 1)[1]
        if method == "DELETE":
            self.deleted.append(sid)
            return 200, {}
        spl = self.jobs[sid]["search"]
        count = 0
        for key, n in self.hits.items():  # "term" or "term@<earliest>"
            term, _, when = key.partition("@")
            if term in spl and when in ("", self.jobs[sid]["earliest_time"]):
                count += n
        return 200, {"entry": [{"content": {"dispatchState": "DONE", "resultCount": count}}]}


def test_every_pack_reads_its_indexes_windows_and_rule_list(tmp_path):
    app = build.stage(tmp_path / "built")
    for name in ("botsv3", "botsv2", "dedale"):
        pack = survey.Pack(name)
        cfg = config_mod.load(app, name)
        assert pack.source_index == cfg.replay["source_index"] and pack.index == cfg.replay["index"]
        assert pack.rules == {r for r in cfg.rules if not r.startswith("@")}
        assert pack.windows() == (config_mod.segments(cfg.replay) or
                                  [(int(cfg.replay["window_start"]), int(cfg.replay["window_end"]))])


def test_feeds_shows_each_sourcetype_next_to_its_feed():
    pack = survey.Pack("botsv3")
    client = FakeSplunkd({}, {}, rows=[
        {"sourcetype": "WinEventLog", "source": "WinEventLog:Security", "count": "10"},
        {"sourcetype": "cisco:asa", "source": "udp:514", "count": "5"},
        {"sourcetype": "made:up", "source": "x", "count": "1"}])
    report, unused = survey.survey_feeds(client, pack)
    by = {r["sourcetype"]: r["feeds"] for r in report}
    assert len(by["WinEventLog"]) == 1 and len(by["cisco:asa"]) == 1 and by["made:up"] == []
    assert len(unused) == len(pack.feeds) - 2


def test_rules_runs_risk_detections_read_only_and_marks_new_ones(tmp_path):
    pack = survey.Pack("botsv3")
    listed = sorted(pack.rules)[0]
    client = FakeSplunkd({
        listed: ("`sysmon` EventCode=1 | stats count", "risk,notable", survey.ESCU),
        "ESCU - Brand New - Rule": ("| tstats count from datamodel=Endpoint", "risk", survey.ESCU),
        "ESCU - Writes - Rule": ("index=x | outputlookup y", "risk", survey.ESCU),
        "ESCU - No Risk - Rule": ("index=x", "notable", survey.ESCU),
        "Someone else's - Rule": ("index=x", "risk", "search"),
    }, {"EventCode=1": 7, "datamodel=Endpoint": 3})
    out = io.StringIO()
    results = survey.survey_rules(client, pack, [(1534755600, 1534779000)], raw=True, out=out, log=lambda m: None)

    assert {r["rule"]: r["state"] for r in results} == {listed: "DONE", "ESCU - Brand New - Rule": "DONE",
                                                         "ESCU - Writes - Rule": "SKIPPED"}
    dispatched = [j["search"] for j in client.jobs.values()]
    assert "search index=botsv3 `sysmon` EventCode=1 | stats count" in dispatched
    assert "| tstats count from datamodel=Endpoint" in dispatched
    assert len(client.deleted) == 2 and len(out.getvalue().splitlines()) == 3
    text = survey.summary(results, pack, 1)
    assert "ESCU - Brand New - Rule  NEW" in text and f"{listed}  NEW" not in text
    assert "incomplete: ESCU - Writes - Rule (SKIPPED)" in text


def test_per_segment_gives_a_matrix(tmp_path):
    pack = survey.Pack("botsv2")
    spans = pack.windows()[:2]
    client = FakeSplunkd({"ESCU - A - Rule": ("index=botsv2 x", "risk", survey.ESCU)},
                         {f"x@{spans[1][0]}": 4})
    results = survey.survey_rules(client, pack, spans, raw=True, log=lambda m: None)
    assert [r["count"] for r in results] == [0, 4]
    assert "     0      4  ESCU - A - Rule  NEW" in survey.summary(results, pack, 2)


def test_a_missing_pack_is_named():
    with pytest.raises(SystemExit, match="no pack"):
        survey.Pack("nosuch")
