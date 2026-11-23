"""BOTSv3 played from its pack: real-time replay ticks, loop and daily schedules, the rule set.

Ported from the earlier single-dataset BOTSv3 app's tests; the replay must behave the same. The
Windows Security lines are modelled on BOTSv3's classic WinEventLog format.

Tests write settings in the pack's own shape ([replay] or [dataset], [feed:<name>], [rules]);
PackConf turns them into the app's replay_lab.conf stanzas, as build.py does.
"""

import io
import json
import re
import sys
import urllib.parse
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "replay_lab" / "bin"))
sys.path.insert(0, str(REPO))

import build  # noqa: E402
from replaylib import config as config_mod  # noqa: E402
from replaylib import store  # noqa: E402
from replaylib.ledger import LocalLedger  # noqa: E402
from replaylib.runner import Runner as _Runner  # noqa: E402
from replaylib.timeshift import Shifter  # noqa: E402

DATASET = "botsv3"


def Runner(*args, **kwargs):
    return _Runner(*args, dataset=DATASET, **kwargs)


class PackConf:
    """One layer (default or local) of a test app's settings, written in the pack's shape."""

    def __init__(self, app, layer):
        self.target = Path(app) / layer / config_mod.CONF
        self.source = Path(app) / layer / "pack.conf.txt"

    def write_text(self, text):
        text = re.sub(r"^\[replay\]", "[dataset]", text, flags=re.M)
        self.source.parent.mkdir(parents=True, exist_ok=True)
        self.source.write_text(text)
        self.target.write_text(build.pack_stanzas(DATASET, text))

    def read_text(self):
        return self.source.read_text()


def local(saved):
    """The checkpoint ledger over a plain {name: original} dict."""
    return LocalLedger(DATASET, {"rules": saved}, lambda: None)


def data_of(app):
    """Where a test app's export lives: $SPLUNK_HOME/var/lib/replay_lab/botsv3 (see the autouse fixture)."""
    return Path(app).parent / "home" / "var" / "lib" / "replay_lab" / DATASET


@pytest.fixture(autouse=True)
def splunk_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SPLUNK_HOME", str(tmp_path / "home"))


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    """The app as build.py stages it, with every pack."""
    return build.stage(tmp_path_factory.mktemp("built"))


FIRST = 1534723200  # 2018-08-20T00:00:00Z
LAST = FIRST + 2 * 3600 - 1
DAY = 86400


def winsec(t_text, code, extra=""):
    return (f"{t_text}\nLogName=Security\nSourceName=Microsoft Windows security auditing.\n"
            f"EventCode={code}\nEventType=0\nComputerName=FYODOR-L.froth.ly\n{extra}")


# BOTSv3's Windows raw times are a 24-hour clock with an AM/PM suffix; export
# results carry TA_windows' search-time sourcetype, WinEventLog.
EVENTS = [
    {"t": FIRST + 60.0, "raw": winsec("08/19/2018 12:01:00 PM", 4624), "sourcetype": "WinEventLog",
     "source": "WinEventLog:Security", "host": "FYODOR-L"},
    {"t": FIRST + 3700.0, "raw": winsec("08/19/2018 13:01:40 PM", 4720, "Message=A user account was created."),
     "sourcetype": "WinEventLog", "source": "WinEventLog:Security", "host": "FYODOR-L"},
    {"t": FIRST + 7000.0, "raw": winsec("08/19/2018 13:56:40 PM", 4732), "sourcetype": "WinEventLog",
     "source": "WinEventLog:Security", "host": "FYODOR-L"},
]
TEST_CONF = """
[replay]
enabled = 0
index = botsv3_live
source_index = botsv3
tick_seconds = 30
max_catchup_seconds = 3600
anchor =

[feed:wineventlog_security]
search = source="WinEventLog:Security"
set_sourcetype = wineventlog:security

[feed:sysmon]
search = source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
set_sourcetype = xmlwineventlog:microsoft-windows-sysmon/operational
set_source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

[feed:osquery_process]
search = sourcetype="osquery:results" "pack_process-monitoring_proc_events"
set_sourcetype = osquery:results
json_set = columns.event_type=exec

[rules]
names =
"""


def make_app(tmp_path, conf=TEST_CONF):
    app = tmp_path / "app"
    (app / "default").mkdir(parents=True)
    (app / "local").mkdir()
    PackConf(app, "default").write_text(conf)
    return app


OTHER = {"t": FIRST + 120.0, "raw": "Aug 20 00:02:00 host sshd[1]: hi \u00e9", "sourcetype": "syslog",
         "source": "/var/log/secure", "host": "host"}


# --- timestamps inside the raw text ---

def test_every_known_format_moves_by_the_offset_and_keeps_its_shape():
    shifter = Shifter(FIRST, LAST)
    shift = DAY * 3000 + 13 * 3600 + 5  # lands on a different date, afternoon
    raw = ("08/20/2018 12:01:00 AM | 2018-08-20T00:01:00.1234567Z | 2018-08-20 00:01:00 | "
           "Aug 20 00:01:00 | Mon Aug 20 00:01:00 2018 | 1534723260 | 1534723260123 | 1534723260.5")
    out = shifter.shift(raw, shift)
    t = FIRST + 60 + shift
    from datetime import datetime, timezone
    d = datetime.fromtimestamp(t, timezone.utc)
    assert d.strftime("%m/%d/%Y %I:%M:%S %p") in out
    assert d.strftime("%Y-%m-%dT%H:%M:%S") + ".1234567Z" in out
    assert d.strftime("%Y-%m-%d %H:%M:%S") in out
    assert d.strftime("%b %d %H:%M:%S") in out
    assert d.strftime("%a %b %d %H:%M:%S %Y") in out
    assert f"| {t} |" in out and f"{t}123" in out and f"{t}.5" in out
    assert "2018" not in out and "1534" not in out


def test_values_outside_the_dataset_window_are_left_alone():
    shifter = Shifter(FIRST, LAST)
    raw = "built 2016-01-01T00:00:00Z pid=1234567890 size=1534999999999999 on 01/02/2017 03:04:05 PM"
    assert shifter.shift(raw, DAY * 100) == raw


def test_twelve_hour_clock_crosses_noon_and_keeps_its_padding():
    shifter = Shifter(FIRST, LAST)
    assert shifter.shift("08/20/2018 11:30:00 AM", 3600) == "08/20/2018 12:30:00 PM"
    assert shifter.shift("08/20/2018 9:30:00 PM", 3600) == "08/20/2018 10:30:00 PM"


# --- replay ticks ---

@pytest.fixture
def lab(tmp_path):
    app = make_app(tmp_path)
    data = data_of(app)
    count = store.write_feed(data, "wineventlog_security", [dict(e) for e in EVENTS], FIRST)
    store.write_manifest(data, FIRST, LAST, {"wineventlog_security": count})
    return app


def switch(app, on, **extra):
    lines = ["[replay]", f"enabled = {1 if on else 0}"] + [f"{k} = {v}" for k, v in extra.items()]
    PackConf(app, "local").write_text("\n".join(lines) + "\n")


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def emitted(out):
    text = out.getvalue()
    return [{"time": float(m[0]), "index": m[1], "sourcetype": m[2], "source": m[3], "host": m[4], "raw": m[5]}
            for m in re.findall(r"<time>(.*?)</time><index>(.*?)</index><sourcetype>(.*?)</sourcetype>"
                                r"<source>(.*?)</source><host>(.*?)</host><data>(.*?)</data>", text, re.S)]


NOW = 1_794_000_000  # an anchor well after 2018


def make_runner(app, tmp_path, clock, wraps=None, out=None):
    return Runner(app, tmp_path / "checkpoint.json", out or io.StringIO(), now=clock,
                  on_wrap=(wraps.append if wraps is not None else None), sleep=lambda s: None)


def test_events_go_out_when_their_shifted_time_arrives(lab, tmp_path):
    switch(lab, True)
    clock = Clock(NOW)
    runner = make_runner(lab, tmp_path, clock)
    runner.tick()
    clock.t = NOW + 3650
    runner.tick()
    out = emitted(runner.out)

    assert [e["time"] for e in out] == [NOW + 60]
    clock.t = NOW + 3701
    runner.tick()
    out = emitted(runner.out)
    assert [e["time"] for e in out] == [NOW + 60, NOW + 3700]
    assert out[1]["index"] == "botsv3_live" and out[1]["source"] == "WinEventLog:Security"
    assert out[1]["sourcetype"] == "wineventlog:security"  # the indexed name, so TA_windows renames it
    assert out[1]["host"] == "FYODOR-L" and "EventCode=4720" in out[1]["raw"]


def test_the_raw_text_carries_the_new_time_and_no_2018(lab, tmp_path):
    switch(lab, True, max_catchup_seconds=DAY)
    clock = Clock(NOW)
    runner = make_runner(lab, tmp_path, clock)
    runner.tick()
    clock.t = NOW + 7200
    runner.tick()
    from datetime import datetime, timezone
    assert len(emitted(runner.out)) == 3
    for event in emitted(runner.out):
        local = datetime.fromtimestamp(event["time"] - 12 * 3600, timezone.utc)  # the raw clock runs 12 h behind
        stamp = local.strftime("%m/%d/%Y %H:%M:%S ") + ("PM" if local.hour >= 12 else "AM")
        assert event["raw"].startswith(stamp)
        assert "2018" not in event["raw"]


def test_the_gaps_between_events_are_kept(lab, tmp_path):
    switch(lab, True, max_catchup_seconds=DAY)
    clock = Clock(NOW)
    runner = make_runner(lab, tmp_path, clock)
    runner.tick()
    clock.t = NOW + 7200
    runner.tick()
    times = [e["time"] for e in emitted(runner.out)]
    assert [b - a for a, b in zip(times, times[1:])] == [3640.0, 3300.0]


def test_the_loop_wraps_without_a_gap_or_a_duplicate(lab, tmp_path):
    switch(lab, True)
    wraps = []
    clock = Clock(NOW)
    runner = make_runner(lab, tmp_path, clock, wraps)
    runner.tick()
    for step in range(1, 25):  # ticks of 10 minutes across two loops of 2 hours
        clock.t = NOW + step * 600
        runner.tick()
    times = [e["time"] for e in emitted(runner.out)]

    loop = 2 * 3600
    assert times == [NOW + k * loop + d for k in (0, 1) for d in (60, 3700, 7000)]
    assert wraps == [1]  # loop 2 starts exactly at the last tick, so it's in the next window


def test_a_restart_resumes_from_the_checkpoint(lab, tmp_path):
    switch(lab, True)
    clock = Clock(NOW)
    first = make_runner(lab, tmp_path, clock)
    first.tick()
    clock.t = NOW + 100
    first.tick()
    clock.t = NOW + 7200
    second = make_runner(lab, tmp_path, clock)  # new process, same checkpoint
    second.tick()

    assert [e["time"] for e in emitted(first.out)] == [NOW + 60]
    assert [e["time"] for e in emitted(second.out)] == [NOW + 3700, NOW + 7000]


def test_nothing_is_sent_while_switched_off_and_switching_on_starts_from_now(lab, tmp_path):
    switch(lab, True)
    clock = Clock(NOW)
    runner = make_runner(lab, tmp_path, clock)
    runner.tick()
    switch(lab, False)
    clock.t = NOW + 3000
    assert runner.tick() == 0
    switch(lab, True)
    clock.t = NOW + 5000
    runner.tick()
    clock.t = NOW + 7100
    runner.tick()

    assert [e["time"] for e in emitted(runner.out)] == [NOW + 7000]


def test_a_long_outage_is_skipped_not_flooded(lab, tmp_path):
    switch(lab, True, max_catchup_seconds=600)
    clock = Clock(NOW)
    runner = make_runner(lab, tmp_path, clock)
    runner.tick()
    clock.t = NOW + 7100  # down for nearly two hours
    runner.tick()

    assert [e["time"] for e in emitted(runner.out)] == [NOW + 7000]


def test_the_shipped_config_starts_switched_off_and_replays_every_botsv3_sourcetype(built):
    cfg = config_mod.load(built, DATASET)
    indexed = {f.set_sourcetype for f in cfg.feeds}

    assert cfg.enabled is False
    assert {"wineventlog:security", "xmlwineventlog:microsoft-windows-sysmon/operational", "osquery:results",
            "cisco:asa", "stream:dns", "aws:cloudtrail", "access_combined"} <= indexed
    assert len(cfg.feeds) == 107 and "ess_content_importer" not in indexed
    assert all(f.set_sourcetype for f in cfg.feeds)
    windows = [f for f in cfg.feeds if f.set_sourcetype.startswith(("wineventlog", "xmlwineventlog"))]
    assert windows and all(f.search.startswith('source="WinEventLog:') for f in windows)
    assert len(cfg.rules) == 54 and cfg.rules[0] == "@risk_rule"  # 38 from 2018 + 15 from the live re-survey
    assert int(cfg.replay["window_end"]) - int(cfg.replay["window_start"]) == 6.5 * 3600


SAMPLES = sorted((REPO / "tests" / "fixtures" / "botsv3_samples").glob("*.jsonl"))
IN_WINDOW = re.compile(r"Mon, 20 Aug|2018-08-(19|20)[T ]\d|08/(19|20)/2018|20/Aug/2018|20180820 |Aug (19|20) \d\d:"
                       r"|^I08(19|20) |\b153475\d{4}\b|\b15347[6-7]\d{4}\b", re.M)


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda p: p.stem)
def test_real_botsv3_samples_keep_no_in_window_2018_time(sample):
    """Real sample lines, a few per sourcetype covering each timestamp format."""
    shifter = Shifter(1534755600, 1534778999)
    offset = NOW - 1534755600
    for line in sample.read_text().splitlines():
        raw = json.loads(line)["_raw"]
        out = shifter.shift(raw, offset)
        assert not IN_WINDOW.search(out), IN_WINDOW.search(out).group(0)
        assert len(out) >= len(raw) - 2  # formats kept, nothing chopped


def test_windows_24_hour_clock_with_suffix_keeps_its_style():
    shifter = Shifter(1534755600, 1534778999)
    assert shifter.shift("08/19/2018 22:08:17 PM", 3 * 3600) == "08/20/2018 01:08:17 AM"
    assert shifter.shift("08/20/2018 03:18:00 AM", 10 * 3600) == "08/20/2018 13:18:00 PM"


# --- export ---

# --- packaging ---

# --- dashboard ---

def test_the_health_dashboard_has_a_search_in_every_panel(built):
    import xml.etree.ElementTree as ET

    root = ET.parse(built / "default" / "data" / "ui" / "views" / "replay_health.xml").getroot()
    panels = root.findall(".//panel")
    titles = [p.findtext("title") for p in panels]

    assert {"Open findings now (all datasets)", "Findings per hour, by rule (all datasets)",
            "Replayed events per hour, by sourcetype"} <= set(titles)
    assert all((p.findtext(".//search/query") or "").strip() for p in panels)


# --- relabel fixes ---

SYSMON = {"t": FIRST + 30.0, "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational", "source": "WinEventLog:Microsoft-Windows-Sysmon/Operational",
          "host": "FYODOR-L", "raw": "<Event><System><EventID>1</EventID><TimeCreated SystemTime='2018-08-20T00:00:30.123456700Z'/>"
                                     "</System><EventData><Data Name='Image'>C:\\Windows\\cmd.exe</Data></EventData></Event>"}
OSQUERY = {"t": FIRST + 40.0, "sourcetype": "osquery:results", "source": "/var/log/osquery/osqueryd.results.log",
           "host": "hoth", "raw": json.dumps({"name": "pack_process-monitoring_proc_events", "unixTime": FIRST + 40,
                                             "calendarTime": "Mon Aug 20 00:00:40 2018 UTC",
                                             "columns": {"cmdline": "/bin/sh -c id", "pid": "42"}})}


@pytest.fixture
def relabel_lab(tmp_path):
    app = make_app(tmp_path)
    data = data_of(app)
    counts = {"sysmon": store.write_feed(data, "sysmon", [dict(SYSMON)], FIRST),
              "osquery_process": store.write_feed(data, "osquery_process", [dict(OSQUERY)], FIRST)}
    store.write_manifest(data, FIRST, LAST, counts)
    return app


def replay_all(app, tmp_path):
    switch(app, True, max_catchup_seconds=DAY)
    clock = Clock(NOW)
    runner = make_runner(app, tmp_path, clock)
    runner.tick()
    clock.t = NOW + 3600
    runner.tick()
    return {e["sourcetype"]: e for e in emitted(runner.out)}


def test_sysmon_is_replayed_under_the_source_the_sysmon_add_on_expects(relabel_lab, tmp_path):
    out = replay_all(relabel_lab, tmp_path)["xmlwineventlog:microsoft-windows-sysmon/operational"]

    assert out["source"] == "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    assert "2018" not in out["raw"] and ".123456700Z" in out["raw"]


def test_osquery_process_events_get_the_field_their_eventtype_needs(relabel_lab, tmp_path):
    from xml.sax.saxutils import unescape
    out = replay_all(relabel_lab, tmp_path)["osquery:results"]
    doc = json.loads(unescape(out["raw"]))

    assert doc["columns"] == {"cmdline": "/bin/sh -c id", "pid": "42", "event_type": "exec"}
    assert doc["unixTime"] == FIRST + 40 + (NOW - FIRST) and "2018" not in doc["calendarTime"]
    assert "replay_lab_synthetic" not in doc


def test_a_translation_is_opt_in_and_marks_its_events_synthetic(relabel_lab, tmp_path, monkeypatch):
    from replaylib import relabel
    monkeypatch.setitem(relabel.TRANSLATIONS, "dummy", lambda e: {**e, "sourcetype": "dummy:translated"})
    PackConf(relabel_lab, "default").write_text(
        PackConf(relabel_lab, "default").read_text().replace(
            "json_set = columns.event_type=exec", "json_set = columns.event_type=exec\ntranslate = dummy"))
    out = replay_all(relabel_lab, tmp_path)

    assert "osquery:results" not in out
    assert json.loads(out["dummy:translated"]["raw"].replace("&quot;", '"'))["replay_lab_synthetic"] == 1
    assert "replay_lab_synthetic" not in out["xmlwineventlog:microsoft-windows-sysmon/operational"]["raw"]


# --- rule set and reset on loop wrap ---

class FakeRest:
    """The saved-search and search-job endpoints the rule set calls."""

    def __init__(self, searches):
        self.searches = {s["name"]: s for s in searches}  # name -> {name, app, disabled, is_scheduled}
        self.jobs = []
        self.posts = []

    def call(self, method, path, query=None, form=None, timeout=120):
        parts = [urllib.parse.unquote(p) for p in path.split("/") if p]
        if path == "/services/search/jobs":
            self.jobs.append(form["search"])
            return 200, {"results": []}
        if parts[:1] == ["servicesNS"] and parts[3:5] == ["saved", "searches"]:
            if len(parts) == 5 and method == "GET":
                patterns = re.findall(r'name="([^"]+)"', query.get("search", ""))
                hits = [s for s in self.searches.values()
                        if any(re.fullmatch(p.replace("*", ".*"), s["name"].lower()) for p in patterns)]
                return 200, {"entry": [self._entry(s) for s in hits]}
            name = parts[5]
            if name not in self.searches:
                return 404, {}
            search = self.searches[name]
            if method == "GET":
                return 200, {"entry": [self._entry(search)]}
            self.posts.append((name, parts[6] if len(parts) > 6 else dict(form)))
            if len(parts) > 6:
                search["disabled"] = "1" if parts[6] == "disable" else "0"
            for key in ("is_scheduled", "alert.suppress.period", "search", "dispatch.earliest_time",
                        "alert.suppress.fields"):
                if key in form:
                    search[key] = form[key]
            return 200, {}
        return 404, {}

    @staticmethod
    def _entry(s):
        content = {k: v for k, v in s.items() if k not in ("name", "app")}
        return {"name": s["name"], "acl": {"app": s["app"]}, "content": content}


RULES_CONF = """
[rules]
names = ESCU - Detect New Local Admin account - Rule \\
        @risk_rule \\
        ESCU - Already On - Rule
reset_lookups = previously_seen_lookup
reset_searches = | makeresults | eval x=1
"""


@pytest.fixture
def rest():
    return FakeRest([
        {"name": "ESCU - Detect New Local Admin account - Rule", "app": "DA-ESS-ContentUpdate",
         "disabled": "1", "is_scheduled": "0"},
        {"name": "ESCU - Already On - Rule", "app": "DA-ESS-ContentUpdate", "disabled": "0", "is_scheduled": "1"},
        {"name": "Risk - 24 Hour Risk Threshold Exceeded - Rule", "app": "SA-ThreatIntelligence",
         "disabled": "1", "is_scheduled": "1"},
        {"name": "Threat - Findings Risk Threshold Exceeded for Entity Over 24 Hour Period - Rule",
         "app": "SA-ThreatIntelligence", "disabled": "1", "is_scheduled": "0"},
    ])


def rules_runner(app, tmp_path, clock, rest):
    from replaylib.rules import Rules
    return Runner(app, tmp_path / "checkpoint.json", io.StringIO(), now=clock, sleep=lambda s: None,
                  rules=lambda cfg: Rules(rest, cfg.rules, cfg.reset_lookups, cfg.reset_searches,
                                          suppress_period=cfg.suppress_period,
                                          skip_risk_objects=cfg.skip_risk_objects,
                                          risk_earliest=cfg.risk_earliest,
                                          risk_suppress_fields=cfg.risk_suppress_fields))


def test_listed_rules_run_on_their_schedules_while_on_and_go_back_when_off(lab, tmp_path, rest):
    PackConf(lab, "default").write_text(TEST_CONF.split("[rules]")[0] + RULES_CONF)
    switch(lab, True)
    clock = Clock(NOW)
    runner = rules_runner(lab, tmp_path, clock, rest)
    runner.tick()
    s = rest.searches

    assert (s["ESCU - Detect New Local Admin account - Rule"]["disabled"],
            s["ESCU - Detect New Local Admin account - Rule"]["is_scheduled"]) == ("0", "1")
    assert s["Risk - 24 Hour Risk Threshold Exceeded - Rule"]["disabled"] == "0"
    assert s["Threat - Findings Risk Threshold Exceeded for Entity Over 24 Hour Period - Rule"]["disabled"] == "1"
    assert not any(name == "ESCU - Already On - Rule" for name, _ in rest.posts)

    posts = len(rest.posts)
    clock.t = NOW + 60
    runner.tick()
    assert len(rest.posts) == posts  # applied once, not every tick

    # a restart while on remembers the originals, and switching off puts them back
    switch(lab, False)
    clock.t = NOW + 120
    rules_runner(lab, tmp_path, clock, rest).tick()
    assert (s["ESCU - Detect New Local Admin account - Rule"]["disabled"],
            s["ESCU - Detect New Local Admin account - Rule"]["is_scheduled"]) == ("1", "0")
    assert (s["Risk - 24 Hour Risk Threshold Exceeded - Rule"]["disabled"],
            s["Risk - 24 Hour Risk Threshold Exceeded - Rule"]["is_scheduled"]) == ("1", "1")
    assert (s["ESCU - Already On - Rule"]["disabled"], s["ESCU - Already On - Rule"]["is_scheduled"]) == ("0", "1")


def test_state_is_cleared_only_when_the_loop_wraps(lab, tmp_path, rest):
    PackConf(lab, "default").write_text(TEST_CONF.split("[rules]")[0] + RULES_CONF)
    switch(lab, True)
    clock = Clock(NOW)
    runner = rules_runner(lab, tmp_path, clock, rest)
    for step in range(0, 12):  # 10-minute ticks up to just before the first wrap at 2 hours
        clock.t = NOW + step * 600
        runner.tick()
    assert rest.jobs == []
    clock.t = NOW + 2 * 3600 + 30
    runner.tick()

    assert rest.jobs == ["| makeresults | where false() | outputlookup previously_seen_lookup",
                         "| makeresults | eval x=1"]


# --- box setup ---

# --- asset and identity lists ---

def test_the_lists_are_registered_with_es_and_shared_globally(built):
    import configparser
    inputs = configparser.RawConfigParser(strict=False, interpolation=None)
    inputs.read(built / "default" / "inputs.conf")
    meta = (built / "metadata" / "default.meta").read_text()

    assert inputs.get("identity_manager://botsv3_assets", "url") == "lookup://botsv3_assets_lookup"
    assert inputs.get("identity_manager://botsv3_identities", "target") == "identity"
    assert "[lookups]\nexport = system" in meta and "[transforms]\nexport = system" in meta


def test_splunkd_can_discover_and_restart_the_input(built):
    """splunkd skips a modular input whose spec declares no parameter, and stops restarting a
    single-instance one whose spec declares interval or whose instance overrides it."""
    import configparser
    inputs = configparser.RawConfigParser(strict=False, interpolation=None)
    inputs.read(built / "default" / "inputs.conf")
    spec, inside = [], False
    for line in (built / "README" / "inputs.conf.spec").read_text().splitlines():
        line = line.strip()
        if line.startswith("["):
            inside = line == "[replay_lab://<name>]"
        elif inside and line and line[0] not in "*#" and "=" in line:
            spec.append(line.split("=", 1)[0].strip())

    assert "disabled" in spec and "interval" not in spec
    assert inputs.get("replay_lab", "interval") == "60"
    assert not inputs.has_option("replay_lab://botsv3", "interval")
    for stanza in ("replay_lab", "replay_lab://botsv3"):
        assert inputs.get(stanza, "python.version") == "python3"
        assert "3.13" in inputs.get(stanza, "python.required")


def test_a_raw_event_with_bytes_xml_cant_carry_still_makes_a_valid_stream():
    import xml.etree.ElementTree as ET
    from replaylib.runner import event_xml
    text = event_xml({"time": 1.0, "index": "i", "sourcetype": "stream:udp", "source": "s", "host": "h",
                      "raw": "payload\x00\x01<&>\ufffd end"})
    data = ET.fromstring(f"<stream>{text}</stream>").find("event/data").text

    assert data.startswith("payload") and data.endswith("<&>\ufffd end")


# --- in-text times the indexer reads in its own zone ---

FIRST_WINDOW = 1534755600


def test_text_without_a_zone_is_written_in_the_indexers_zone_and_zoned_text_stays_utc():
    from replaylib.timeshift import Shifter
    shift = 1794367183 - FIRST_WINDOW  # 2018-08-20 09:00 UTC lands on 2026-11-11 03:19:43 UTC
    ny = Shifter(FIRST_WINDOW, FIRST_WINDOW + 23400, text_timezone="America/New_York")

    assert ny.shift("08/20/2018 15:00:00 PM LogName=Security", shift) == "11/11/2026 04:19:43 AM LogName=Security"
    assert ny.shift("Aug 20 15:00:01 fw1 %ASA", shift) == "Nov 11 04:19:44 fw1 %ASA"
    assert ny.shift("20180820 15:00:00,rds", shift) == "20261111 04:19:43,rds"
    assert ny.shift("a 2018-08-20 15:00:00 b 2018-08-20T15:00:00Z", shift) == "a 2026-11-11 04:19:43 b 2026-11-11T09:19:43Z"
    assert ny.shift("Mon Aug 20 15:00:00 UTC 2018", shift) == "Wed Nov 11 09:19:43 UTC 2026"
    assert ny.shift("20/Aug/2018:15:00:00 +0000", shift) == "11/Nov/2026:09:19:43 +0000"
    assert Shifter(FIRST_WINDOW, FIRST_WINDOW + 23400).shift("Aug 20 15:00:01 fw1", shift) == "Nov 11 09:19:44 fw1"


def test_the_feeds_splunk_reads_in_local_time_are_set_to_local(built):
    from replaylib import config as config_mod
    feeds = {f.name: f for f in config_mod.load(built, DATASET).feeds}

    for name in ("wineventlog_security", "wineventlog_system", "wineventlog_application", "cisco_asa", "syslog",
                 "aws_rds_audit", "osquery_info", "osquery_warning", "linux_secure", "amazon_ssm_agent",
                 "script_listeningports", "symantec_ep_packet_file", "symantec_ep_agent_file",
                 "symantec_ep_behavior_file", "symantec_ep_traffic_file", "symantec_ep_agt_system_file",
                 "script_getendpointinfo", "script_installedapps", "errors", "errors_too_small",
                 "amazon_ssm_agent_too_small", "wineventlog_microsoft_windows_applocker_exe_and_dll",
                 "wineventlog_microsoft_windows_applocker_packaged_app_execution",
                 "alternatives", "aws_config_rule", "bootstrap", "dpkg", "history_2", "out_3"):
        assert feeds[name].text_timezone == "local", name
    assert all(f.text_timezone == "local" for n, f in feeds.items() if n.startswith(("wineventlog_", "symantec_")))
    assert feeds["xmlwineventlog_microsoft_windows_sysmon_operational"].text_timezone == "utc" and feeds["stream_dns"].text_timezone == "utc"


def _utc(text):
    import calendar
    from datetime import datetime
    return calendar.timegm(datetime.strptime(text, "%Y-%m-%d %H:%M:%S").timetuple())


def test_the_first_zoneless_time_is_anchored_to_the_events_own_time():
    from replaylib.timeshift import Shifter
    shift = 1794367183 - FIRST_WINDOW  # 2018-08-20 09:00 UTC lands on 2026-11-11 03:19:43 UTC
    ny = Shifter(FIRST_WINDOW, FIRST_WINDOW + 23400, text_timezone="America/New_York")

    # Windows, 12 h behind with the wrong suffix: real local 12-hour time, other times in the event move with it
    assert ny.shift("08/20/2018 03:18:00 AM\nLogName=Security x=08/20/2018 03:17:00 AM", shift,
                    _utc("2018-08-20 15:18:00")) == "11/11/2026 04:37:43 AM\nLogName=Security x=11/11/2026 04:36:43 AM"
    assert ny.shift("08/19/2018 22:08:17 PM\nLogName=Security", shift,
                    _utc("2018-08-20 10:08:17")) == "11/10/2026 11:28:00 PM\nLogName=Security"
    # Windows on the right clock
    assert ny.shift("08/20/2018 14:44:00 PM\nLogName=Application", shift,
                    _utc("2018-08-20 14:44:00")) == "11/11/2026 04:03:43 AM\nLogName=Application"
    # a stale first date becomes the event's time
    assert ny.shift("2018-07-25 23:44:23 INFO [instanceID=i-1]", shift,
                    _utc("2018-08-20 15:17:23")) == "2026-11-11 04:37:06 INFO [instanceID=i-1]"
    # zoneless ISO (symantec:ep:traffic:file)
    assert ny.shift("2018-08-20 14:58:39,Info,BGIST-L", shift, _utc("2018-08-20 14:58:39")) == "2026-11-11 04:18:22,Info,BGIST-L"


def test_winhostmon_takes_the_replays_time_at_index_time(built):
    props = (built / "default" / "props.conf").read_text()

    assert re.search(r"^\[WinHostMon\]\nDATETIME_CONFIG = NONE$", props, re.M)
    assert re.search(r"^\[XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\]\nDATETIME_CONFIG = NONE$", props, re.M)


# --- loop-wrap state: throttles and who's minute times ---

def test_a_rule_that_throttles_longer_than_a_loop_is_shortened_while_on_and_put_back():
    from replaylib.rules import Rules
    rest = FakeRest([
        {"name": "Risk - 24 Hour Risk Threshold Exceeded - Rule", "app": "SA-ThreatIntelligence", "disabled": "0",
         "is_scheduled": "1", "alert.suppress": "1", "alert.suppress.period": "86400s"},
        {"name": "ESCU - Short - Rule", "app": "DA-ESS-ContentUpdate", "disabled": "1", "is_scheduled": "0",
         "alert.suppress": "1", "alert.suppress.period": "3600"},
    ])
    rules = Rules(rest, ["@risk_rule", "ESCU - Short - Rule"], suppress_period="21600")
    saved = {}
    list(rules.enable(local(saved), DATASET))
    risk = rest.searches["Risk - 24 Hour Risk Threshold Exceeded - Rule"]

    assert risk["alert.suppress.period"] == "21600s" and risk["disabled"] == "0"
    assert rest.searches["ESCU - Short - Rule"]["alert.suppress.period"] == "3600"
    assert list(rules.enable(local(saved), DATASET)) == []  # already shortened: no more changes

    list(rules.put_back(local(saved), DATASET))
    assert risk["alert.suppress.period"] == "86400s" and risk["disabled"] == "0" and risk["is_scheduled"] == "1"
    assert rest.searches["ESCU - Short - Rule"]["disabled"] == "1" and saved == {}


def test_the_shipped_rules_clear_the_service_baseline_and_keep_es_throttles(built):
    from replaylib import config as config_mod
    cfg = config_mod.load(built, DATASET)

    assert cfg.reset_lookups == ["previously_seen_running_windows_services"]
    # daily: the risk rule sums the workday (8 h) and throttles 20 h, so findings come in work hours
    assert (cfg.risk_earliest, cfg.suppress_period) == ("-490m@m", "72000")
    assert cfg.risk_suppress_fields == "normalized_risk_object,risk_object_type"  # one finding per entity a day


def test_dated_times_before_the_window_and_minute_times_move_too():
    from replaylib.timeshift import Shifter
    shift = 1794367183 - FIRST_WINDOW
    utc = Shifter(FIRST_WINDOW, FIRST_WINDOW + 23400)

    assert utc.shift("root pts/0 2018-08-17 14:03 (192.0.2.1)", shift) == "root pts/0 2026-11-08 08:22 (192.0.2.1)"
    assert utc.shift("x 2018-08-20 15:00:00 y", shift) == "x 2026-11-11 09:19:43 y"
    assert utc.shift("Aug 10 15:00:01 host", shift) == "Aug 10 15:00:01 host"  # no year: window only


def test_a_new_suppress_period_reaches_a_replay_that_is_already_on(lab, tmp_path, rest):
    conf = PackConf(lab, "default")
    conf.write_text(TEST_CONF.split("[rules]")[0] + RULES_CONF)
    risk = rest.searches["Risk - 24 Hour Risk Threshold Exceeded - Rule"]
    risk.update({"alert.suppress": "1", "alert.suppress.period": "86400s"})
    switch(lab, True)
    clock = Clock(NOW)
    rules_runner(lab, tmp_path, clock, rest).tick()
    assert risk["alert.suppress.period"] == "86400s"

    conf.write_text(conf.read_text() + "suppress_period = 21600\n")  # an upgrade adds the setting
    clock.t = NOW + 60
    rules_runner(lab, tmp_path, clock, rest).tick()
    assert risk["alert.suppress.period"] == "21600s" and risk["disabled"] == "0"

    switch(lab, False)
    clock.t = NOW + 120
    rules_runner(lab, tmp_path, clock, rest).tick()
    assert risk["alert.suppress.period"] == "86400s" and risk["disabled"] == "1"


def test_the_replay_keeps_the_exact_case_the_export_wrote():
    from replaylib.config import Feed
    from replaylib.engine import Engine

    class Data:
        first, last, loop_seconds, feeds = FIRST, LAST, 3600, {"w": 1}
    engine = Engine(Data(), [Feed("w", {"search": "x", "set_sourcetype": "wineventlog:security"})], "botsv3_live", NOW)
    out = engine._rewrite("w", {"t": FIRST, "raw": "r", "sourcetype": "WinEventLog:Security",
                                "source": "WinEventLog:Security", "host": "h"}, 0)

    assert out["sourcetype"] == "WinEventLog:Security"


# --- placeholder risk objects ---

RISK_SPL = "| tstats sum(All_Risk.calculated_risk_score) as risk_score from datamodel=Risk.All_Risk | where risk_score>100"


def test_the_risk_rule_skips_findings_on_placeholder_entities_while_on_and_is_put_back():
    from replaylib.rules import Rules
    rest = FakeRest([
        {"name": "Risk - 24 Hour Risk Threshold Exceeded - Rule", "app": "SA-ThreatIntelligence", "disabled": "0",
         "is_scheduled": "1", "search": RISK_SPL},
        {"name": "ESCU - Other - Rule", "app": "DA-ESS-ContentUpdate", "disabled": "1", "is_scheduled": "0",
         "search": "| tstats count"},
    ])
    rules = Rules(rest, ["@risk_rule", "ESCU - Other - Rule"], skip_risk_objects=["unknown", "null"])
    saved = {}
    list(rules.enable(local(saved), DATASET))
    risk = rest.searches["Risk - 24 Hour Risk Threshold Exceeded - Rule"]

    assert risk["search"].startswith(RISK_SPL + " | where NOT lower(coalesce(risk_object, normalized_risk_object")
    assert 'IN ("unknown", "null")' in risk["search"]
    assert rest.searches["ESCU - Other - Rule"]["search"] == "| tstats count"  # only the risk rule
    assert list(rules.enable(local(saved), DATASET)) == []  # already filtered: no more changes

    list(rules.put_back(local(saved), DATASET))
    assert risk["search"] == RISK_SPL and risk["disabled"] == "0" and saved == {}


def test_skip_risk_objects_reaches_a_replay_that_is_already_on(lab, tmp_path, rest):
    conf = PackConf(lab, "default")
    conf.write_text(TEST_CONF.split("[rules]")[0] + RULES_CONF)
    risk = rest.searches["Risk - 24 Hour Risk Threshold Exceeded - Rule"]
    risk["search"] = RISK_SPL
    switch(lab, True)
    clock = Clock(NOW)
    rules_runner(lab, tmp_path, clock, rest).tick()
    assert risk["search"] == RISK_SPL

    conf.write_text(conf.read_text() + "skip_risk_objects = unknown, null\n")  # an upgrade adds the setting
    clock.t = NOW + 60
    rules_runner(lab, tmp_path, clock, rest).tick()
    assert "replay_lab: skip_risk_objects" in risk["search"] and risk["disabled"] == "0"

    switch(lab, False)
    clock.t = NOW + 120
    rules_runner(lab, tmp_path, clock, rest).tick()
    assert risk["search"] == RISK_SPL and risk["disabled"] == "1"


def test_the_shipped_rules_skip_unknown_and_null_risk_objects(built):
    from replaylib import config as config_mod
    assert config_mod.load(built, DATASET).skip_risk_objects == ["unknown", "null"]


# --- daily schedule: one workday a day at real speed ---

from datetime import datetime as _dt  # noqa: E402
from zoneinfo import ZoneInfo  # noqa: E402

EASTERN = ZoneInfo("America/New_York")


def et(y, mo, d, h=9, mi=0):
    return int(_dt(y, mo, d, h, mi, tzinfo=EASTERN).timestamp())


def daily(app, **extra):
    switch(app, True, schedule="daily", daily_start="09:00", schedule_timezone="America/New_York", **extra)


def run_ticks(runner, clock, start, end, step=600):
    t = start
    while t <= end:
        clock.t = t
        runner.tick()
        t += step


def test_the_daily_schedule_plays_the_window_from_9_am_et_and_is_idle_otherwise(lab, tmp_path):
    daily(lab)
    wraps, statuses = [], []
    clock = Clock(et(2026, 11, 12, 8))
    runner = Runner(lab, tmp_path / "checkpoint.json", io.StringIO(), now=clock, sleep=lambda s: None,
                    on_wrap=wraps.append, status=statuses.append)
    run_ticks(runner, clock, et(2026, 11, 12, 8), et(2026, 11, 13, 12))
    times = [e["time"] for e in emitted(runner.out)]

    assert times == [day + d for day in (et(2026, 11, 12), et(2026, 11, 13)) for d in (60, 3700, 7000)]
    assert wraps == [0, 1]  # each day's start, once
    at = {s["at"]: s for s in statuses if s.get("state") == "on"}
    assert at[et(2026, 11, 12, 10)]["playing"] is True and at[et(2026, 11, 12, 10)]["mode"] == "daily"
    idle = at[et(2026, 11, 12, 20)]
    assert idle["playing"] is False and idle["loop"] == 0 and idle["next_start"] == et(2026, 11, 13)
    assert at[et(2026, 11, 13, 10)]["loop"] == 1


def test_the_daily_start_stays_at_9_am_local_across_daylight_saving_changes(lab, tmp_path, monkeypatch):
    for days in (((2027, 3, 13), (2027, 3, 14), (2027, 3, 15)), ((2026, 10, 31), (2026, 11, 1), (2026, 11, 2))):
        app = make_app(tmp_path / str(days[0][1]))
        monkeypatch.setenv("SPLUNK_HOME", str(app.parent / "home"))
        count = store.write_feed(data_of(app), "wineventlog_security", [dict(EVENTS[0])], FIRST)
        store.write_manifest(data_of(app), FIRST, LAST, {"wineventlog_security": count})
        daily(app)
        clock = Clock(et(*days[0], 8))
        runner = make_runner(app, tmp_path / str(days[0][1]), clock)
        run_ticks(runner, clock, et(*days[0], 8), et(*days[2], 12), step=1800)

        assert [e["time"] for e in emitted(runner.out)] == [et(*d) + 60 for d in days]


def test_switching_on_mid_workday_starts_at_the_matching_point_in_the_day(lab, tmp_path):
    daily(lab)
    clock = Clock(et(2026, 11, 12, 9, 30))
    runner = make_runner(lab, tmp_path, clock)
    run_ticks(runner, clock, et(2026, 11, 12, 9, 30), et(2026, 11, 12, 12))

    assert [e["time"] for e in emitted(runner.out)] == [et(2026, 11, 12) + 3700, et(2026, 11, 12) + 7000]


def test_a_gap_overnight_longer_than_the_catch_up_limit_skips_ahead(lab, tmp_path):
    daily(lab, max_catchup_seconds=1800)
    clock = Clock(et(2026, 11, 12, 12))
    runner = make_runner(lab, tmp_path, clock)
    runner.tick()
    clock.t = et(2026, 11, 13, 10, 30)  # Splunk was down from noon until 10:30 the next day
    runner.tick()

    assert [e["time"] for e in emitted(runner.out)] == [et(2026, 11, 13) + 3700]  # 9:01 was skipped


# --- daily as the shipped default, and the upgrade from the loop ---

def test_the_shipped_replay_plays_daily_at_9_am_eastern(built):
    cfg = config_mod.load(built, DATASET)

    assert (cfg.replay["schedule"], cfg.replay["daily_start"], cfg.replay["schedule_timezone"]) == (
        "daily", "09:00", "America/New_York")
    assert cfg.skip_risk_objects == ["unknown", "null"]
    version = (REPO / "VERSION").read_text().strip()
    assert re.search(rf"^version = {re.escape(version)}$", (built / "default" / "app.conf").read_text(), re.M)


def test_a_looping_replay_moves_to_daily_without_a_burst_or_a_duplicate(lab, tmp_path):
    switch(lab, True)  # loop mode, anchored at 8:58 ET
    clock = Clock(et(2026, 11, 12, 8, 58))
    runner = make_runner(lab, tmp_path, clock)
    run_ticks(runner, clock, et(2026, 11, 12, 8, 58), et(2026, 11, 12, 9, 8))
    before = [e["time"] for e in emitted(runner.out)]
    assert before == [et(2026, 11, 12, 8, 58) + 60]  # the loop sent its 8:59 event

    daily(lab)  # the upgrade: same checkpoint, new schedule
    after_runner = make_runner(lab, tmp_path, clock)
    run_ticks(after_runner, clock, et(2026, 11, 12, 9, 18), et(2026, 11, 12, 12))
    after = [e["time"] for e in emitted(after_runner.out)]

    assert after == [et(2026, 11, 12) + 3700, et(2026, 11, 12) + 7000]  # nothing re-sent, nothing flushed
    assert set(before).isdisjoint(after)


def test_dropping_suppress_period_on_upgrade_puts_the_24_hour_throttle_back(lab, tmp_path, rest):
    conf = PackConf(lab, "default")
    conf.write_text(TEST_CONF.split("[rules]")[0] + RULES_CONF + "suppress_period = 21600\nskip_risk_objects = unknown, null\n")
    risk = rest.searches["Risk - 24 Hour Risk Threshold Exceeded - Rule"]
    risk.update({"alert.suppress": "1", "alert.suppress.period": "86400s", "search": RISK_SPL,
                 "action.notable": "1"})
    switch(lab, True)
    clock = Clock(NOW)
    rules_runner(lab, tmp_path, clock, rest).tick()
    assert risk["alert.suppress.period"] == "21600s" and "skip_risk_objects" in risk["search"]

    conf.write_text(conf.read_text().replace("suppress_period = 21600\n", ""))  # an earlier version shipped none
    clock.t = NOW + 60
    rules_runner(lab, tmp_path, clock, rest).tick()

    assert risk["alert.suppress.period"] == "86400s"
    assert risk["search"].startswith(RISK_SPL) and "skip_risk_objects" in risk["search"]
    assert risk["disabled"] == "0"


def test_the_lab_never_changes_a_rules_alert_actions(lab, tmp_path, rest):
    PackConf(lab, "default").write_text(
        TEST_CONF.split("[rules]")[0] + RULES_CONF + "skip_risk_objects = unknown, null\n")
    rule = rest.searches["ESCU - Detect New Local Admin account - Rule"]
    rule.update({"action.notable": "0", "action.risk": "1"})  # J's intermediate-findings-only change
    switch(lab, True)
    clock = Clock(NOW)
    rules_runner(lab, tmp_path, clock, rest).tick()
    switch(lab, False)
    clock.t = NOW + 60
    rules_runner(lab, tmp_path, clock, rest).tick()

    assert (rule["action.notable"], rule["action.risk"]) == ("0", "1")
    changed = {key for _, form in rest.posts if isinstance(form, dict) for key in form}
    assert not any(key.startswith("action.") for key in changed)


# --- dashboard shows the schedule ---

def test_the_status_line_names_the_next_start_in_the_schedules_zone(lab, tmp_path):
    daily(lab)
    statuses = []
    clock = Clock(et(2026, 11, 12, 20))
    Runner(lab, tmp_path / "checkpoint.json", io.StringIO(), now=clock, sleep=lambda s: None,
           status=statuses.append).tick()

    assert statuses[-1]["next_start_text"] == "2026-11-13 09:00 EST"


def test_the_health_dashboard_shows_the_schedule_from_fields_the_tick_writes(lab, tmp_path, built):
    import xml.etree.ElementTree as ElementTree

    root = ElementTree.parse(built / "default" / "data" / "ui" / "views" / "replay_health.xml").getroot()
    panel = next(p for p in root.findall(".//panel") if p.findtext("title") == "Replay schedule (last tick)")
    query = panel.findtext(".//search/query")
    daily(lab)
    statuses = []
    clock = Clock(et(2026, 11, 12, 10))
    Runner(lab, tmp_path / "checkpoint.json", io.StringIO(), now=clock, sleep=lambda s: None,
           status=statuses.append).tick()

    for field in ("mode", "playing", "loop", "next_start_text"):
        assert field in query and field in statuses[-1]


# --- review fixes: bad schedule settings, and resets across downtime ---

@pytest.mark.parametrize("setting", [{"schedule_timezone": "US/Eastrn"}, {"daily_start": "09:00:00"},
                                     {"daily_start": "9h"}, {"schedule": "weekly"}])
def test_a_bad_schedule_setting_is_reported_and_changes_no_rules(lab, tmp_path, rest, setting):
    PackConf(lab, "default").write_text(TEST_CONF.split("[rules]")[0] + RULES_CONF)
    switch(lab, True, **{"schedule": "daily", "daily_start": "09:00", "schedule_timezone": "America/New_York",
                         **setting})
    statuses = []
    from replaylib.rules import Rules
    runner = Runner(lab, tmp_path / "checkpoint.json", io.StringIO(), now=Clock(et(2026, 11, 12, 10)),
                    sleep=lambda s: None, status=statuses.append,
                    rules=lambda cfg: Rules(rest, cfg.rules, cfg.reset_lookups, cfg.reset_searches))

    assert runner.tick() == 0
    assert "config_error" in statuses[-1] and rest.posts == []


def test_a_day_start_inside_skipped_downtime_still_resets_the_rules_state(lab, tmp_path, rest):
    PackConf(lab, "default").write_text(TEST_CONF.split("[rules]")[0] + RULES_CONF)
    daily(lab, max_catchup_seconds=1800)
    clock = Clock(et(2026, 11, 12, 12))
    runner = rules_runner(lab, tmp_path, clock, rest)
    runner.tick()
    clock.t = et(2026, 11, 14, 10, 30)  # down over two day starts; catch-up only reaches back to 10:00
    runner.tick()

    assert rest.jobs == ["| makeresults | where false() | outputlookup previously_seen_lookup",
                         "| makeresults | eval x=1"]  # once, not once per missed day


# --- leftover future-dated feeds ---

@pytest.mark.parametrize("sourcetype", ["aws:config:rule", "aws:rds:error", "code42:security", "code42:computer",
                                        "code42:user"])
def test_feeds_splunk_misdates_take_the_replays_time_at_index_time(sourcetype, built):
    # residual-ts-samples.md: Splunk ignores aws:config:rule's "+00:00" and reads aws:rds:error's zoneless UTC
    # as local (5 h ahead); for code42 it picks a later time (modular_input_consumption_time, lastConnected).
    props = (built / "default" / "props.conf").read_text()

    assert re.search(rf"^\[{re.escape(sourcetype)}\]\nDATETIME_CONFIG = NONE$", props, re.M)



# --- risk rule sums the workday while the replay is on ---

def test_the_risk_rule_sums_the_workday_while_on_and_gets_its_window_back():
    from replaylib.rules import Rules
    rest = FakeRest([
        {"name": "Risk - 24 Hour Risk Threshold Exceeded - Rule", "app": "SA-ThreatIntelligence", "disabled": "0",
         "is_scheduled": "1", "alert.suppress": "1", "alert.suppress.period": "86400s",
         "dispatch.earliest_time": "-24h", "search": RISK_SPL},
        {"name": "ESCU - Other - Rule", "app": "DA-ESS-ContentUpdate", "disabled": "1", "is_scheduled": "0",
         "dispatch.earliest_time": "-70m@m"},
    ])
    rules = Rules(rest, ["@risk_rule", "ESCU - Other - Rule"], suppress_period="72000", risk_earliest="-8h")
    saved = {}
    list(rules.enable(local(saved), DATASET))
    risk = rest.searches["Risk - 24 Hour Risk Threshold Exceeded - Rule"]

    assert (risk["dispatch.earliest_time"], risk["alert.suppress.period"]) == ("-8h", "72000s")
    assert rest.searches["ESCU - Other - Rule"]["dispatch.earliest_time"] == "-70m@m"  # only the risk rule
    assert list(rules.enable(local(saved), DATASET)) == []  # already applied: no more changes

    list(rules.put_back(local(saved), DATASET))
    assert (risk["dispatch.earliest_time"], risk["alert.suppress.period"]) == ("-24h", "86400s") and saved == {}


def test_a_new_risk_window_reaches_a_replay_that_is_already_on(lab, tmp_path, rest):
    conf = PackConf(lab, "default")
    conf.write_text(TEST_CONF.split("[rules]")[0] + RULES_CONF)
    risk = rest.searches["Risk - 24 Hour Risk Threshold Exceeded - Rule"]
    risk["dispatch.earliest_time"] = "-24h"
    switch(lab, True)
    clock = Clock(NOW)
    rules_runner(lab, tmp_path, clock, rest).tick()
    assert risk["dispatch.earliest_time"] == "-24h"

    conf.write_text(conf.read_text() + "risk_earliest = -8h\n")  # an upgrade adds the setting
    clock.t = NOW + 60
    rules_runner(lab, tmp_path, clock, rest).tick()
    assert risk["dispatch.earliest_time"] == "-8h"

    switch(lab, False)
    clock.t = NOW + 120
    rules_runner(lab, tmp_path, clock, rest).tick()
    assert risk["dispatch.earliest_time"] == "-24h"



# --- one risk finding per entity per day ---

def test_the_risk_rule_throttles_by_entity_only_while_on_and_gets_its_fields_back(lab, tmp_path, rest):
    conf = PackConf(lab, "default")
    conf.write_text(TEST_CONF.split("[rules]")[0] + RULES_CONF
                    + "risk_suppress_fields = normalized_risk_object,risk_object_type\n")
    risk = rest.searches["Risk - 24 Hour Risk Threshold Exceeded - Rule"]
    es_fields = "source_count,normalized_risk_object,risk_object_type"
    risk["alert.suppress.fields"] = es_fields
    other = rest.searches["ESCU - Already On - Rule"]
    other["alert.suppress.fields"] = "dest"
    switch(lab, True)
    clock = Clock(NOW)
    rules_runner(lab, tmp_path, clock, rest).tick()

    assert risk["alert.suppress.fields"] == "normalized_risk_object,risk_object_type"
    assert other["alert.suppress.fields"] == "dest"  # only the risk rule

    switch(lab, False)
    clock.t = NOW + 60
    rules_runner(lab, tmp_path, clock, rest).tick()
    assert risk["alert.suppress.fields"] == es_fields


# --- run_on, rules mode and data_dir: one package for a standalone box or a search head cluster ---

def _set(lab, text):
    (lab / "local").mkdir(exist_ok=True)
    PackConf(lab, "local").write_text(text)


def test_rules_mode_none_sends_data_and_puts_back_rules_from_an_earlier_escu_run(lab, tmp_path):
    class FakeRules:
        def __init__(self):
            self.calls = []

        def enable(self, ledger, dataset):
            self.calls.append("enable")
            ledger.saved["ESCU - X"] = {"app": "a", "disabled": "1"}
            yield

        def put_back(self, ledger, dataset):
            self.calls.append("put_back")
            ledger.saved.clear()
            yield

        def reset(self, k):
            self.calls.append("reset")

    fake = FakeRules()
    clock = Clock(NOW)
    _set(lab, "[replay]\nenabled = 1\n")
    runner = make_runner(lab, tmp_path, clock)
    runner.rules = lambda cfg: fake
    runner.tick()
    assert fake.calls == ["enable"]  # escu (the default): rules switched on

    _set(lab, "[replay]\nenabled = 1\n[rules]\nmode = none\n")
    clock.t += 30
    sent = runner.tick()
    assert fake.calls == ["enable", "put_back"]  # none: what escu switched on goes back...
    clock.t += 30
    runner.tick()
    assert fake.calls == ["enable", "put_back"]  # ...once, and nothing touches rules after that
    assert sent >= 0 and config_mod.load(lab, DATASET).rules_mode == "none"


def test_a_bad_rules_mode_is_refused(lab):
    _set(lab, "[rules]\nmode = falcon\n")
    with pytest.raises(ValueError):
        config_mod.load(lab, DATASET)


def test_run_on_another_server_keeps_this_one_on_standby(lab, tmp_path):
    _set(lab, "[replay]\nenabled = 1\nrun_on = sh2\n")
    clock = Clock(NOW)
    statuses = []
    runner = make_runner(lab, tmp_path, clock)
    runner.server_name = "sh1"
    runner.status = statuses.append
    assert runner.tick() == 0
    assert statuses[-1]["state"] == "standby" and statuses[-1]["run_on"] == "sh2"
    runner.server_name = "SH2.example.com"  # splunkd passes the host name, not the serverName
    statuses.clear()
    runner.tick()
    assert statuses and statuses[-1]["state"] != "standby"


def test_data_dir_outside_the_app_is_used_by_the_runner(lab, tmp_path, monkeypatch):
    monkeypatch.setenv("SPLUNK_HOME", str(tmp_path / "home"))
    _set(lab, "[replay]\ndata_dir = $SPLUNK_HOME/var/lib/replay_lab/elsewhere\n")
    cfg = config_mod.load(lab, DATASET)
    assert config_mod.data_dir(cfg.replay, lab) == tmp_path / "home" / "var/lib/replay_lab/elsewhere"


# --- Falcon Search fixes in the setup script (fillnull, entity_zone, index macros) ---

