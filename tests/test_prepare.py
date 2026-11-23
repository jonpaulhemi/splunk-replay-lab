"""Prepare dataset, engine side: export, setup with undo, asset lists, and requests from the page.

FakeSplunkd answers the searches the export and the asset hooks run, and the REST endpoints setup
reads and writes (CIM and Falcon Search macros, data models, roles, apps, lookup files).
"""

import io
import json
import re
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "replay_lab" / "bin"))
sys.path.insert(0, str(REPO))

import build  # noqa: E402
from replaylib import assets as assets_mod  # noqa: E402
from replaylib import config as config_mod  # noqa: E402
from replaylib import export as export_mod  # noqa: E402
from replaylib import prepare  # noqa: E402
from replaylib import setup as setup_mod  # noqa: E402
from replaylib import store  # noqa: E402
from replaylib.config import Feed  # noqa: E402
from replaylib.runner import Runner  # noqa: E402

FIRST = 1534755600
QUIET = lambda *a: None  # noqa: E731

PACK = """
[dataset]
enabled = 0
index = alpha_live
source_index = alpha
requires = Splunk_SA_CIM, Splunk_TA_missing
window_start = {start}
window_end = {end}
{extra}

[feed:security]
search = source="WinEventLog:Security"
set_sourcetype = wineventlog:security

[feed:syslog]
search = sourcetype="syslog"
set_sourcetype = syslog
"""


def make_app(tmp_path, name="alpha", start=FIRST, end=FIRST + 7200, extra=""):
    app = tmp_path / "app"
    (app / "default").mkdir(parents=True, exist_ok=True)
    (app / "local").mkdir(exist_ok=True)
    text = PACK.format(start=start, end=end, extra=extra).replace("alpha", name)
    conf = app / "default" / config_mod.CONF
    conf.write_text((conf.read_text() if conf.exists() else "") + build.pack_stanzas(name, text))
    return app


@pytest.fixture(autouse=True)
def splunk_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SPLUNK_HOME", str(tmp_path / "home"))


def event(t, raw, source, sourcetype, host="host1", cd=None):
    return {"epoch": str(t), "_raw": raw, "_cd": cd or f"0:{t}:{raw}", "source": source,
            "sourcetype": sourcetype, "host": host}


class FakeSplunkd:
    def __init__(self, events=()):
        self.events = list(events)  # in the source index
        self.answers = {}  # search substring -> rows (asset hooks)
        self.conf = {
            "Splunk_SA_CIM/macros": {
                "cim_Authentication_indexes": {"definition": "(index=alpha)"},
                "cim_Network_indexes": {"definition": "()"},
                "cim_Other_indexes": {"definition": "(index=beta_live)"},
                "other_macro": {"definition": "(index=alpha)"},
            },
            "Splunk_SA_CIM/datamodels": {
                "Authentication": {"acceleration": "1", "acceleration.earliest_time": "-1y"},
                "Endpoint": {"acceleration": "0", "acceleration.earliest_time": ""},
                "Risk": {"acceleration": "1", "acceleration.earliest_time": "-1y", "_app": "SA-ThreatIntelligence"},
            },
            "FalconSearch/macros": {
                "fs_Windows_index": {"definition": "index=wineventlog"},
                "fs_Any_index": {"definition": "index=*"},
                "fs_Risk_index": {"definition": 'index IN ("risk","notable")'},
            },
            "DA-ESS-ContentUpdate/macros": {"summariesonly_config": {"definition": "summariesonly=false"}},
        }
        self.roles = {"admin": {"srchIndexesDefault": ["main"]}, "analyst": {"srchIndexesAllowed": ["main"]}}
        self.apps = {"Splunk_SA_CIM": {"disabled": "0"}, "Splunk_TA_off": {"disabled": "1"}}
        self.lookups = {}
        self.posts = []

    # -- searches --

    def export(self, search, earliest="0", latest="+10y"):
        for key, rows in self.answers.items():
            if key in search:
                return iter(rows)
        lo, hi = float(earliest), (float(latest) if latest != "+10y" else 1e12)
        inside = [e for e in self.events if lo <= float(e["epoch"]) < hi]
        if search.startswith("| tstats min(_time)"):
            times = [float(e["epoch"]) for e in self.events]
            return iter([{"first": str(min(times)), "last": str(max(times))}] if times else [{}])
        if search.startswith("| tstats count where"):
            return iter([{"count": str(len(inside))}])
        if search.startswith("| metadata type=sourcetypes"):
            return iter([{"sourcetype": s} for s in sorted({e["sourcetype"] for e in self.events})])
        match = re.match(r"search index=\w+ (.*?) \| eval epoch", search)
        if match:
            clause = match.group(1)
            key, _, value = clause.partition("=")
            return iter([dict(e) for e in inside if e[key.strip()] == value.strip('"')])
        return iter([])

    # -- REST --

    @staticmethod
    def _entries(items, app):
        return {"entry": [{"name": name, "content": {k: v for k, v in c.items() if k != "_app"},
                           "acl": {"app": c.get("_app", app)}} for name, c in items.items()]}

    def call(self, method, path, query=None, form=None, timeout=120, body=None):
        m = re.match(r"/servicesNS/nobody/([\w-]+)/configs/conf-(\w+)(?:/(.+))?$", path)
        if m:
            app, kind, name = m.groups()
            items = self.conf.get(f"{app}/{kind}")
            if items is None:
                return 404, {}
            if name is None:
                return 200, self._entries(items, app)
            name = re.sub(r"%([0-9A-F]{2})", lambda x: chr(int(x.group(1), 16)), name)
            if name not in items:
                return 404, {}
            if method == "POST":
                self.posts.append((path, dict(form)))
                items[name].update(form)
            return 200, self._entries({name: items[name]}, app)
        m = re.match(r"/services/authorization/roles/(\w+)$", path)
        if m:
            role = self.roles.get(m.group(1))
            if role is None:
                return 404, {}
            if method == "POST":
                self.posts.append((path, dict(form)))
                role.update({k: [i for i in v if i] for k, v in form.items()})
            return 200, {"entry": [{"name": m.group(1), "content": role}]}
        m = re.match(r"/services/apps/local/([\w-]+)$", path)
        if m:
            app = self.apps.get(m.group(1))
            return (200, {"entry": [{"name": m.group(1), "content": app}]}) if app else (404, {})
        m = re.match(r"/servicesNS/nobody/replay_lab/data/lookup-table-files(?:/(.+))?$", path)
        if m:
            name = m.group(1) or form.get("name")
            if m.group(1) and name not in self.lookups:
                return 404, {}
            self.lookups[name] = Path(form["eai:data"]).read_text()
            return (200 if m.group(1) else 201), {}
        raise AssertionError(f"unexpected {method} {path}")


def cfg_of(app, name="alpha"):
    return config_mod.load(app, name)


EVENTS = [
    event(FIRST + 60, "logon", "WinEventLog:Security", "WinEventLog"),
    event(FIRST + 4000, "logoff", "WinEventLog:Security", "WinEventLog"),
    event(FIRST + 100, "sshd ok", "/var/log/secure", "syslog"),
    event(FIRST + 9000, "after the window", "/var/log/secure", "syslog"),
]


# --- export ---

def test_the_export_writes_each_feed_in_the_window_and_the_replay_can_open_it(tmp_path):
    app = make_app(tmp_path)
    manifest = export_mod.export(FakeSplunkd(EVENTS), cfg_of(app), log=QUIET)

    folder = config_mod.data_dir(cfg_of(app).replay)
    assert manifest["feeds"] == {"security": 2, "syslog": 1}
    assert manifest["loop_seconds"] == 7200
    [data] = store.open_all(folder)
    assert data.first == FIRST and data.feeds == {"security": 2, "syslog": 1}
    # the indexed (exact-case) name, taken from the source, not the search-time rename
    rows = [json.loads(line) for line in __import__("gzip").open(folder / "security" / "00000.jsonl.gz")]
    assert rows[0]["sourcetype"] == "WinEventLog:Security"


def test_an_empty_source_index_fails_and_keeps_the_previous_export(tmp_path):
    app = make_app(tmp_path)
    export_mod.export(FakeSplunkd(EVENTS), cfg_of(app), log=QUIET)
    folder = config_mod.data_dir(cfg_of(app).replay)
    before = (folder / "manifest.json").read_text()

    with pytest.raises(export_mod.ExportError, match="load the dataset"):
        export_mod.export(FakeSplunkd([]), cfg_of(app), log=QUIET)

    assert (folder / "manifest.json").read_text() == before
    assert not folder.with_name(folder.name + ".new").exists()


def test_a_failed_export_leaves_the_previous_one_in_place(tmp_path):
    app = make_app(tmp_path)
    export_mod.export(FakeSplunkd(EVENTS), cfg_of(app), log=QUIET)
    folder = config_mod.data_dir(cfg_of(app).replay)
    split = EVENTS + [event(FIRST + 61, "row 2", "WinEventLog:Security", "WinEventLog", cd=EVENTS[0]["_cd"])]

    with pytest.raises(export_mod.ExportError, match="KV_MODE = none"):
        export_mod.export(FakeSplunkd(split), cfg_of(app), log=QUIET)

    assert store.open_all(folder)[0].feeds == {"security": 2, "syslog": 1}


def test_segments_export_one_folder_each(tmp_path):
    seg = f"{FIRST}-{FIRST + 3600},{FIRST + 3600}-{FIRST + 7200}"
    app = make_app(tmp_path, extra=f"segments = {seg}")
    export_mod.export(FakeSplunkd(EVENTS), cfg_of(app), log=QUIET)

    data = store.open_all(config_mod.data_dir(cfg_of(app).replay))
    assert [d.feeds for d in data] == [{"security": 1, "syslog": 1}, {"security": 1, "syslog": 0}]
    assert all(d.loop_seconds == 3600 for d in data)


def test_without_a_window_the_export_takes_the_whole_index(tmp_path):
    app = make_app(tmp_path, start="", end="")
    manifest = export_mod.export(FakeSplunkd(EVENTS), cfg_of(app), log=QUIET)
    assert manifest["first"] == FIRST + 60 and manifest["feeds"]["syslog"] == 2


def test_the_export_writes_indexed_sourcetypes_in_their_exact_case():
    cases = {"winhostmon": "WinHostMon", "xmlwineventlog": "XmlWinEventLog"}

    def feed(**kw):
        return Feed("f", kw)
    assert export_mod.indexed_name(feed(search='source="WinEventLog:Security"', set_sourcetype="wineventlog:security"),
                                   cases) == "WinEventLog:Security"
    assert export_mod.indexed_name(feed(search='sourcetype="winhostmon"', set_sourcetype="winhostmon"),
                                   cases) == "WinHostMon"
    assert export_mod.indexed_name(feed(search='sourcetype="cisco:asa"', set_sourcetype="cisco:asa"),
                                   cases) == "cisco:asa"


# --- setup and undo ---

def test_setup_points_the_box_at_the_live_index_and_undo_puts_it_back(tmp_path):
    app = make_app(tmp_path, extra="extra_roles = analyst, nosuchrole")
    box = FakeSplunkd()
    original = json.loads(json.dumps((box.conf, box.roles)))
    path = prepare.state_path(cfg_of(app))

    result = setup_mod.setup(box, cfg_of(app), path, QUIET)

    macros = box.conf["Splunk_SA_CIM/macros"]
    assert macros["cim_Authentication_indexes"]["definition"] == "((index=alpha) OR index=alpha_live)"
    assert macros["cim_Other_indexes"]["definition"] == "((index=beta_live) OR index=alpha_live)"
    assert macros["cim_Network_indexes"]["definition"] == "()"  # names neither: left alone
    assert macros["other_macro"]["definition"] == "(index=alpha)"
    models = box.conf["Splunk_SA_CIM/datamodels"]
    assert models["Authentication"]["acceleration.earliest_time"] == "-7d"
    assert models["Risk"]["acceleration.earliest_time"] == "-1y"  # ES's own model
    assert models["Endpoint"]["acceleration.earliest_time"] == ""  # not accelerated
    fs = box.conf["FalconSearch/macros"]
    assert fs["fs_Windows_index"]["definition"] == "(index=wineventlog OR index=alpha_live)"
    assert fs["fs_Risk_index"]["definition"] == 'index IN ("risk","notable")'
    assert fs["fs_Any_index"]["definition"] == "index=*"
    assert box.roles["admin"]["srchIndexesDefault"] == ["main", "alpha_live"]
    assert box.roles["analyst"]["srchIndexesAllowed"] == ["main", "alpha_live"]
    assert result["changes"] == 6 and result["warnings"] == []

    posts = len(box.posts)
    setup_mod.setup(box, cfg_of(app), path, QUIET)  # again: the plan is empty
    assert len(box.posts) == posts

    setup_mod.undo(box, path, QUIET)
    assert (box.conf, box.roles) == (original[0], original[1])
    assert not path.exists()


def test_two_datasets_share_a_macro_and_undo_takes_out_only_its_own_index(tmp_path):
    app = make_app(tmp_path)
    app = make_app(tmp_path, name="beta")
    box = FakeSplunkd()
    box.conf["Splunk_SA_CIM/macros"]["cim_Authentication_indexes"]["definition"] = "(index=alpha OR index=beta)"
    a, b = prepare.state_path(cfg_of(app, "alpha")), prepare.state_path(cfg_of(app, "beta"))
    setup_mod.setup(box, cfg_of(app, "alpha"), a, QUIET)
    setup_mod.setup(box, cfg_of(app, "beta"), b, QUIET)
    macro = box.conf["Splunk_SA_CIM/macros"]["cim_Authentication_indexes"]
    assert "index=alpha_live" in macro["definition"] and "index=beta_live" in macro["definition"]

    setup_mod.undo(box, a, QUIET)

    assert "index=alpha_live" not in macro["definition"] and "index=beta_live" in macro["definition"]
    # beta still needs the 7-day window
    assert box.conf["Splunk_SA_CIM/datamodels"]["Authentication"]["acceleration.earliest_time"] == "-7d"
    assert box.roles["admin"]["srchIndexesDefault"] == ["main", "beta_live"]

    setup_mod.undo(box, b, QUIET)
    assert box.conf["Splunk_SA_CIM/datamodels"]["Authentication"]["acceleration.earliest_time"] == "-1y"
    assert macro["definition"] == "(index=alpha OR index=beta)"
    assert box.roles["admin"]["srchIndexesDefault"] == ["main"]


def test_setup_warns_when_escu_reads_summaries_only(tmp_path):
    app = make_app(tmp_path)
    box = FakeSplunkd()
    box.conf["DA-ESS-ContentUpdate/macros"]["summariesonly_config"]["definition"] = "summariesonly=true"
    result = setup_mod.setup(box, cfg_of(app), prepare.state_path(cfg_of(app)), QUIET)
    assert result["warnings"] and "summariesonly" in result["warnings"][0]


def test_missing_and_disabled_add_ons_are_named():
    box = FakeSplunkd()
    assert setup_mod.missing_addons(box, ["Splunk_SA_CIM", "Splunk_TA_off", "Splunk_TA_gone"]) == \
        ["Splunk_TA_off", "Splunk_TA_gone"]


# --- assets ---

@pytest.fixture(scope="module")
def built(tmp_path_factory):
    return build.stage(tmp_path_factory.mktemp("built"))


def test_asset_and_identity_lists_come_from_the_dataset_and_are_registered(built, tmp_path, monkeypatch):
    monkeypatch.setenv("SPLUNK_HOME", str(tmp_path / "home"))
    app = tmp_path / "app"
    import shutil
    shutil.copytree(built, app)
    box = FakeSplunkd()
    box.answers = {
        "| tstats": [{"host": "FYODOR-L", "sourcetype": "wineventlog:security"},
                     {"host": "hoth", "sourcetype": "osquery:results"},
                     {"host": "FROTHLY-FW1", "sourcetype": "cisco:asa"},
                     {"host": "C:\\Program Files/x", "sourcetype": "junk"}],
        "ComputerName": [{"host": "FYODOR-L", "fqdn": "FYODOR-L.froth.ly"}],
        "symantec:ep:packet:file": [{"nt_host": "FYODOR-L", "ip": "198.51.100.103"}],
        "froth.ly": [{"u": "fyodor@froth.ly"}, {"u": "FrothlyAdmin@froth.ly"}],
    }
    assets, ids = assets_mod.derive(box, app, "botsv3", "botsv3", QUIET)
    by = {a["nt_host"]: a for a in assets}
    assert set(by) == {"FYODOR-L", "FROTHLY-FW1", "hoth"}
    assert by["FYODOR-L"]["owner"] == "fyodor@froth.ly" and by["FYODOR-L"]["ip"] == "198.51.100.103"
    assert by["FROTHLY-FW1"]["priority"] == "critical"
    assert {i["email"]: i["category"] for i in ids} == {"frothlyadmin@froth.ly": "privileged",
                                                        "fyodor@froth.ly": "employee"}

    assets_mod.upload(box, app, "botsv3", QUIET)
    assert box.lookups["botsv3_assets.csv"].startswith("ip,mac,nt_host,dns,owner,priority")
    assert box.lookups["botsv3_identities.csv"].splitlines()[1].startswith("frothlyadmin|frothlyadmin@froth.ly,")


@pytest.mark.parametrize("dataset", ["botsv3", "botsv2", "dedale"])
def test_every_shipped_hook_builds_lists_from_empty_results(built, dataset):
    module = assets_mod.hook(built, dataset)
    if module is None:
        pytest.skip(f"{dataset} has no lists")
    asset_rows, identity_rows = module.build({key: [] for key in module.SEARCHES})
    assert isinstance(asset_rows, list) and isinstance(identity_rows, list)
    for spl in module.SEARCHES.values():
        assert "{index}" in spl


def test_hosts_that_differ_only_by_case_or_domain_become_one_asset(built):
    module = assets_mod.hook(built, "botsv3")
    rows = module.assets([{"host": "gacrux", "sourcetype": "ps"}, {"host": "GACRUX", "sourcetype": "wineventlog"},
                          {"host": "gacrux.froth.ly", "sourcetype": "syslog"}], [], [])
    assert len(rows) == 1 and rows[0]["dns"] == "gacrux.froth.ly" and rows[0]["category"].endswith("|windows")


def test_a_pack_without_lists_skips_the_step(tmp_path):
    app = make_app(tmp_path)
    assert assets_mod.derive(FakeSplunkd(), app, "alpha", "alpha", QUIET) is None


# --- prepare.run and requests ---

@pytest.mark.parametrize("text,parsed", [
    ("1700000000:setup,export,assets", (1700000000, ["setup", "export", "assets"])),
    ("1700000000:assets,export", (1700000000, ["export", "assets"])),
    ("", None), ("1700000000:", None), ("now:export", None), ("1700000000:export,rm", None),
])
def test_requests_are_parsed_strictly_and_steps_run_in_order(text, parsed):
    assert prepare.parse_request(text) == parsed


def test_run_reports_each_step_and_a_summary_with_warnings(tmp_path):
    app = make_app(tmp_path)
    records = []
    summary = prepare.run(FakeSplunkd(EVENTS), app, cfg_of(app), ["setup", "export", "assets"], records.append)

    assert summary["ok"]
    assert summary["steps"]["export"] == {"ok": True, "segments": 1}
    assert summary["steps"]["assets"] == {"ok": True, "lists": "none"}
    assert any("Splunk_TA_missing" in w for w in summary["warnings"])
    assert {"step": "export", "feed": "security", "events": 2} in records
    assert prepare.export_info(cfg_of(app))["ready"]


def test_a_failing_step_stops_the_ones_after_it(tmp_path):
    app = make_app(tmp_path)
    summary = prepare.run(FakeSplunkd([]), app, cfg_of(app), ["export", "assets"], QUIET)
    assert not summary["ok"]
    assert summary["steps"]["export"]["ok"] is False and "assets" not in summary["steps"]


def write_local(app, name, **values):
    lines = [f"[dataset:{name}]"] + [f"{k} = {v}" for k, v in values.items()]
    (app / "local" / config_mod.CONF).write_text("\n".join(lines) + "\n")


def runner_for(app, tmp_path, factory, statuses):
    return Runner(app, tmp_path / "cp.json", io.StringIO(), status=statuses.append, dataset="alpha",
                  sleep=lambda s: None, prepare=factory, now=lambda: FIRST)


def wait_for(runner):
    deadline = time.time() + 5
    while runner._job is not None and runner._job.is_alive() and time.time() < deadline:
        time.sleep(0.01)


def test_a_request_runs_once_in_the_background_and_reports_progress(tmp_path):
    app = make_app(tmp_path)
    calls, statuses = [], []

    def factory(cfg, steps, progress):
        calls.append(steps)
        progress({"step": "export", "status": "done"})
        return {"ok": True}

    write_local(app, "alpha", prepare_request="1700000000:export")
    runner = runner_for(app, tmp_path, factory, statuses)
    runner.tick()
    assert statuses[-1]["state"] == "preparing"
    wait_for(runner)
    runner.tick()

    assert calls == [["export"]]
    assert statuses[-2]["state"] == "prepared"
    assert statuses[-2]["prepare"]["summary"] == {"ok": True}
    assert statuses[-2]["prepare"]["log"] == [{"step": "export", "status": "done"}]

    runner.tick()  # the same request again: handled already
    restarted = runner_for(app, tmp_path, factory, statuses)
    restarted.tick()  # and after a restart
    assert calls == [["export"]]


def test_a_request_is_refused_while_the_dataset_is_on(tmp_path):
    app = make_app(tmp_path)
    calls, statuses = [], []
    write_local(app, "alpha", enabled=1, prepare_request="1700000000:export")
    runner = runner_for(app, tmp_path, lambda *a: calls.append(a), statuses)
    runner.tick()

    assert calls == []
    assert statuses[0]["state"] == "prepare_refused" and "switch the dataset off" in statuses[0]["error"]
    assert statuses[0]["prepare"] == {"request": "1700000000:export", "refused": statuses[0]["error"]}


def test_a_malformed_request_is_refused_and_a_crash_never_kills_the_input(tmp_path):
    app = make_app(tmp_path)
    statuses = []
    write_local(app, "alpha", prepare_request="soon:export")
    runner_for(app, tmp_path, lambda *a: None, statuses).tick()
    assert statuses[0]["state"] == "prepare_refused"

    def boom(cfg, steps, progress):
        raise RuntimeError("splunkd went away")

    write_local(app, "alpha", prepare_request="1700000001:assets")
    runner = runner_for(app, tmp_path, boom, statuses)
    runner.tick()
    wait_for(runner)
    runner.tick()
    done = [s for s in statuses if s["state"] == "prepared"][-1]
    assert done["prepare"]["summary"] == {"ok": False, "error": "splunkd went away"}


def test_the_command_line_refuses_a_dataset_that_is_on(tmp_path, monkeypatch, capsys):
    sys.path.insert(0, str(REPO / "replay_lab" / "bin"))
    import replay_lab_prepare as cli
    app = make_app(tmp_path)
    write_local(app, "alpha", enabled=1)
    monkeypatch.setattr(cli, "APP_DIR", app)
    monkeypatch.setenv("SPLUNK_PASSWORD", "x")
    with pytest.raises(SystemExit):
        cli.main(["alpha", "https://localhost:8089"])
    assert "switch it off first" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli.main(["nosuch", "https://localhost:8089"])


@pytest.mark.parametrize("first", ["alpha_live", "beta_live"])
def test_undo_takes_out_its_wrapper_in_either_order(first):
    both = "(((index=a OR index=b) OR index=alpha_live) OR index=beta_live)"
    other = "beta_live" if first == "alpha_live" else "alpha_live"
    assert setup_mod.unwrap(setup_mod.unwrap(both, first), other) == "(index=a OR index=b)"
    assert setup_mod.unwrap("(index=x)", "alpha_live") == "(index=x)"


def test_on_a_cluster_prepare_saved_from_member_2_runs_only_on_member_1(tmp_path):
    """Demo: the page on sh2 saves the request through the settings API; the replicated setting
    reaches both members, and only sh1, which plays the dataset, runs it."""
    sys.path.insert(0, str(REPO / "tests"))
    from replaylib import settings
    from test_settings_api import FakeSplunkd as SettingsSplunkd
    sh2 = SettingsSplunkd()
    sh2.conf["dataset:alpha"] = {"enabled": "0", "run_on": "sh1"}
    status, _ = settings.handle(sh2, "POST", "datasets/alpha", {"prepare_request": "1700000000:export,assets"})
    assert status == 200

    app = make_app(tmp_path)
    write_local(app, "alpha", **{k: v for k, v in sh2.conf["dataset:alpha"].items()})  # replicated
    ran, statuses = {}, {"sh1": [], "sh2": []}
    runners = {m: Runner(app, tmp_path / f"{m}.json", io.StringIO(), status=statuses[m].append, dataset="alpha",
                         server_name=m, sleep=lambda s: None, now=lambda: FIRST,
                         prepare=lambda cfg, steps, progress, m=m: ran.setdefault(m, steps) and {"ok": True})
               for m in ("sh1", "sh2")}
    for runner in runners.values():
        runner.tick()
    wait_for(runners["sh1"])

    assert ran == {"sh1": ["export", "assets"]}
    assert statuses["sh1"][-1]["state"] == "preparing" and statuses["sh2"][-1]["state"] == "standby"
