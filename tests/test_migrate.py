"""Moving a dataset from its earlier single-dataset app: the replay continues where it stopped."""

import io
import json
import re
import shutil
import sys
import urllib.parse
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "replay_lab" / "bin"))
sys.path.insert(0, str(REPO / "tests"))

import build  # noqa: E402
from replaylib import config as config_mod  # noqa: E402
from replaylib import migrate, store  # noqa: E402
from replaylib.ledger import RULES, KvLedger  # noqa: E402
from replaylib.runner import Runner  # noqa: E402
from test_shared_rules import FakeSplunkd as KvSplunkd  # noqa: E402

FEED = {"botsv3_replay": "access_combined", "botsv2_replay": "access_combined", "dedale_replay": "security"}
SHARED = "ESCU - Shared - Rule"
ANCHOR = 1_800_000_000


class FakeSplunkd(KvSplunkd):
    """The KV store, plus the apps and conf endpoints migrate uses."""

    def __init__(self, disabled=("botsv3_replay", "botsv2_replay", "dedale_replay"), server="sh1.example.com"):
        super().__init__()
        self.disabled = set(disabled)
        self.server = server
        self.saved = []  # (stanza, values) in order

    def call(self, method, path, query=None, form=None, timeout=120, body=None):
        m = re.match(r"/services/apps/local/(\w+)$", path)
        if m:
            return 200, {"entry": [{"content": {"disabled": "1" if m.group(1) in self.disabled else "0"}}]}
        if path == "/services/server/info":
            return 200, {"entry": [{"content": {"serverName": self.server}}]}
        if path.startswith(migrate.CONF + "/"):
            self.saved.append((urllib.parse.unquote(path.rsplit("/", 1)[1]), dict(form)))
            return 200, {}
        return super().call(method, path, query, form, timeout, body)

    def local_conf(self):
        out = {}
        for stanza, values in self.saved:
            out.setdefault(stanza, {}).update(values)
        return "".join(f"[{s}]\n" + "".join(f"{k} = {v}\n" for k, v in vals.items()) + "\n" for s, vals in out.items())


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    return build.stage(tmp_path_factory.mktemp("built"))


def old_app(home, name, built, rules=None, enabled="1", inside=True):
    """An old app as it was left: its checkpoint, local settings and export."""
    dataset = migrate.OLD_APPS[name]
    app = home / "etc" / "apps" / name
    data = app / "data" if inside else home / "var" / "lib" / name / "data"
    first = 1534755600
    events = [{"t": first + s, "raw": f"event at {s}", "sourcetype": "access_combined", "source": "a", "host": "h"}
              for s in (60, 120, 200)]
    count = store.write_feed(data, FEED[name], events, first)
    store.write_manifest(data, first, first + 23399, {FEED[name]: count}, 23400)
    (app / "local").mkdir(parents=True)
    lines = ["[replay]", f"enabled = {enabled}", "schedule = loop"]
    if not inside:
        lines.append(f"data_dir = $SPLUNK_HOME/var/lib/{name}/data")
    lines += ["", f"[feed:{FEED[name]}]", "enabled = 1", "", "[rules]", "mode = escu"]
    (app / "local" / f"{name}.conf").write_text("\n".join(lines) + "\n")
    state = {"anchor": ANCHOR, "next": ANCHOR + 100, "rules_for": ["names"],
             "rules": rules if rules is not None else
             {SHARED: {"app": "DA-ESS-ContentUpdate", "disabled": "1", "is_scheduled": "0"}}}
    checkpoint = home / "var" / "lib" / "splunk" / "modinputs" / name / f"{name}.json"
    checkpoint.parent.mkdir(parents=True)
    checkpoint.write_text(json.dumps(state))
    return dataset


def new_app(tmp_path, built, splunkd):
    app = tmp_path / "replay_lab"
    if not app.exists():
        shutil.copytree(built, app)
    (app / "local").mkdir(exist_ok=True)
    (app / "local" / config_mod.CONF).write_text(splunkd.local_conf())
    return app


@pytest.mark.parametrize("name", sorted(migrate.OLD_APPS))
def test_a_migrated_dataset_continues_where_the_old_app_stopped(name, built, tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("SPLUNK_HOME", str(home))
    dataset = old_app(home, name, built)
    splunkd = FakeSplunkd()
    migrate.run(splunkd, home, name, built, log=lambda r: None)

    # settings: renamed stanzas, data_dir at the old export, enabled saved last
    assert splunkd.saved[-1] == (f"dataset:{dataset}", {"enabled": "1"})
    settings = dict(splunkd.saved[:-1])
    shipped = config_mod.load(built, dataset)
    assert settings[f"dataset:{dataset}"]["data_dir"] == str(home / "etc" / "apps" / name / "data")
    # only what differs from the pack is carried
    assert ("schedule" in settings[f"dataset:{dataset}"]) == (shipped.replay["schedule"] != "loop")
    assert "window_start" not in settings[f"dataset:{dataset}"]
    feed = {f.name: f for f in shipped.feeds}[FEED[name]]
    assert (f"feed:{dataset}:{FEED[name]}" in settings) == (not feed.enabled)
    assert f"rules:{dataset}" not in settings  # mode escu, as shipped
    # rule originals into the shared KV records
    record = splunkd.record(SHARED)
    assert record["holders"] == [dataset]
    assert json.loads(record["original"]) == {"disabled": "1", "is_scheduled": "0"}
    assert record["app"] == "DA-ESS-ContentUpdate"

    # the first tick picks up at the old position (100 s in), not at now
    app = new_app(tmp_path, built, splunkd)
    out = io.StringIO()
    runner = Runner(app, migrate.new_checkpoint(home, dataset), out, dataset=dataset, now=lambda: ANCHOR + 300,
                    sleep=lambda s: None, rules=lambda cfg: None)
    assert runner.tick() == 2
    assert re.findall(r"event at (\d+)", out.getvalue()) == ["120", "200"]


def test_a_second_dataset_joins_a_rule_the_first_already_holds(built, tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("SPLUNK_HOME", str(home))
    old_app(home, "botsv3_replay", built)
    old_app(home, "dedale_replay", built,
            rules={SHARED: {"app": "DA-ESS-ContentUpdate", "disabled": "0", "is_scheduled": "1"}})
    splunkd = FakeSplunkd()
    migrate.run(splunkd, home, "botsv3_replay", built, log=lambda r: None)
    migrate.run(splunkd, home, "dedale_replay", built, log=lambda r: None)

    record = splunkd.record(SHARED)
    assert record["holders"] == ["botsv3", "dedale"]
    assert json.loads(record["original"]) == {"disabled": "1", "is_scheduled": "0"}  # the first one's


def test_an_input_already_running_keeps_the_migrated_position_while_the_settings_arrive(built, tmp_path,
                                                                                       monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("SPLUNK_HOME", str(home))
    dataset = old_app(home, "botsv3_replay", built)
    splunkd = FakeSplunkd()
    app = new_app(tmp_path, built, splunkd)  # replay_lab installed, botsv3 off
    clock = [ANCHOR + 250]
    runner = Runner(app, migrate.new_checkpoint(home, dataset), io.StringIO(), dataset=dataset,
                    now=lambda: clock[0], sleep=lambda s: None, rules=lambda cfg: None)
    runner.tick()  # running before the migration

    plan = migrate.plan(home, "botsv3_replay", built, now=lambda: clock[0])
    migrate.run(splunkd, home, "botsv3_replay", built, log=lambda r: None, now=lambda: clock[0])
    runner.tick()  # the checkpoint changed under it; the settings haven't reached it yet
    assert runner.state["next"] == ANCHOR + 100 and runner.state.get("holding") is True
    assert plan["checkpoint"]["migrated"] == ANCHOR + 250

    out = io.StringIO()
    runner.out = out
    new_app(tmp_path, built, splunkd)  # now they have
    clock[0] = ANCHOR + 300
    assert runner.tick() == 2


def test_it_refuses_while_the_old_app_is_enabled_and_over_an_existing_checkpoint(built, tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("SPLUNK_HOME", str(home))
    old_app(home, "botsv3_replay", built)
    with pytest.raises(migrate.MigrateError, match="stop botsv3_replay first"):
        migrate.run(FakeSplunkd(disabled=()), home, "botsv3_replay", built, log=lambda r: None)
    splunkd = FakeSplunkd()
    migrate.run(splunkd, home, "botsv3_replay", built, log=lambda r: None)
    with pytest.raises(migrate.MigrateError, match="already has a checkpoint"):
        migrate.run(splunkd, home, "botsv3_replay", built, log=lambda r: None)


def test_an_export_inside_the_old_app_is_flagged_and_can_be_copied(built, tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("SPLUNK_HOME", str(home))
    old_app(home, "botsv3_replay", built)
    assert any("removing that app deletes it" in w for w in migrate.plan(home, "botsv3_replay", built)["warnings"])

    splunkd = FakeSplunkd()
    migrate.run(splunkd, home, "botsv3_replay", built, copy_export=True, log=lambda r: None)
    assert dict(splunkd.saved[:-1])["dataset:botsv3"]["data_dir"] == ""
    copied = home / "var" / "lib" / "replay_lab" / "botsv3"
    assert store.open_all(copied)[0].feeds == {"access_combined": 3}


def test_an_export_outside_the_old_app_is_used_where_it_is(built, tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("SPLUNK_HOME", str(home))
    old_app(home, "dedale_replay", built, inside=False)
    todo = migrate.plan(home, "dedale_replay", built)
    assert todo["warnings"] == [] and todo["settings"]["dataset:dedale"]["data_dir"] == \
        str(home / "var" / "lib" / "dedale_replay" / "data")


def test_no_checkpoint_or_no_export_is_named(built, tmp_path):
    with pytest.raises(migrate.MigrateError, match="no checkpoint"):
        migrate.plan(tmp_path, "botsv3_replay", built)
    with pytest.raises(migrate.MigrateError, match="no migration"):
        migrate.plan(tmp_path, "other_replay", built)


def test_the_command_line_dry_run_changes_nothing(built, tmp_path, monkeypatch, capsys):
    import replay_lab_migrate as cli
    home = tmp_path / "home"
    monkeypatch.setenv("SPLUNK_HOME", str(home))
    old_app(home, "botsv2_replay", built)
    monkeypatch.setattr(cli, "APP_DIR", built)
    assert cli.main(["botsv2_replay", "https://localhost:8089", "--dry-run"]) == 0
    assert '"dataset": "botsv2"' in capsys.readouterr().out
    assert not migrate.new_checkpoint(home, "botsv2").exists()


def test_after_the_grace_an_off_dataset_forgets_its_position_as_usual(built, tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("SPLUNK_HOME", str(home))
    dataset = old_app(home, "botsv3_replay", built, enabled="0", rules={})
    splunkd = FakeSplunkd()
    migrate.run(splunkd, home, "botsv3_replay", built, log=lambda r: None, now=lambda: ANCHOR)
    app = new_app(tmp_path, built, splunkd)
    clock = [ANCHOR + 60]
    runner = Runner(app, migrate.new_checkpoint(home, dataset), io.StringIO(), dataset=dataset,
                    now=lambda: clock[0], sleep=lambda s: None, rules=lambda cfg: None)
    runner.tick()
    assert runner.state["next"] == ANCHOR + 100
    clock[0] = ANCHOR + 601
    runner.tick()
    assert "next" not in runner.state and "migrated" not in runner.state


def test_a_deployer_pushed_app_parked_on_no_member_migrates_its_lab_settings(built, tmp_path, monkeypatch):
    """A deployer folds local/ into default/, and the app can't be disabled on one member. Disabling its
    input doesn't stop it either (splunkd restarts it); parking it on a name no member has does."""
    home = tmp_path / "home"
    monkeypatch.setenv("SPLUNK_HOME", str(home))
    dataset = old_app(home, "dedale_replay", built, inside=False)
    app = home / "etc" / "apps" / "dedale_replay"
    shipped = migrate.read_conf(built / "default" / config_mod.CONF)
    renamed = {"dataset:dedale": "replay", "rules:dedale": "rules"}
    old_default = "".join(
        f"[{renamed.get(s, s.replace('feed:dedale:', 'feed:'))}]\n" +
        "".join(f"{k} = " + v.replace("\n", " \\\n") + "\n" for k, v in vals.items()) + "\n"
        for s, vals in shipped.items() if s in renamed or s.startswith("feed:dedale:"))
    local = (app / "local" / "dedale_replay.conf").read_text().replace("[replay]\n", "[replay]\nrun_on = sh1\n")
    (app / "default").mkdir()
    (app / "default" / "dedale_replay.conf").write_text(old_default + "\n" + local)  # merged by the deployer
    (app / "local" / "dedale_replay.conf").unlink()

    splunkd = FakeSplunkd(disabled=())
    with pytest.raises(migrate.MigrateError, match="stop dedale_replay first"):
        migrate.run(splunkd, home, "dedale_replay", built, log=lambda r: None)  # still plays on sh1
    (app / "local").mkdir(exist_ok=True)
    (app / "local" / "dedale_replay.conf").write_text("[replay]\nrun_on = nobody\n")  # the REST fallback
    migrate.run(splunkd, home, "dedale_replay", built, log=lambda r: None)
    saved = {}
    for stanza, values in splunkd.saved:
        saved.setdefault(stanza, {}).update(values)
    assert saved["dataset:dedale"] == {"enabled": "1", "run_on": "sh1.example.com",
                                       "data_dir": str(home / "var" / "lib" / "dedale_replay" / "data")}
    assert [s for s in saved if s != "dataset:dedale"] == []  # the rest matches the pack


def test_an_old_replay_that_is_off_counts_as_stopped(built, tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("SPLUNK_HOME", str(home))
    old_app(home, "botsv2_replay", built, enabled="0")
    splunkd = FakeSplunkd(disabled=())
    assert migrate.old_app_stopped(splunkd, home, "botsv2_replay") == "[replay] enabled = 0"
    migrate.run(splunkd, home, "botsv2_replay", built, log=lambda r: None)
