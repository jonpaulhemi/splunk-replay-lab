"""The build (packs into one app, reproducibly) and the modular input (one process per dataset)."""

import configparser
import io
import json
import sys
import tarfile
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "replay_lab" / "bin"))
sys.path.insert(0, str(REPO))

import build  # noqa: E402
import replay_lab  # noqa: E402
from replaylib import config as config_mod  # noqa: E402
from replaylib import store  # noqa: E402
from replaylib.runner import Runner  # noqa: E402


def make_repo(tmp_path, packs):
    """A minimal repo: the real app skeleton plus the given packs {name: {file: text}}."""
    root = tmp_path / "repo"
    (root / "datasets").mkdir(parents=True)
    (root / "VERSION").write_text("9.9.9\n")
    build._copy_tree(REPO / "replay_lab", root / "replay_lab")
    for name, files in packs.items():
        for rel, text in files.items():
            path = root / "datasets" / name / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
    return root


def conf(path):
    parser = configparser.RawConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    parser.read_string(path.read_text().replace("\\\n", "\n    "))
    return parser


PACK = "[dataset]\nlabel = Alpha\n\n[feed:one]\nsearch = sourcetype=x\n\n[rules]\nnames = A rule\n"


# --- build ---

def test_two_builds_of_one_commit_are_byte_identical(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    first = build.build(tmp_path / "a").read_bytes()
    second = build.build(tmp_path / "b").read_bytes()
    assert first == second


def test_the_package_holds_the_app_and_no_box_state(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    root = make_repo(tmp_path, {"alpha": {"pack.conf": PACK}})
    for junk in ("replay_lab/local/replay_lab.conf", "replay_lab/data/x.jsonl.gz",
                 "replay_lab/bin/replaylib/__pycache__/x.pyc"):
        (root / junk).parent.mkdir(parents=True, exist_ok=True)
        (root / junk).write_text("x")
    with tarfile.open(build.build(tmp_path / "dist", root=root)) as tar:
        members = {m.name: m for m in tar.getmembers()}
    names = set(members)
    assert "replay_lab/default/replay_lab.conf" in names and "replay_lab/bin/replay_lab.py" in names
    assert "replay_lab/default/data/ui/views/replay_health.xml" in names
    assert not any("/local/" in n or n.startswith("replay_lab/data/") or "__pycache__" in n for n in names)
    assert all(m.uid == 0 and m.mtime == 1700000000 for m in members.values())
    assert members["replay_lab/bin/replay_lab.py"].mode == 0o755


def test_a_pack_becomes_stanzas_named_after_it(tmp_path):
    root = make_repo(tmp_path, {"alpha": {"pack.conf": PACK}, "beta": {"pack.conf": PACK.replace("Alpha", "Beta")}})
    app = build.stage(tmp_path / "out", root)
    replay = conf(app / "default" / "replay_lab.conf")
    assert {"dataset:alpha", "feed:alpha:one", "rules:alpha", "dataset:beta", "feed:beta:one"} <= set(replay.sections())
    assert config_mod.datasets(app) == ["alpha", "beta"]
    cfg = config_mod.load(app, "beta")
    assert (cfg.replay["label"], cfg.replay["index"], cfg.replay["source_index"]) == ("Beta", "beta_live", "beta")
    assert [f.name for f in cfg.feeds] == ["one"] and cfg.rules == ["A rule"]
    assert "@VERSION@" not in (app / "default" / "app.conf").read_text()
    assert "version = 9.9.9" in (app / "default" / "app.conf").read_text()


def test_each_pack_gets_its_input_and_live_index(tmp_path):
    root = make_repo(tmp_path, {"alpha": {"pack.conf": PACK}, "beta": {"pack.conf": PACK.replace(
        "label = Alpha", "label = Beta\nindex = beta_replayed")}})
    app = build.stage(tmp_path / "out", root)
    inputs = conf(app / "default" / "inputs.conf")
    indexes = conf(app / "default" / "indexes.conf")
    for name in ("alpha", "beta"):
        assert inputs.get(f"replay_lab://{name}", "disabled") == "0"
        assert not inputs.has_option(f"replay_lab://{name}", "interval")
    assert {"alpha_live", "beta_replayed"} <= set(indexes.sections())
    assert indexes.get("alpha_live", "frozenTimePeriodInSecs") == "604800"


def test_a_pack_that_defines_its_own_index_keeps_it(tmp_path):
    root = make_repo(tmp_path, {"alpha": {"pack.conf": PACK,
                                          "indexes.conf": "[alpha_live]\nhomePath = $SPLUNK_DB/a/db\n"}})
    text = (build.stage(tmp_path / "out", root) / "default" / "indexes.conf").read_text()
    assert text.count("[alpha_live]") == 1 and "$SPLUNK_DB/a/db" in text


def test_two_packs_that_set_one_stanza_key_differently_fail_the_build(tmp_path):
    root = make_repo(tmp_path, {"alpha": {"pack.conf": PACK, "props.conf": "[shared]\nKV_MODE = none\n"},
                                "beta": {"pack.conf": PACK, "props.conf": "[shared]\nKV_MODE = json\n"}})
    with pytest.raises(build.BuildError, match="KV_MODE"):
        build.stage(tmp_path / "out", root)


def test_two_packs_may_agree_on_a_stanza(tmp_path):
    root = make_repo(tmp_path, {"alpha": {"pack.conf": PACK, "props.conf": "[shared]\nKV_MODE = none\n"},
                                "beta": {"pack.conf": PACK, "props.conf": "[shared]\nKV_MODE = none\n"}})
    assert conf(build.stage(tmp_path / "out", root) / "default" / "props.conf").get("shared", "KV_MODE") == "none"


def test_an_unknown_stanza_in_a_pack_is_refused(tmp_path):
    root = make_repo(tmp_path, {"alpha": {"pack.conf": PACK + "\n[replay_extra]\nx = 1\n"}})
    with pytest.raises(build.BuildError, match="unknown stanza"):
        build.stage(tmp_path / "out", root)


def test_a_badly_named_pack_folder_is_refused(tmp_path):
    root = make_repo(tmp_path, {"Bad-Name": {"pack.conf": PACK}})
    with pytest.raises(build.BuildError, match="Bad-Name"):
        build.stage(tmp_path / "out", root)


def test_pack_lookups_and_hooks_land_in_the_app(tmp_path):
    root = make_repo(tmp_path, {"alpha": {"pack.conf": PACK, "lookups/alpha_assets.csv": "ip\n",
                                          "hooks/assets.py": "# hook\n"}})
    app = build.stage(tmp_path / "out", root)
    assert (app / "lookups" / "alpha_assets.csv").read_text() == "ip\n"
    assert (app / "bin" / "datasets" / "alpha" / "assets.py").exists()


def test_a_comment_and_a_continued_value_survive_the_rename():
    text = "# about it\n[rules]\nnames = A \\\n        B\n[feed:x]\nsearch = s\n"
    out = build.pack_stanzas("alpha", text)
    assert out == "# about it\n[rules:alpha]\nnames = A \\\n        B\n[feed:alpha:x]\nsearch = s\n"


# --- settings ---

def test_rules_mode_on_the_dataset_stanza_wins_over_the_rules_stanza(tmp_path):
    (tmp_path / "default").mkdir()
    (tmp_path / "default" / "replay_lab.conf").write_text(
        "[dataset:alpha]\nrules_mode = none\n[rules:alpha]\nmode = escu\n")
    assert config_mod.load(tmp_path, "alpha").rules_mode == "none"


def test_the_export_lives_outside_the_app_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("SPLUNK_HOME", str(tmp_path / "home"))
    cfg = config_mod.load(tmp_path, "alpha")
    assert config_mod.data_dir(cfg.replay) == tmp_path / "home" / "var" / "lib" / "replay_lab" / "alpha"


def test_one_datasets_settings_never_reach_another(tmp_path):
    (tmp_path / "default").mkdir()
    (tmp_path / "default" / "replay_lab.conf").write_text(
        "[dataset:alpha]\nenabled = 1\n[feed:alpha:one]\nsearch = a\n[dataset:beta]\n[feed:beta:two]\nsearch = b\n")
    alpha, beta = config_mod.load(tmp_path, "alpha"), config_mod.load(tmp_path, "beta")
    assert alpha.enabled and not beta.enabled
    assert [f.name for f in alpha.feeds] == ["one"] and [f.name for f in beta.feeds] == ["two"]


# --- the modular input ---

def test_the_input_runs_one_process_per_dataset(capsys):
    assert replay_lab.main(["--scheme"]) == 0
    scheme = ET.fromstring(capsys.readouterr().out)
    assert scheme.findtext("use_single_instance") == "false"


def test_the_process_learns_its_dataset_from_its_stanza():
    root = ET.fromstring("<input><server_host>sh1</server_host><configuration>"
                         '<stanza name="replay_lab://botsv2"><param name="disabled">0</param></stanza>'
                         "</configuration></input>")
    assert replay_lab.dataset_of(root) == "botsv2"


def test_each_dataset_writes_its_own_status_log_tagged_with_its_name(tmp_path):
    replay_lab.status_writer("alpha", home=str(tmp_path))({"state": "off", "at": 1})
    replay_lab.status_writer("beta", home=str(tmp_path))({"state": "on", "at": 2})
    folder = tmp_path / "var" / "log" / "replay_lab"
    assert json.loads((folder / "alpha.log").read_text()) == {"dataset": "alpha", "state": "off", "at": 1}
    assert json.loads((folder / "beta.log").read_text())["dataset"] == "beta"


def test_events_carry_their_datasets_stanza(tmp_path, monkeypatch):
    monkeypatch.setenv("SPLUNK_HOME", str(tmp_path / "home"))
    (tmp_path / "default").mkdir()
    (tmp_path / "default" / "replay_lab.conf").write_text(
        "[dataset:alpha]\nenabled = 1\nmax_catchup_seconds = 86400\n[feed:alpha:one]\nsearch = x\n[rules:alpha]\nmode = none\n")
    data = tmp_path / "home" / "var" / "lib" / "replay_lab" / "alpha"
    first = 1_500_000_000
    count = store.write_feed(data, "one", [{"t": first + 5.0, "raw": "hello", "sourcetype": "x", "source": "s",
                                             "host": "h"}], first)
    store.write_manifest(data, first, first + 99, {"one": count})
    out = io.StringIO()
    clock = [1_800_000_000]
    runner = Runner(tmp_path, tmp_path / "alpha.json", out, now=lambda: clock[0], sleep=lambda s: None,
                    dataset="alpha")
    runner.tick()
    clock[0] += 60
    runner.tick()
    text = out.getvalue()
    assert '<event stanza="replay_lab://alpha">' in text and "<index>alpha_live</index>" in text


def test_a_runner_without_a_dataset_is_refused(tmp_path):
    with pytest.raises(ValueError):
        Runner(tmp_path, tmp_path / "c.json", io.StringIO())


# --- malformed packs fail the build with a message naming the pack ---

BAD_PACKS = {
    "a feed given twice": (PACK + "\n[feed:one]\nsearch = again\n", "already exists"),
    "a key given twice": (PACK.replace("label = Alpha", "label = Alpha\nlabel = Again"), "already exists"),
    "an invalid live index": (PACK.replace("label = Alpha", "label = Alpha\nindex = Bad Index"), "valid index"),
    "live index = source index": (PACK.replace("label = Alpha", "label = Alpha\nindex = alpha"), "differ"),
    "a bad schedule": (PACK.replace("label = Alpha", "label = Alpha\nschedule = weekly"), "loop or daily"),
    "a bad time zone": (PACK.replace("label = Alpha", "label = Alpha\nschedule = daily\nschedule_timezone = Mars/Base"),
                        "pack.conf"),
    "unequal segments": (PACK.replace("label = Alpha", "label = Alpha\nsegments = 0-100 200-250"), "same length"),
    "a window that ends first": (PACK.replace("label = Alpha", "label = Alpha\nwindow_start = 200\nwindow_end = 100"),
                                 "ends before"),
    "no feeds": ("[dataset]\nlabel = Alpha\n", "no [feed"),
}


@pytest.mark.parametrize("case", sorted(BAD_PACKS))
def test_a_malformed_pack_fails_the_build_naming_it(tmp_path, case):
    text, message = BAD_PACKS[case]
    root = make_repo(tmp_path, {"alpha": {"pack.conf": text}})
    with pytest.raises(build.BuildError) as error:
        build.stage(tmp_path / "out", root)
    assert "datasets/alpha" in str(error.value) and message in str(error.value)


def test_two_packs_with_one_live_index_fail_the_build(tmp_path):
    shared = PACK.replace("label = Alpha", "label = Alpha\nindex = shared_live")
    root = make_repo(tmp_path, {"alpha": {"pack.conf": shared}, "beta": {"pack.conf": shared}})
    with pytest.raises(build.BuildError, match="shared_live is also alpha's"):
        build.stage(tmp_path / "out", root)


def test_a_hook_that_does_not_import_fails_the_build(tmp_path):
    root = make_repo(tmp_path, {"alpha": {"pack.conf": PACK, "hooks/assets.py": "import not_a_module_anywhere\n"}})
    with pytest.raises(build.BuildError, match="hooks/assets.py doesn't import"):
        build.stage(tmp_path / "out", root)


def test_a_packs_loading_tools_and_readme_stay_out_of_the_package(tmp_path):
    root = make_repo(tmp_path, {"alpha": {"pack.conf": PACK, "README.md": "x\n", "load/convert.py": "x = 1\n"}})
    app = build.stage(tmp_path / "out", root)
    assert not list(app.rglob("convert.py")) and not list(app.rglob("README.md"))


def test_a_cluster_replicates_the_settings(tmp_path):
    """Settings saved on one search head cluster member reach the others."""
    root = make_repo(tmp_path, {"alpha": {"pack.conf": PACK}})
    server = conf(build.stage(tmp_path / "out", root) / "default" / "server.conf")
    assert server.get("shclustering", "conf_replication_include.replay_lab") == "true"
