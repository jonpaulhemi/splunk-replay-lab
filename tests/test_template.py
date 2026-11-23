"""The template pack: a new pack made from it builds, validates and loads like a shipped one."""

import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "replay_lab" / "bin"))

import build  # noqa: E402
import new_pack  # noqa: E402
from replaylib import assets as assets_mod  # noqa: E402
from replaylib import config as config_mod  # noqa: E402


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "datasets").mkdir(parents=True)
    (root / "VERSION").write_text("9.9.9\n")
    build._copy_tree(REPO / "replay_lab", root / "replay_lab")
    shutil.copytree(REPO / "templates", root / "templates")
    return root


def test_a_pack_made_from_the_template_builds_and_loads(repo, tmp_path):
    folder = new_pack.new_pack("lab_one", "Lab One", root=repo)
    assert sorted(p.name for p in folder.iterdir()) == ["README.md", "hooks", "inputs.conf", "load", "lookups",
                                                         "pack.conf", "props.conf", "transforms.conf"]
    assert (folder / "lookups" / "lab_one_assets.csv").exists()
    app = build.stage(tmp_path / "out", repo)

    cfg = config_mod.load(app, "lab_one")
    assert cfg.replay["label"] == "Lab One" and cfg.replay["index"] == "lab_one_live"
    assert cfg.replay["source_index"] == "lab_one" and cfg.rules_mode == "none"
    assert [f.name for f in cfg.feeds if f.enabled] == ["syslog"]
    assert "[replay_lab://lab_one]" in (app / "default" / "inputs.conf").read_text()
    assert "[identity_manager://lab_one_assets]" in (app / "default" / "inputs.conf").read_text()
    assert "[lab_one_live]" in (app / "default" / "indexes.conf").read_text()
    assert not (app / "bin" / "datasets" / "lab_one" / "README.md").exists()

    hook = assets_mod.hook(app, "lab_one")
    assets, ids = hook.build({"hosts": [{"host": "dc01.example.com"}, {"host": "web7"}],
                              "users": [{"user": "Alice"}]})
    assert [(a["nt_host"], a["priority"]) for a in assets] == [("dc01", "critical"), ("web7", "medium")]
    assert ids[0]["email"] == "alice@example.com"


def test_two_packs_from_the_template_build_side_by_side(repo, tmp_path):
    new_pack.new_pack("one", root=repo)
    new_pack.new_pack("two", root=repo)
    app = build.stage(tmp_path / "out", repo)
    assert config_mod.datasets(app) == ["one", "two"]


@pytest.mark.parametrize("name", ["Bad", "1st", "has-dash", ""])
def test_a_bad_pack_name_is_refused(repo, name):
    with pytest.raises(ValueError):
        new_pack.new_pack(name, root=repo)


def test_an_existing_pack_is_never_overwritten(repo):
    new_pack.new_pack("one", root=repo)
    with pytest.raises(ValueError, match="already exists"):
        new_pack.new_pack("one", root=repo)
