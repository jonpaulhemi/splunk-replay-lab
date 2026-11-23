"""Every shipped pack plays through the one engine, plus what each pack promises about itself.

The engine tests here run once per pack folder, so a new pack is covered without new tests.
Segment tests are the engine's own (BOTSv2 and DEDALE play several windows in turn).
"""

import io
import random
import re
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "replay_lab" / "bin"))
sys.path.insert(0, str(REPO))

import build  # noqa: E402
from replaylib import config as config_mod  # noqa: E402
from replaylib import store  # noqa: E402
from replaylib.engine import Engine  # noqa: E402
from replaylib.runner import Runner  # noqa: E402
from replaylib.schedule import Loop  # noqa: E402

PACKS = [name for name, _ in build.packs()]
NOW = 1_794_000_000


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    return build.stage(tmp_path_factory.mktemp("built"))


def spans(cfg):
    return config_mod.segments(cfg.replay) or [(int(cfg.replay["window_start"]), int(cfg.replay["window_end"]))]


def synthetic_export(cfg, data):
    """Two events per feed per window, each a line carrying its own time in hex (so no shifter touches it)."""
    rnd = random.Random(7)
    names = []
    windows = spans(cfg)
    for k, (start, end) in enumerate(windows):
        folder = data / f"seg{k:02d}" if len(windows) > 1 else data
        counts = {}
        for feed in cfg.feeds:
            times = sorted(start + int(rnd.random() * (end - start - 1)) for _ in range(2))
            events = [{"t": float(t), "raw": f"{feed.name} at {t:x}", "sourcetype": feed.set_sourcetype or "st",
                       "source": feed.set_source or "src", "host": "h"} for t in times]
            counts[feed.name] = store.write_feed(folder, feed.name, events, start)
        store.write_manifest(folder, start, end - 1, counts, end - start)
        names.append(f"seg{k:02d}")
    if len(windows) > 1:
        store.write_segments(data, names)


# --- once per pack ---

@pytest.mark.parametrize("dataset", PACKS)
def test_a_shipped_pack_starts_switched_off_with_feeds_rules_and_its_own_live_index(built, dataset):
    cfg = config_mod.load(built, dataset)
    assert cfg.enabled is False
    assert cfg.replay["index"] == f"{dataset}_live" and cfg.replay["source_index"] == dataset
    assert cfg.replay["label"]
    assert cfg.feeds and all(f.search for f in cfg.feeds) and any(f.enabled for f in cfg.feeds)
    assert cfg.rules_mode == "escu" and cfg.rules and cfg.rules[0] == "@risk_rule"
    assert cfg.skip_risk_objects == ["unknown", "null"]


@pytest.mark.parametrize("dataset", PACKS)
def test_a_shipped_pack_plays_each_enabled_event_once_into_its_live_index(built, dataset, tmp_path, monkeypatch):
    monkeypatch.setenv("SPLUNK_HOME", str(tmp_path / "home"))
    cfg = config_mod.load(built, dataset)
    synthetic_export(cfg, config_mod.data_dir(cfg.replay))
    app = tmp_path / "app"
    (app / "default").mkdir(parents=True)
    (app / "local").mkdir()
    (app / "default" / "replay_lab.conf").write_text((built / "default" / "replay_lab.conf").read_text())
    (app / "local" / "replay_lab.conf").write_text(
        f"[dataset:{dataset}]\nenabled = 1\nanchor = {NOW}\nschedule = loop\n[rules:{dataset}]\nmode = none\n")
    windows = spans(cfg)
    length = windows[0][1] - windows[0][0]
    out = io.StringIO()
    clock = [NOW]
    runner = Runner(app, tmp_path / "ck.json", out, now=lambda: clock[0], sleep=lambda s: None, dataset=dataset)
    end = NOW + length * len(windows)
    while clock[0] < end:
        runner.tick()
        clock[0] += 3600
    clock[0] = end
    runner.tick()

    text = out.getvalue()
    events = re.findall(r'<event stanza="replay_lab://([^"]+)"><time>([\d.]+)</time><index>([^<]+)</index>'
                        r".*?<data>([^<]*)</data>", text)
    enabled = {f.name for f in cfg.feeds if f.enabled}
    assert len(events) == 2 * len(enabled) * len(windows)
    assert {e[0] for e in events} == {dataset} and {e[2] for e in events} == {cfg.replay["index"]}
    assert {e[3].split(" at ")[0] for e in events} == enabled
    assert len({(e[1], e[3]) for e in events}) == len(events)  # nothing sent twice
    for _, at, _, raw in events:  # each window moves by one whole-second offset to its own period
        original = int(raw.split(" at ")[1], 16)
        k = next(i for i, (s, e) in enumerate(windows) if s <= original < e)
        assert float(at) == NOW + k * length + (original - windows[k][0])


# --- what particular packs promise ---

def test_botsv3_is_one_workday_daily_at_9_am_eastern(built):
    cfg = config_mod.load(built, "botsv3")
    assert (cfg.replay["schedule"], cfg.replay["daily_start"], cfg.replay["schedule_timezone"]) == (
        "daily", "09:00", "America/New_York")
    assert int(cfg.replay["window_end"]) - int(cfg.replay["window_start"]) == 6.5 * 3600


def test_botsv2_plays_seven_host_data_days_apt_day_first(built):
    cfg = config_mod.load(built, "botsv2")
    indexed = {f.set_sourcetype for f in cfg.feeds}
    on = {f.set_sourcetype for f in cfg.feeds if f.enabled}
    assert len(cfg.feeds) == 103 and "ess_content_importer" not in indexed
    assert all(f.set_sourcetype for f in cfg.feeds)
    # host data only: Windows and Linux on, network/application/metrics listed but off
    assert {"wineventlog:security", "xmlwineventlog:microsoft-windows-sysmon/operational", "winregistry",
            "winhostmon", "linux_secure", "auditd", "ps"} <= on
    assert not on & {"stream:dns", "suricata", "pan:traffic", "access_combined", "perfmon:process",
                     "mysql:server:stats", "collectd", "apache:error", "apache_error"}
    windows = [f for f in cfg.feeds if f.set_sourcetype.startswith(("wineventlog", "xmlwineventlog"))]
    assert windows and all(f.search.startswith('source="WinEventLog:') for f in windows)
    assert len(cfg.rules) == 46
    segments = config_mod.segments(cfg.replay)
    assert len(segments) == 7 and all(e - s == 86400 for s, e in segments)
    assert segments[0] == (1503532800, 1503619200)  # Aug 24 2017, the APT day, plays first


def test_dedale_plays_sixteen_days_benign_week_first_from_its_rebuilt_sources(built):
    cfg = config_mod.load(built, "dedale")
    sources = {f.set_source for f in cfg.feeds}
    assert {"XmlWinEventLog:Security", "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational", "XmlWinEventLog:Windows PowerShell",
            "XmlWinEventLog:System", "XmlWinEventLog:Application"} <= sources
    assert {f.set_sourcetype for f in cfg.feeds} == {"XmlWinEventLog", "auditd"}
    assert all(f.text_timezone == "utc" for f in cfg.feeds)  # SystemTime ends in Z; auditd carries epochs
    assert len(cfg.rules) == 56
    segments = config_mod.segments(cfg.replay)
    assert len(segments) == 16 and all(e - s == 86400 for s, e in segments)
    # 2024-12-30 .. 2025-01-14, in order: 7 benign days first, then the attack (Jan 6 is segment 7)
    assert segments[0][0] == 1735516800 and segments[7][0] == 1736121600 and segments[-1][0] == 1736812800
    assert [s for s, _ in segments] == sorted(s for s, _ in segments)


@pytest.mark.parametrize("dataset", ["botsv2", "dedale"])
def test_day_packs_loop_one_day_per_24_h_from_an_eastern_midnight(built, dataset):
    cfg = config_mod.load(built, dataset)
    assert cfg.replay["schedule"] == "loop"
    anchor = datetime.fromtimestamp(int(cfg.replay["anchor"]), ZoneInfo("America/New_York"))
    assert (anchor.hour, anchor.minute) == (0, 0)


def test_dedales_loading_tools_stay_out_of_the_package(built):
    assert (REPO / "datasets" / "dedale" / "load" / "dedale_convert.py").exists()
    assert not list(built.rglob("dedale_convert.py")) and not list(built.rglob("dedale_load.py"))


# --- segments ---

def _segment_data(tmp_path, days):
    """One feed and one event per segment, 10 s into each 100 s segment."""
    data = tmp_path / "data"
    names = []
    for i, first in enumerate(days):
        seg = data / f"seg{i:02d}"
        store.write_feed(seg, "f", [{"t": first + 10, "raw": f"day{i} {first + 10}", "sourcetype": "st",
                                     "source": "src", "host": "h"}], first)
        store.write_manifest(seg, first, first + 99, {"f": 1}, 100)
        names.append(f"seg{i:02d}")
    store.write_segments(data, names)
    return data


def test_a_single_window_export_is_one_segment(tmp_path):
    store.write_feed(tmp_path, "f", [], 100)
    store.write_manifest(tmp_path, 100, 199, {"f": 0}, 100)
    assert [d.first for d in store.open_all(tmp_path)] == [100]


def test_segments_must_share_one_length():
    with pytest.raises(ValueError):
        config_mod.segments({"segments": "0-100 200-250"})
    assert config_mod.segments({"segments": "0-100 200-300"}) == [(0, 100), (200, 300)]


def test_segments_play_in_turn_one_per_period_and_wrap(tmp_path):
    days = [1503532800, 1503100800, 1503705600]  # epoch-shaped, so the in-text times move
    data = _segment_data(tmp_path, days)
    feed = config_mod.Feed("f", {"search": "x", "timestamp_formats": "epoch"})
    engine = Engine(store.open_all(data), [feed], "live", Loop(NOW, 100))

    events = engine.due(NOW, NOW + 400)

    assert [e["time"] for e in events] == [NOW + 10, NOW + 110, NOW + 210, NOW + 310]
    assert [e["raw"].split()[0] for e in events] == ["day0", "day1", "day2", "day0"]
    # each segment's in-text time moves with its own offset
    assert [int(e["raw"].split()[1]) for e in events] == [NOW + 10, NOW + 110, NOW + 210, NOW + 310]
    assert engine.status(NOW + 150)["segment"] == 1
