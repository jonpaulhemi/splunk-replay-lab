"""Read one dataset's settings from replay_lab.conf (default/ then local/) in the app directory.

Each dataset has three kinds of stanza, all named after it:
    [dataset:<name>]        how it plays (on/off, index, schedule, member, data folder)
    [feed:<name>:<feed>]    one per exported feed
    [rules:<name>]          the detections it turns on while it plays
The build writes them from the dataset's pack (datasets/<name>/pack.conf).
"""

import configparser
import os
from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[2]
CONF = "replay_lab.conf"
TRUE = {"1", "true", "yes", "t", "y", "on"}

REPLAY_DEFAULTS = {
    "enabled": "0",
    "index": "",  # empty: <dataset>_live
    "tick_seconds": "30",
    "max_catchup_seconds": "3600",
    "anchor": "",
    "source_index": "",  # empty: the dataset's name
    # The part of the dataset that is replayed, as epoch seconds; empty = all of it.
    "window_start": "",
    "window_end": "",
    # Several windows that play in turn, one per period (start-end epoch pairs, space or line
    # separated, all the same length). Set, it replaces window_start/window_end.
    "segments": "",
    # loop: the window repeats back to back from the anchor. daily: it plays once a day from
    # daily_start (HH:MM) in schedule_timezone (a zone name, or local).
    "schedule": "loop",
    "daily_start": "09:00",
    "schedule_timezone": "America/New_York",
    # Which server plays the replay: empty = any server the app runs on (a standalone box). On a
    # search head cluster the deployer puts the app on every member, so name one member here
    # (its serverName); the input stays on standby everywhere else.
    "run_on": "",
    # Where the exported data lives. Empty = $SPLUNK_HOME/var/lib/replay_lab/<dataset>, outside the
    # app, because a deployer push replaces the app's contents.
    "data_dir": "",
    # Shown on the settings page.
    "label": "",
    # Add-ons the pack needs (comma or space separated app names); Prepare warns about missing ones.
    "requires": "",
    # Roles besides admin that should search the live index (setup adds it to srchIndexesAllowed).
    "extra_roles": "",
    # Set by the settings page: <epoch>:<steps>. The named member runs a request it hasn't handled.
    "prepare_request": "",
}

RULE_MODES = ("escu", "none")


def data_dir(replay, app_dir=None):
    """The exported data's folder: data_dir ($SPLUNK_HOME expanded), or var/lib/replay_lab/<dataset>."""
    home = os.environ.get("SPLUNK_HOME", "/opt/splunk")
    value = (replay.get("data_dir") or "").strip()
    if not value:
        return Path(home) / "var" / "lib" / "replay_lab" / replay["dataset"]
    return Path(value.replace("$SPLUNK_HOME", home))


class Feed:
    def __init__(self, name, settings):
        self.name = name
        self.search = settings.get("search", "").strip()
        self.enabled = settings.get("enabled", "1").strip().lower() in TRUE
        self.set_source = settings.get("set_source", "").strip() or None
        self.set_sourcetype = settings.get("set_sourcetype", "").strip() or None
        formats = settings.get("timestamp_formats", "").replace(",", " ").split()
        self.timestamp_formats = tuple(formats) or None
        self.json_set = settings.get("json_set", "").strip()
        # utc (the dataset's own clock, usually), local (the indexer's zone) or a zone name like America/New_York.
        self.text_timezone = settings.get("text_timezone", "").strip() or "utc"
        self.translate = settings.get("translate", "").strip() or None


class Config:
    def __init__(self, replay, feeds, rules, reset_lookups=(), reset_searches=(), suppress_period=None,
                 skip_risk_objects=(), risk_earliest=None, risk_suppress_fields=None):
        self.replay = replay
        self.risk_earliest = risk_earliest
        self.risk_suppress_fields = risk_suppress_fields
        self.skip_risk_objects = list(skip_risk_objects)
        self.feeds = feeds
        self.rules = rules
        self.reset_lookups = list(reset_lookups)
        self.reset_searches = list(reset_searches)
        self.suppress_period = suppress_period

    @property
    def enabled(self):
        return self.replay["enabled"].strip().lower() in TRUE

    def number(self, key):
        return float(self.replay[key])


def segments(replay):
    """[(start, end), ...] from [replay] segments, or [] when it's not set."""
    out = []
    for item in replay.get("segments", "").replace(",", " ").split():
        start, _, end = item.partition("-")
        out.append((int(float(start)), int(float(end))))
    if out and len({end - start for start, end in out}) != 1:
        raise ValueError("segments must all be the same length")
    return out


def _split_list(text):
    return [line.strip() for line in text.replace("\\\n", "\n").splitlines() if line.strip()]


def read(app_dir=APP_DIR):
    """replay_lab.conf as one parser: default/, then local/ on top."""
    parser = configparser.RawConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    for layer in ("default", "local"):
        path = Path(app_dir) / layer / CONF
        if path.exists():
            # Splunk continues a value with a trailing backslash; configparser by indenting.
            parser.read_string(path.read_text(encoding="utf-8").replace("\\\n", "\n    "), source=str(path))
    return parser


def datasets(app_dir=APP_DIR):
    """The names of every dataset the app knows, in conf order."""
    return [s.split(":", 1)[1] for s in read(app_dir).sections() if s.startswith("dataset:")]


def load(app_dir, dataset):
    parser = read(app_dir)
    section = f"dataset:{dataset}"
    rules_section = f"rules:{dataset}"
    replay = dict(REPLAY_DEFAULTS)
    if parser.has_section(section):
        replay.update(parser.items(section))
    replay["dataset"] = dataset
    replay["index"] = replay["index"].strip() or f"{dataset}_live"
    replay["source_index"] = replay["source_index"].strip() or dataset
    prefix = f"feed:{dataset}:"
    feeds = [Feed(s[len(prefix):], dict(parser.items(s))) for s in parser.sections() if s.startswith(prefix)]
    has_rules = parser.has_section(rules_section)

    def rules_value(key):
        return parser.get(rules_section, key, fallback="").strip() if has_rules else ""

    def listed(key):
        return _split_list(rules_value(key))

    # escu: the app switches the listed detections on while it plays and puts them back after.
    # none: it only sends data and never touches saved searches (Falcon Search, or rules managed
    # some other way). [dataset:<name>] rules_mode wins over [rules:<name>] mode.
    mode = (replay.get("rules_mode", "").strip() or rules_value("mode") or "escu").lower()
    if mode not in RULE_MODES:
        raise ValueError(f"[{section}] rules_mode must be escu or none, not {mode!r}")
    cfg = Config(replay, feeds, listed("names"), listed("reset_lookups"), listed("reset_searches"),
                 rules_value("suppress_period") or None,
                 [v.strip() for v in rules_value("skip_risk_objects").split(",") if v.strip()],
                 rules_value("risk_earliest") or None,
                 ",".join(v.strip() for v in rules_value("risk_suppress_fields").split(",") if v.strip()) or None)
    cfg.rules_mode = mode
    cfg.dataset = dataset
    return cfg
