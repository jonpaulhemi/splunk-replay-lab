"""Move a dataset from its earlier single-dataset app (botsv3_replay, botsv2_replay, dedale_replay)
to replay_lab, so the replay continues where the old app stopped.

Run on the member that played the old app, once the old app has stopped: disabled, its [replay]
off, or its run_on set to a name no member has (two apps writing one live index would double every
event; disabling only its input doesn't stop it). In order:

1. Rule originals from the old checkpoint go into the replay_lab_rules KV records, with this
   dataset as a holder. A rule another dataset already holds keeps the original recorded first.
2. The old checkpoint (anchor, position, which rules are on) becomes the dataset's checkpoint. A
   running input picks it up on its next tick, and keeps it for 10 minutes even while the
   dataset is still off, so the settings below have time to arrive.
3. The old app's settings (default/ and local/: a deployer folds local/ into default/) that differ
   from what replay_lab ships become [dataset:<name>], [feed:<name>:<feed>] and [rules:<name>]
   settings, saved through splunkd so a cluster replicates them. data_dir points at the old
   export (or at a copy of it, with copy_export). enabled is saved last, so the input never
   starts before its checkpoint is in place.
"""

import configparser
import json
import shutil
import time
import urllib.parse
from pathlib import Path

from . import config as config_mod
from .ledger import KvLedger

OLD_APPS = {"botsv3_replay": "botsv3", "botsv2_replay": "botsv2", "dedale_replay": "dedale"}
CONF = "/servicesNS/nobody/replay_lab/configs/conf-replay_lab"


class MigrateError(RuntimeError):
    pass


def paths(home, old_app):
    home = Path(home)
    return {
        "app": home / "etc" / "apps" / old_app,
        "local": home / "etc" / "apps" / old_app / "local" / f"{old_app}.conf",
        "checkpoint": home / "var" / "lib" / "splunk" / "modinputs" / old_app / f"{old_app}.json",
    }


def new_checkpoint(home, dataset):
    return Path(home) / "var" / "lib" / "splunk" / "modinputs" / "replay_lab" / f"{dataset}.json"


def read_conf(*paths):
    """{stanza: {key: value}} from the given conf files, later ones on top; missing files are skipped."""
    parser = configparser.RawConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    for path in paths:
        if Path(path).exists():
            # Splunk continues a value with a trailing backslash; configparser by indenting.
            parser.read_string(Path(path).read_text(encoding="utf-8").replace("\\\n", "\n    "), source=str(path))
    return {s: dict(parser.items(s)) for s in parser.sections()}


def read_local(path):
    return read_conf(path)


def _same(a, b):
    """Two setting values are the same, line breaks and spacing aside."""
    return " ".join(str(a).replace("\\", " ").split()) == " ".join(str(b).replace("\\", " ").split())


def changed_settings(settings, app_dir, dataset):
    """Only the values that differ from what replay_lab already ships for the dataset.

    A search head cluster's deployer folds an app's local/ into default/, so the old app's own
    settings and the lab's changes arrive mixed; comparing with the new defaults leaves the lab's
    changes (run_on, data_dir, enabled, ...) and drops what the pack already says."""
    shipped = read_conf(Path(app_dir) / "default" / config_mod.CONF)
    defaults = dict(config_mod.REPLAY_DEFAULTS, index=f"{dataset}_live", source_index=dataset)
    out = {}
    for stanza, values in settings.items():
        base = (dict(defaults) if stanza.startswith("dataset:") else
                {"enabled": "1"} if stanza.startswith("feed:") else {"mode": "escu"})
        base.update(shipped.get(stanza, {}))
        kept = {k: v for k, v in values.items() if k not in base or not _same(v, base[k])}
        if kept or stanza.startswith("dataset:"):
            out[stanza] = kept
    return out


def old_data_dir(home, old_app, replay):
    value = (replay.get("data_dir") or "").strip()
    if value:
        return Path(value.replace("$SPLUNK_HOME", str(home)))
    return Path(home) / "etc" / "apps" / old_app / "data"


def stanzas(dataset, local):
    """The old local stanzas under their new names: [replay] -> [dataset:<name>] and so on."""
    out = {}
    for stanza, values in local.items():
        if stanza == "replay":
            out[f"dataset:{dataset}"] = dict(values)
        elif stanza == "rules":
            out[f"rules:{dataset}"] = dict(values)
        elif stanza.startswith("feed:"):
            out[f"feed:{dataset}:{stanza[5:]}"] = dict(values)
    return out


def plan(home, old_app, app_dir, copy_export=False, now=time.time):
    """What migrate will do, without doing it: {"dataset", "checkpoint", "rules", "settings",
    "export_from", "export_to", "warnings"}."""
    if old_app not in OLD_APPS:
        raise MigrateError(f"no migration from {old_app!r}; known: {', '.join(sorted(OLD_APPS))}")
    dataset = OLD_APPS[old_app]
    p = paths(home, old_app)
    if not p["checkpoint"].exists():
        raise MigrateError(f"no checkpoint at {p['checkpoint']}: run this on the member that played {old_app}")
    state = json.loads(p["checkpoint"].read_text())
    # default/ too: a deployer folds local/ into it
    local = read_conf(p["app"] / "default" / f"{old_app}.conf", p["local"])
    settings = changed_settings(stanzas(dataset, local), app_dir, dataset)
    replay = settings.setdefault(f"dataset:{dataset}", {})
    warnings = []
    source = old_data_dir(home, old_app, local.get("replay", {}))
    if not (source / "manifest.json").exists():
        raise MigrateError(f"no export at {source}")
    target = None
    if copy_export:
        target = config_mod.data_dir({"dataset": dataset})
        replay["data_dir"] = ""
    else:
        replay["data_dir"] = str(source)
        if p["app"] in source.parents:
            warnings.append(f"the export is inside {old_app} ({source}); removing that app deletes it: "
                            "use copy_export, or move it first")
    known = {f.name for f in config_mod.load(app_dir, dataset).feeds}
    for stanza in settings:
        if stanza.startswith("feed:") and stanza.split(":", 2)[2] not in known:
            warnings.append(f"[{stanza}] matches no feed in the {dataset} pack; saved anyway")
    replay.pop("rules_mode", None)  # the old apps had none; [rules] mode carries it
    checkpoint = {k: state[k] for k in ("anchor", "next", "rules_for") if k in state}
    checkpoint["migrated"] = int(now())
    if state.get("rules"):
        checkpoint["holding"] = True
    return {"dataset": dataset, "checkpoint": checkpoint, "rules": state.get("rules") or {},
            "settings": settings, "export_from": str(source), "export_to": str(target) if target else None,
            "warnings": warnings}


TRUE = ("1", "true", "t", "yes", "y", "on")


def _short(name):
    return str(name).strip().lower().split(".")[0]


def _app_disabled(rest, old_app):
    status, body = rest.call("GET", f"/services/apps/local/{urllib.parse.quote(old_app, safe='')}")
    if status == 404:
        return True  # removed
    content = (body.get("entry") or [{}])[0].get("content") or {} if status == 200 else {}
    return str(content.get("disabled", "0")).lower() in TRUE


def _server_name(rest):
    status, body = rest.call("GET", "/services/server/info", query={"output_mode": "json"})
    return ((body.get("entry") or [{}])[0].get("content") or {}).get("serverName", "") if status == 200 else ""


def old_app_stopped(rest, home, old_app):
    """Why the old app can't play on this member, or None if it still can.

    Only the old app's own checks count: the app is disabled or removed, its [replay] is off, or
    its run_on names another member. Disabling its input doesn't: splunkd restarts a
    single-instance input instead of stopping it, and the old replay carries on."""
    if _app_disabled(rest, old_app):
        return "app disabled"
    p = paths(home, old_app)
    replay = read_conf(p["app"] / "default" / f"{old_app}.conf", p["local"]).get("replay", {})
    if str(replay.get("enabled", "0")).strip().lower() not in TRUE:
        return "[replay] enabled = 0"
    run_on = (replay.get("run_on") or "").strip()
    if run_on and _short(run_on) != _short(_server_name(rest) or run_on):
        return f"run_on = {run_on}"
    return None


def run(rest, home, old_app, app_dir, copy_export=False, force=False, log=print, now=time.time):
    todo = plan(home, old_app, app_dir, copy_export, now)
    dataset = todo["dataset"]
    for warning in todo["warnings"]:
        log({"warning": warning})
    stopped = old_app_stopped(rest, home, old_app)
    if not force and stopped is None:
        raise MigrateError(f"stop {old_app} first (set its [replay] run_on to a name no member has, or "
                           "disable the app): two apps playing one live index double every event")
    replay = todo["settings"][f"dataset:{dataset}"]
    if stopped and stopped.startswith("run_on") and replay.get("run_on"):
        # The old app was parked on a name no member has; replay_lab plays where migrate runs.
        replay["run_on"] = _server_name(rest) or replay["run_on"]
    target = new_checkpoint(home, dataset)
    if target.exists() and not force:
        raise MigrateError(f"{dataset} already has a checkpoint ({target}); pass force to replace it")

    if todo["export_to"]:  # before anything points at it
        dest = Path(todo["export_to"])
        work = dest.with_name(dest.name + ".new")
        if work.exists():
            shutil.rmtree(work)
        shutil.copytree(todo["export_from"], work)
        if dest.exists():
            shutil.rmtree(dest)
        work.rename(dest)
        log({"export": f"copied to {dest}"})

    ledger = KvLedger(dataset, rest)
    for name, saved in sorted(todo["rules"].items()):
        original = dict(saved)
        app = original.pop("app", "")

        def step(record, app=app, original=original):
            new = dict(record, holders=list(record["holders"]))
            if not new["holders"]:
                new.update(app=app, original=original)
            if dataset not in new["holders"]:
                new["holders"].append(dataset)
            return new, None
        ledger.change(name, step)
        log({"rule": name, "held_by": dataset})

    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".tmp")
    tmp.write_text(json.dumps(todo["checkpoint"], sort_keys=True))
    tmp.replace(target)
    log({"checkpoint": str(target)})

    settings = todo["settings"]
    enabled = settings[f"dataset:{dataset}"].pop("enabled", None)
    for stanza, values in sorted(settings.items()):
        if values:
            _save(rest, stanza, values)
            log({"settings": stanza, "keys": sorted(values)})
    if enabled is not None:
        _save(rest, f"dataset:{dataset}", {"enabled": enabled})
        log({"settings": f"dataset:{dataset}", "keys": ["enabled"]})
    return todo


def _save(rest, stanza, values):
    status, _ = rest.call("POST", f"{CONF}/{urllib.parse.quote(stanza, safe='')}", form=dict(values))
    if status == 404:  # a stanza default/ doesn't have (a local-only feed): create it
        status, _ = rest.call("POST", CONF, form={"name": stanza, **values})
    if not 200 <= status < 300:
        raise MigrateError(f"couldn't save [{stanza}] (HTTP {status})")
