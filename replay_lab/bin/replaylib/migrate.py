"""Move a dataset from its earlier single-dataset app (botsv3_replay, botsv2_replay, dedale_replay)
to replay_lab, so the replay continues where the old app stopped.

Run on the member that played the old app, with the old app disabled (two apps writing one live
index would double every event). In order:

1. Rule originals from the old checkpoint go into the replay_lab_rules KV records, with this
   dataset as a holder. A rule another dataset already holds keeps the original recorded first.
2. The old checkpoint (anchor, position, which rules are on) becomes the dataset's checkpoint. A
   running input picks it up on its next tick, and keeps it for 10 minutes even while the
   dataset is still off, so the settings below have time to arrive.
3. The old app's local settings become [dataset:<name>], [feed:<name>:<feed>] and [rules:<name>]
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


def read_local(path):
    """{stanza: {key: value}} from the old app's local conf, or {} when it has none."""
    parser = configparser.RawConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    if Path(path).exists():
        parser.read(path)
    return {s: dict(parser.items(s)) for s in parser.sections()}


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
    local = read_local(p["local"])
    settings = stanzas(dataset, local)
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


def old_app_disabled(rest, old_app):
    status, body = rest.call("GET", f"/services/apps/local/{urllib.parse.quote(old_app, safe='')}")
    if status == 404:
        return True  # already removed
    content = (body.get("entry") or [{}])[0].get("content") or {}
    return str(content.get("disabled", "0")).lower() in ("1", "true")


def run(rest, home, old_app, app_dir, copy_export=False, force=False, log=print, now=time.time):
    todo = plan(home, old_app, app_dir, copy_export, now)
    dataset = todo["dataset"]
    for warning in todo["warnings"]:
        log({"warning": warning})
    if not force and not old_app_disabled(rest, old_app):
        raise MigrateError(f"disable {old_app} first: two apps playing one live index double every event")
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
