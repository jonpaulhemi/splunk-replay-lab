"""Point the search head's existing setup for a dataset at its live index too, and undo it (Prepare's setup step).

Every change goes through REST, so a search head cluster replicates it, and each original is
recorded before the change:

- CIM index macros (Splunk_SA_CIM) that name the source index, or another dataset's *_live index,
  also name the live index, so the data models and accelerations cover the replay.
- The admin role's default search indexes include the live index, so detections that name no
  index (most ESCU rules) search it.
- Roles in [dataset] extra_roles, when they exist, may search the live index.
- Accelerated CIM data models owned by Splunk_SA_CIM summarize a rolling 7 days (the live index's
  retention) instead of all time.
- Falcon Search, when installed: its fs_<source>_index macros that name specific indexes also name
  the live index (never fs_Risk_index, which reads ES's risk and notable indexes). Falcon Search's
  own searches are left alone.
- ESCU's summariesonly_config is checked (detections should read raw events), never changed.

Undo takes back only this dataset's part: its index comes out of macros and roles, and a data
model's acceleration window goes back only when no other dataset is set up (otherwise the record
passes to one that is, and goes back when the last is undone).
"""

import json
import re
import urllib.parse
from pathlib import Path

CIM_APP = "Splunk_SA_CIM"
ESCU_APP = "DA-ESS-ContentUpdate"
FS_APP = "FalconSearch"
ACCEL_EARLIEST = "-7d"
_LIVE_INDEX = re.compile(r"index\s*=\s*\"?\w+_live\b")


class SetupError(RuntimeError):
    pass


def _q(name):
    return urllib.parse.quote(name, safe="")


def _content(status, body):
    return body["entry"][0]["content"] if status == 200 and body.get("entry") else None


def _list(value):
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [v for v in str(value).split(";") if v]


def _names_index(definition, index):
    return re.search(rf"index\s*=\s*\"?{re.escape(index)}\"?(?![\w-])", definition) is not None


PATHS = {
    "macro": f"/servicesNS/nobody/{CIM_APP}/configs/conf-macros/{{}}",
    "fs_macro": f"/servicesNS/nobody/{FS_APP}/configs/conf-macros/{{}}",
    "datamodel": f"/servicesNS/nobody/{CIM_APP}/configs/conf-datamodels/{{}}",
    "role": "/services/authorization/roles/{}",
}


def plan(rest, live, source, extra_roles=()):
    """The changes to make: [(kind, target, field, old, new)]."""
    changes = []
    status, body = rest.call("GET", f"/servicesNS/nobody/{CIM_APP}/configs/conf-macros", query={"count": "0"})
    for entry in body.get("entry", []) if status == 200 else []:
        name, definition = entry["name"], entry["content"].get("definition", "")
        if (name.startswith("cim_") and name.endswith("_indexes") and not _names_index(definition, live)
                and (_names_index(definition, source) or _LIVE_INDEX.search(definition))):
            changes.append(("macro", name, "definition", definition, f"({definition.strip()} OR index={live})"))
    status, body = rest.call("GET", f"/servicesNS/nobody/{CIM_APP}/configs/conf-datamodels", query={"count": "0"})
    for entry in body.get("entry", []) if status == 200 else []:
        if (entry.get("acl") or {}).get("app") != CIM_APP:
            continue  # ES's own models (Risk, ...) are listed here too; leave them alone
        content = entry["content"]
        accelerated = str(content.get("acceleration", "")).strip().lower() in ("1", "true", "t", "yes")
        earliest = content.get("acceleration.earliest_time") or ""
        if accelerated and earliest != ACCEL_EARLIEST:
            changes.append(("datamodel", entry["name"], "acceleration.earliest_time", earliest, ACCEL_EARLIEST))
    status, body = rest.call("GET", f"/servicesNS/nobody/{FS_APP}/configs/conf-macros", query={"count": "0"})
    for entry in body.get("entry", []) if status == 200 else []:
        if (entry.get("acl") or {}).get("app") != FS_APP:
            continue
        name, definition = entry["name"], (entry["content"].get("definition") or "").strip()
        if (name.startswith("fs_") and name.endswith("_index") and name != "fs_Risk_index" and definition
                and "index=*" not in definition and not _names_index(definition, live)):
            changes.append(("fs_macro", name, "definition", definition, f"({definition} OR index={live})"))
    for role, field in [("admin", "srchIndexesDefault")] + [(r, "srchIndexesAllowed") for r in extra_roles]:
        content = _content(*rest.call("GET", f"/services/authorization/roles/{_q(role)}"))
        if content is None:
            continue
        current = _list(content.get(field))
        if live not in current:
            changes.append(("role", role, field, current, current + [live]))
    return changes


def unwrap(definition, live):
    """Take out the "(<definition> OR index=<live>)" wrapper setup added, wherever it now sits."""
    tail = f" OR index={live})"
    end = definition.find(tail)
    if end < 0:
        return definition
    depth = 0
    for start in range(end - 1, -1, -1):
        ch = definition[start]
        if ch == ")":
            depth += 1
        elif ch == "(":
            if depth == 0:
                return definition[:start] + definition[start + 1:end] + definition[end + len(tail):]
            depth -= 1
    return definition


def _apply(rest, kind, target, field, value):
    form = {field: value if kind != "role" else (value or [""])}
    status, _ = rest.call("POST", PATHS[kind].format(_q(target)), form=form)
    if status not in (200, 201):
        raise SetupError(f"couldn't set {field} on {kind} {target} (HTTP {status})")


def _read(rest, kind, target, field):
    content = _content(*rest.call("GET", PATHS[kind].format(_q(target))))
    value = (content or {}).get(field)
    return _list(value) if kind == "role" else (value or "")


def check_escu(rest):
    content = _content(*rest.call("GET", f"/servicesNS/nobody/{ESCU_APP}/configs/conf-macros/summariesonly_config"))
    return (content or {}).get("definition")


def missing_addons(rest, required):
    """The required apps that aren't installed (or are disabled)."""
    missing = []
    for app in required:
        content = _content(*rest.call("GET", f"/services/apps/local/{_q(app)}"))
        if content is None or str(content.get("disabled", "0")).lower() in ("1", "true"):
            missing.append(app)
    return missing


def _load(path):
    path = Path(path)
    return json.loads(path.read_text()) if path.exists() else {"changes": []}


def _save(path, state):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True))
    tmp.replace(path)


def setup(rest, cfg, state_path, log=print):
    """Make the changes, recording each original first. Running it twice changes nothing the second time."""
    live, source = cfg.replay["index"], cfg.replay["source_index"]
    extra = [r.strip() for r in cfg.replay.get("extra_roles", "").replace(",", " ").split() if r.strip()]
    state = _load(state_path)
    state.update(live=live)
    done = {(c["kind"], c["target"], c["field"]) for c in state["changes"]}
    applied = 0
    for kind, target, field, old, new in plan(rest, live, source, extra):
        if (kind, target, field) not in done:
            state["changes"].append({"kind": kind, "target": target, "field": field, "old": old, "new": new})
            _save(state_path, state)  # the original first, then the change
        _apply(rest, kind, target, field, new)
        applied += 1
        log({"step": "setup", "change": f"{kind} {target}: {field}"})
    escu = check_escu(rest)
    warnings = []
    only = re.search(r"summariesonly\s*=\s*(\w+)", str(escu or ""))
    if only and only.group(1).lower() in ("1", "t", "true"):
        warnings.append(f"ESCU summariesonly_config is {escu!r}: detections read data model summaries only")
    return {"changes": applied, "warnings": warnings}


def _hand_over(this, change):
    """Give a shared change (a data model's 7-day window) to another prepared dataset, which puts
    it back when it is undone in turn. False when no other dataset is set up."""
    others = sorted(p for p in Path(this).parent.glob("*.setup.json") if p.name != Path(this).name)
    if not others:
        return False
    state = _load(others[0])
    if not any((c["kind"], c["target"], c["field"]) == (change["kind"], change["target"], change["field"])
               for c in state["changes"]):
        state["changes"].insert(0, change)  # undone last, like the first change it made
        _save(others[0], state)
    return True


def undo(rest, state_path, log=print):
    path = Path(state_path)
    if not path.exists():
        log({"step": "undo", "note": "nothing to put back"})
        return 0
    state = _load(path)
    live = state.get("live", "")
    undone = 0
    while state["changes"]:
        c = state["changes"][-1]
        kind, target, field = c["kind"], c["target"], c["field"]
        current = _read(rest, kind, target, field)
        if kind == "role":
            value = [i for i in current if i != live]
        elif kind in ("macro", "fs_macro"):
            value = unwrap(current, live)  # another dataset may have wrapped it since
        else:  # datamodel acceleration: shared by every dataset
            value = None if _hand_over(path, c) else c["old"]
        if value is not None and value != current:
            _apply(rest, kind, target, field, value)
            log({"step": "undo", "change": f"{kind} {target}: {field}"})
            undone += 1
        state["changes"].pop()
        _save(path, state)
    path.unlink()
    return undone
