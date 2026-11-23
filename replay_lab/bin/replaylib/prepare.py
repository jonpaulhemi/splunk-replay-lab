"""Prepare dataset: setup, export and assets for one dataset, in that order.

The settings page saves a request on the dataset's stanza (prepare_request = <epoch>:<steps>). The
input on the dataset's named member picks it up on its next tick and runs it in a background
thread (see Runner), so the export lands on the disk that plays it. Each step also runs from the
command line (bin/replay_lab_prepare.py).

Progress goes to `log` as records: {"step", ...} per step and feed, and a summary at the end.
"""

import re
import time
from pathlib import Path

from . import assets as assets_mod
from . import config as config_mod
from . import export as export_mod
from . import setup as setup_mod

STEPS = ("setup", "export", "assets")
REQUEST = re.compile(r"^(\d+):((?:setup|export|assets)(?:,(?:setup|export|assets))*)$")


def parse_request(text):
    """(epoch, [steps]) from a prepare_request value, or None when it's empty or malformed."""
    match = REQUEST.match((text or "").strip())
    if not match:
        return None
    wanted = set(match.group(2).split(","))
    return int(match.group(1)), [s for s in STEPS if s in wanted]


def state_path(cfg):
    """Where setup records its originals: one folder for every dataset, so undo can see what the
    others still need (wherever their data folders are)."""
    return config_mod.data_dir({"dataset": cfg.dataset}).parent / f"{cfg.dataset}.setup.json"


def requires(cfg):
    return [a.strip() for a in cfg.replay.get("requires", "").replace(",", " ").split() if a.strip()]


def run(client, app_dir, cfg, steps, log=print, now=time.time):
    """Run the steps; returns the summary. A failing step stops the ones after it."""
    summary = {"steps": {}, "warnings": [], "started": now()}
    missing = setup_mod.missing_addons(client, requires(cfg))
    if missing:
        summary["warnings"].append("missing add-ons (some detections won't fire): " + ", ".join(missing))
        log({"step": "check", "missing_addons": missing})
    for step in steps:
        log({"step": step, "status": "running"})
        try:
            if step == "setup":
                result = setup_mod.setup(client, cfg, state_path(cfg), log)
                summary["warnings"] += result["warnings"]
                detail = {"changes": result["changes"]}
            elif step == "export":
                manifest = export_mod.export(client, cfg, log=log)
                detail = {"segments": len(manifest.get("segments", [])) or 1}
            else:
                lists = assets_mod.derive(client, app_dir, cfg.dataset, cfg.replay["source_index"], log)
                if lists is not None:
                    assets_mod.upload(client, app_dir, cfg.dataset, log)
                detail = {"assets": len(lists[0]), "identities": len(lists[1])} if lists else {"lists": "none"}
        except Exception as e:
            summary["steps"][step] = {"ok": False, "error": str(e)}
            log({"step": step, "status": "failed", "error": str(e)})
            break
        summary["steps"][step] = {"ok": True, **detail}
        log({"step": step, "status": "done", **detail})
    summary["ok"] = all(s["ok"] for s in summary["steps"].values()) and len(summary["steps"]) == len(steps)
    summary["finished"] = now()
    return summary


def undo_setup(client, cfg, log=print):
    return setup_mod.undo(client, state_path(cfg), log)


def export_info(cfg):
    """What's on this member's disk for the dataset: {"ready", "files", "bytes"}."""
    folder = config_mod.data_dir(cfg.replay)
    if not (folder / "manifest.json").exists():
        return {"ready": False}
    files = [p for p in Path(folder).rglob("*") if p.is_file()]
    return {"ready": True, "files": len(files), "bytes": sum(p.stat().st_size for p in files),
            "at": int((folder / "manifest.json").stat().st_mtime)}
