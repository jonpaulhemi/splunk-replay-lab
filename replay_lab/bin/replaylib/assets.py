"""ES asset and identity lists for a dataset, derived from its source index (Prepare's assets step).

A pack that has lists ships hooks/assets.py (built into bin/datasets/<name>/assets.py) with:

    SEARCHES = {"key": "SPL with {index}", ...}   run against the source index ({index} is the
                                                    only placeholder; other braces are left as they are)
    def build(found): -> (asset rows, identity rows)   found = {"key": [result, ...]}

This step runs the searches, writes lookups/<name>_assets.csv and <name>_identities.csv, and
registers them through splunkd (data/lookup-table-files), so a search head cluster replicates
them. The pack's identity_manager inputs then hand them to ES.
"""

import csv
import importlib.util
import io
import os
import shutil
from pathlib import Path

ASSET_FIELDS = ["ip", "mac", "nt_host", "dns", "owner", "priority", "lat", "long", "city", "country", "bunit",
                "category", "pci_domain", "is_expected", "should_timesync", "should_update", "requires_av"]
IDENTITY_FIELDS = ["identity", "prefix", "nickname", "first", "last", "suffix", "email", "phone", "phone2",
                   "managedBy", "priority", "bunit", "category", "watchlist", "startDate", "endDate"]


def hook(app_dir, dataset):
    """The pack's assets hook module, or None when the pack has no lists."""
    path = Path(app_dir) / "bin" / "datasets" / dataset / "assets.py"
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location(f"replay_lab_assets_{dataset}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def to_csv(fields, rows):
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=fields, restval="", lineterminator="\n", extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue()


def derive(client, app_dir, dataset, index, log=print):
    module = hook(app_dir, dataset)
    if module is None:
        log({"step": "assets", "note": "this pack has no asset or identity lists"})
        return None
    found = {key: list(client.export(spl.replace("{index}", index))) for key, spl in module.SEARCHES.items()}
    asset_rows, identity_rows = module.build(found)
    folder = Path(app_dir) / "lookups"
    folder.mkdir(exist_ok=True)
    (folder / f"{dataset}_assets.csv").write_text(to_csv(ASSET_FIELDS, asset_rows))
    (folder / f"{dataset}_identities.csv").write_text(to_csv(IDENTITY_FIELDS, identity_rows))
    log({"step": "assets", "assets": len(asset_rows), "identities": len(identity_rows)})
    return asset_rows, identity_rows


def upload(client, app_dir, dataset, log=print):
    """Register the two CSVs through splunkd. Runs on the member itself: splunkd reads the staged
    file from its own lookup_tmp folder."""
    home = Path(os.environ.get("SPLUNK_HOME", "/opt/splunk"))
    staging = home / "var" / "run" / "splunk" / "lookup_tmp"
    staging.mkdir(parents=True, exist_ok=True)
    for name in (f"{dataset}_assets.csv", f"{dataset}_identities.csv"):
        staged = staging / name
        shutil.copyfile(Path(app_dir) / "lookups" / name, staged)
        status, _ = client.call("POST", f"/servicesNS/nobody/replay_lab/data/lookup-table-files/{name}",
                                form={"eai:data": str(staged)})
        if status == 404:
            status, _ = client.call("POST", "/servicesNS/nobody/replay_lab/data/lookup-table-files",
                                    form={"eai:data": str(staged), "name": name})
        if status not in (200, 201):
            raise RuntimeError(f"couldn't register {name} (HTTP {status})")
        log({"step": "assets", "uploaded": name})
