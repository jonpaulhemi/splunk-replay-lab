#!/usr/bin/env python3
"""Run Prepare dataset's steps from the command line, on the member that plays the dataset.

    SPLUNK_PASSWORD=... python3 replay_lab_prepare.py botsv3 https://localhost:8089 --user admin --ca-file ca.pem
    SPLUNK_PASSWORD=... python3 replay_lab_prepare.py botsv3 https://localhost:8089 --steps export
    SPLUNK_PASSWORD=... python3 replay_lab_prepare.py botsv3 https://localhost:8089 --undo-setup

Steps: setup (point the box's CIM macros, roles and accelerations at the live index, with undo),
export (the source index to this member's disk), assets (ES asset and identity lists). Default: all
three. Switch the dataset off first; the export replaces the files the replay reads.
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from replaylib import config as config_mod  # noqa: E402
from replaylib import prepare  # noqa: E402
from replaylib.splunkd import Client  # noqa: E402

APP_DIR = Path(__file__).resolve().parent.parent


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dataset", help="one of: " + ", ".join(config_mod.datasets(APP_DIR)))
    parser.add_argument("url", help="splunkd management URL, such as https://localhost:8089")
    parser.add_argument("--user", default="admin")
    parser.add_argument("--ca-file")
    parser.add_argument("--insecure", action="store_true", help="skip TLS verification (a local test box only)")
    parser.add_argument("--steps", default="setup,export,assets")
    parser.add_argument("--undo-setup", action="store_true", help="put back what setup changed for this dataset")
    args = parser.parse_args(argv)
    if args.dataset not in config_mod.datasets(APP_DIR):
        parser.error(f"no dataset {args.dataset!r}")
    password = os.environ.get("SPLUNK_PASSWORD")
    if not password:
        parser.error("set SPLUNK_PASSWORD")
    client = Client(args.url, user=args.user, password=password, ca_file=args.ca_file, verify=not args.insecure)
    cfg = config_mod.load(APP_DIR, args.dataset)
    log = lambda record: print(json.dumps(record, sort_keys=True), flush=True)  # noqa: E731
    if args.undo_setup:
        prepare.undo_setup(client, cfg, log)
        return 0
    if cfg.enabled:
        parser.error(f"{args.dataset} is on: switch it off first")
    steps = [s for s in prepare.STEPS if s in args.steps.split(",")]
    summary = prepare.run(client, APP_DIR, cfg, steps, log)
    log({"summary": summary})
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
