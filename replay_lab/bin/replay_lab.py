#!/usr/bin/env python3
"""Modular input: replay one dataset's export into its live index in real time.

splunkd starts one process per replay_lab://<dataset> stanza. Settings live in replay_lab.conf
([dataset:<name>] enabled = 1 switches it on); the input stanza only starts the process.
"""

import json
import os
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from replaylib.ledger import KvLedger  # noqa: E402
from replaylib.rules import Rest, Rules  # noqa: E402
from replaylib.runner import SCHEME, Runner  # noqa: E402
from replaylib.status import StatusKv  # noqa: E402

SCHEME_XML = """<scheme>
  <title>Replay lab</title>
  <description>Replays one dataset's export with current timestamps.</description>
  <use_external_validation>false</use_external_validation>
  <use_single_instance>false</use_single_instance>
  <streaming_mode>xml</streaming_mode>
  <endpoint><args/></endpoint>
</scheme>
"""


def status_writer(dataset, home=None):
    """One JSON line per record in $SPLUNK_HOME/var/log/replay_lab/<dataset>.log, tagged with the dataset."""
    home = os.environ.get("SPLUNK_HOME", "") if home is None else home
    folder = Path(home) / "var" / "log" / "replay_lab" if home else None
    if folder:
        folder.mkdir(parents=True, exist_ok=True)

    def write(record):
        line = json.dumps({"dataset": dataset, **record}, sort_keys=True)
        if folder:
            with open(folder / f"{dataset}.log", "a", encoding="utf-8") as f:
                f.write(line + "\n")
        else:
            sys.stderr.write(line + "\n")
    return write


def dataset_of(root):
    """The dataset this process plays, from its one <stanza name="replay_lab://<dataset>">."""
    for stanza in root.iter("stanza"):
        name = stanza.get("name", "")
        if name.startswith(SCHEME + "://"):
            return name[len(SCHEME) + 3:]
    raise ValueError("no replay_lab:// stanza in the input configuration")


def main(argv):
    if "--scheme" in argv:
        sys.stdout.write(SCHEME_XML)
        return 0
    if "--validate-arguments" in argv:
        return 0
    root = ET.fromstring(sys.stdin.read())
    dataset = dataset_of(root)
    checkpoint_dir = root.findtext("checkpoint_dir") or "."
    app_dir = Path(__file__).resolve().parent.parent
    log = status_writer(dataset)
    rest = Rest(root.findtext("server_uri") or "https://127.0.0.1:8089", root.findtext("session_key") or "")
    server = root.findtext("server_host") or ""
    kv = StatusKv(rest, dataset, server)

    def status(record):  # every record to the log; the latest state to the page's KV record
        log(record)
        kv(record)

    def rules(cfg):
        return Rules(rest, cfg.rules, cfg.reset_lookups, cfg.reset_searches, log=status,
                     suppress_period=cfg.suppress_period, skip_risk_objects=cfg.skip_risk_objects,
                     risk_earliest=cfg.risk_earliest,
                     risk_suppress_fields=cfg.risk_suppress_fields)
    runner = Runner(app_dir, Path(checkpoint_dir) / f"{dataset}.json", sys.stdout,
                    status=status, now=time.time, sleep=time.sleep, rules=rules,
                    server_name=server, dataset=dataset,
                    ledger=lambda: KvLedger(dataset, rest))
    runner.run()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
