#!/usr/bin/env python3
"""Move a dataset from its earlier single-dataset app to replay_lab, keeping its place.

    SPLUNK_PASSWORD=... splunk cmd python3 replay_lab_migrate.py botsv3_replay https://localhost:8089 --ca-file ca.pem
    SPLUNK_PASSWORD=... splunk cmd python3 replay_lab_migrate.py dedale_replay https://localhost:8089 --dry-run

Run it on the member that played the old app, after disabling that app. It carries the old
checkpoint, the old app's local settings and its saved rule originals (into the shared KV
records), and points data_dir at the old export, or copies the export with --copy-export. See
replaylib/migrate.py.
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from replaylib import migrate  # noqa: E402
from replaylib.splunkd import Client  # noqa: E402

APP_DIR = Path(__file__).resolve().parent.parent


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("old_app", choices=sorted(migrate.OLD_APPS))
    parser.add_argument("url", help="splunkd management URL, such as https://localhost:8089")
    parser.add_argument("--user", default="admin")
    parser.add_argument("--ca-file")
    parser.add_argument("--insecure", action="store_true", help="skip TLS verification (a local test box only)")
    parser.add_argument("--copy-export", action="store_true", help="copy the old export to replay_lab's data folder")
    parser.add_argument("--force", action="store_true",
                        help="go ahead with the old app enabled, or over an existing checkpoint")
    parser.add_argument("--dry-run", action="store_true", help="show what would be done; change nothing")
    args = parser.parse_args(argv)
    home = os.environ.get("SPLUNK_HOME", "/opt/splunk")
    log = lambda record: print(json.dumps(record, sort_keys=True), flush=True)  # noqa: E731
    try:
        if args.dry_run:
            log(migrate.plan(home, args.old_app, APP_DIR, args.copy_export))
            return 0
        password = os.environ.get("SPLUNK_PASSWORD")
        if not password:
            parser.error("set SPLUNK_PASSWORD")
        client = Client(args.url, user=args.user, password=password, ca_file=args.ca_file, verify=not args.insecure)
        todo = migrate.run(client, home, args.old_app, APP_DIR, args.copy_export, args.force, log)
    except migrate.MigrateError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    log({"done": todo["dataset"], "next": "remove the old app once the replay shows it playing"})
    return 0


if __name__ == "__main__":
    sys.exit(main())
