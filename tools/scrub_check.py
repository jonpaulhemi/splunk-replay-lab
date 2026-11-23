#!/usr/bin/env python3
"""Fail if any tracked file names something private: a deny-listed term or a private IP address.

    python3 tools/scrub_check.py                      # every file git tracks
    python3 tools/scrub_check.py path [path ...]      # just these files

The deny-list never lives in this repository. It comes from, in order:
  - the SCRUB_DENYLIST environment variable (one term per line), as CI passes it from a secret;
  - the file named by SCRUB_DENYLIST_FILE;
  - ~/.config/splunk-replay-lab/denylist.txt.
Terms match case-insensitively anywhere in a line. Lines starting with # are comments.

Private IPv4 addresses (10/8, 172.16/12, 192.168/16) are always refused, so lab addresses can't
slip in even without a deny-list. Documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24)
and 127/8 are fine to use in examples. A line containing "scrub: ok" may hold private IPs (for
tests of this check); it never exempts deny-listed terms.

Exit status: 0 clean, 1 hits found, 2 no deny-list (hits on private IPs still exit 1).
"""

import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_FILE = Path.home() / ".config" / "splunk-replay-lab" / "denylist.txt"
IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]  # scrub: ok
ALLOW_IP = "scrub: ok"  # on a line, allows private IPs there (deny-listed terms never are)


def parse_terms(text):
    terms = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            terms.append(line.lower())
    return terms


def load_terms(environ=None, default_file=DEFAULT_FILE):
    """The deny-list terms, and where they came from (None when there is no list)."""
    environ = os.environ if environ is None else environ
    if environ.get("SCRUB_DENYLIST", "").strip():
        return parse_terms(environ["SCRUB_DENYLIST"]), "SCRUB_DENYLIST"
    named = environ.get("SCRUB_DENYLIST_FILE", "").strip()
    for path in ([Path(named)] if named else []) + [Path(default_file)]:
        if path.is_file():
            return parse_terms(path.read_text(encoding="utf-8")), str(path)
    return [], None


def private_ips(line):
    out = []
    for match in IPV4.finditer(line):
        if any(int(part) > 255 for part in match.groups()):
            continue
        address = ipaddress.ip_address(match.group(0))
        if any(address in net for net in PRIVATE):
            out.append(match.group(0))
    return out


def scan_text(text, terms):
    """[(line number, what matched)] for one file's text."""
    hits = []
    for number, line in enumerate(text.splitlines(), 1):
        lowered = line.lower()
        for term in terms:
            if term in lowered:
                hits.append((number, "deny-listed term"))  # never echo the term itself
        for address in ([] if ALLOW_IP in line else private_ips(line)):
            hits.append((number, f"private IP {address}"))
    return hits


def tracked_files(root):
    listing = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True).stdout
    return [Path(root) / name for name in listing.decode("utf-8").split("\0") if name]


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    root = Path(__file__).resolve().parents[1]
    terms, source = load_terms()
    files = [Path(a) for a in argv] if argv else tracked_files(root)
    found = 0
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue  # binaries and removed files
        for number, what in scan_text(text, terms):
            print(f"{path}:{number}: {what}")
            found += 1
    if found:
        print(f"scrub check: {found} hit(s)")
        return 1
    if source is None:
        print("scrub check: no deny-list found (set SCRUB_DENYLIST or create "
              f"{DEFAULT_FILE}); only private IPs were checked")
        return 2
    print(f"scrub check: clean ({len(files)} files, {len(terms)} terms from {source})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
