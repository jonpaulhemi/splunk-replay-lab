"""Derive ES asset and identity lists for the EXAMPLE dataset from its source index.

Prepare dataset's assets step runs each search in SEARCHES against the source index ({index} is
filled in; no other placeholder is) and hands the results to build(). Write the heuristics down
here, so they can be argued with:

- Assets: every host in the index. Names with "dc" or "fw" in them are critical; the rest medium.
- Identities: every user seen in authentication events, all "employee".

Standard library only; it runs on Splunk's bundled Python.
"""

import re

DOMAIN = "example.com"
CRITICAL = re.compile(r"(?i)(^|[-.])(dc\d*|fw\d*)($|[-.])")

SEARCHES = {
    "hosts": "| tstats count where index={index} by host",
    "users": "search index={index} tag=authentication user=* | stats count by user",
}


def build(found):
    """(asset rows, identity rows) from {"hosts": [...], "users": [...]}. Columns not given are empty."""
    assets = []
    for row in sorted(found["hosts"], key=lambda r: r.get("host", "").lower()):
        host = row.get("host", "")
        if not host:
            continue
        short = host.split(".")[0]
        assets.append({"nt_host": short, "dns": host if "." in host else f"{short}.{DOMAIN}",
                       "priority": "critical" if CRITICAL.search(host) else "medium",
                       "category": "example", "bunit": "example"})
    identities = []
    for user in sorted({(r.get("user") or "").lower() for r in found["users"]} - {""}):
        identities.append({"identity": user, "email": f"{user}@{DOMAIN}", "priority": "medium",
                           "category": "employee", "bunit": "example"})
    return assets, identities
