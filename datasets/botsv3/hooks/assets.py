"""Derive ES asset and identity lists for BOTSv3 from the dataset itself.

BOTSv3 ships no asset or identity lists, so ES gives every finding the default
priority. This writes lookups/botsv3_assets.csv and lookups/botsv3_identities.csv
in the app; the app's identity_manager inputs register them with ES, which merges
them into its asset and identity lookups within a few minutes. Hosts and users
are the same in index=botsv3 and the replay, so the lists cover both.

How rows are made (heuristics, documented so they can be argued with):
- Assets: every host in index=botsv3. Windows hosts take their FQDN from
  ComputerName and their IP from Symantec Endpoint packet logs. Laptops
  (hostnames ending in -L) are category "workstation", medium priority, owned by
  the user the name starts with (FYODOR-L -> fyodor). Firewalls, Splunk servers
  and domain controllers are critical; other servers are high.
- Identities: every @froth.ly user seen in O365 and Azure AD logs. Names with
  "admin" in them are category "privileged" and high priority; the rest are
  "employee" and medium.
"""

import re

DOMAIN = "froth.ly"
CRITICAL = re.compile(r"(?i)(^|[-.])(fw|firewall|dc\d*|splunk\w*|sepm)($|[-.\d])")

SEARCHES = {
    "hosts": "| tstats count where index={index} by host, sourcetype",
    "fqdn": 'search index={index} source="WinEventLog:*" ComputerName=* | stats latest(ComputerName) as fqdn by host',
    "ip": ('search index={index} sourcetype="symantec:ep:packet:file" '
           '| rex "^[^,]+,(?<nt_host>[^,]+),Local: (?<ip>[0-9.]+)," | stats latest(ip) as ip by nt_host'),
    "users": ('search index={index} (sourcetype="ms:o365:management" OR sourcetype="o365:management:activity" '
              'OR sourcetype="ms:aad:signin" OR sourcetype="ms:aad:audit") '
              '| eval u=lower(coalesce(UserId, userPrincipalName, user)) | search u="*@' + DOMAIN + '" | stats count by u'),
}


def _windows(sourcetypes):
    return any(s.startswith(("wineventlog", "xmlwineventlog", "winhostmon", "perfmonmk", "symantec")) for s in sourcetypes)


def assets(host_rows, fqdn_rows, ip_rows, users=()):
    by_host = {}
    for r in host_rows:
        host = (r.get("host") or "").strip()
        if host and "/" not in host and " " not in host:
            by_host.setdefault(host, set()).add((r.get("sourcetype") or "").lower())
    fqdn = {r["host"].split(".")[0].lower(): r["fqdn"] for r in fqdn_rows if r.get("host") and r.get("fqdn")}
    ips = {r["nt_host"].upper(): r["ip"] for r in ip_rows if r.get("nt_host") and r.get("ip")}
    known = {u.split("@")[0] for u in users}
    # One asset per short name: "gacrux", "GACRUX" and "gacrux.froth.ly" are one host, and ES
    # merges rows that share an nt_host anyway. Prefer the dotted name, then the lowercase one.
    merged = {}
    for host in sorted(by_host, key=lambda h: (h.split(".")[0].lower(), "." not in h, h != h.lower(), h)):
        key = host.split(".")[0].lower()
        if key in merged:
            by_host[merged[key]] |= by_host[host]
        else:
            merged[key] = host
    rows = []
    for host in sorted(merged.values(), key=str.lower):
        short = host.split(".")[0]
        laptop = short.upper().endswith("-L")
        owner = ""
        if laptop and short[:-2].lower() in known:
            owner = f"{short[:-2].lower()}@{DOMAIN}"
        if CRITICAL.search(host):
            priority, category = "critical", "server|critical"
        elif laptop:
            priority, category = "medium", "workstation"
        else:
            priority, category = "high", "server"
        if _windows(by_host[host]):
            category += "|windows"
        rows.append({"ip": ips.get(short.upper(), ""), "nt_host": short, "dns": fqdn.get(short.lower(), host),
                     "owner": owner, "priority": priority, "bunit": "frothly", "category": category,
                     "is_expected": "true" if not laptop else "false",
                     "should_update": "true", "requires_av": "true" if _windows(by_host[host]) else "false"})
    return rows


def identities(user_rows):
    rows = []
    for user in sorted({(r.get("u") or "").lower() for r in user_rows if r.get("u")}):
        name = user.split("@")[0]
        privileged = "admin" in name
        rows.append({"identity": f"{name}|{user}", "nickname": name, "first": name, "email": user,
                     "priority": "high" if privileged else "medium", "bunit": "frothly",
                     "category": "privileged" if privileged else "employee", "watchlist": "false"})
    return rows


def build(found):
    users = [r["u"] for r in found["users"] if r.get("u")]
    return assets(found["hosts"], found["fqdn"], found["ip"], users), identities(found["users"])
