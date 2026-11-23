"""Derive ES asset and identity lists for BOTSv2 from the dataset itself.

BOTSv2 ships no asset or identity lists, so ES gives every finding the default
priority. This writes lookups/botsv2_assets.csv and lookups/botsv2_identities.csv
in the app; the app's identity_manager inputs register them with ES, which merges
them into its asset and identity lookups within a few minutes. Hosts and users
are the same in index=botsv2 and the replay, so the lists cover both.

How rows are made (heuristics, documented so they can be argued with):
- Assets: every host in index=botsv2. Windows hosts take their FQDN from
  ComputerName and their IP from Symantec Endpoint packet logs. Laptops
  (hostnames ending in -L) are category "workstation", medium priority, owned by
  the user the name starts with (FYODOR-L -> fyodor). Firewalls, Splunk servers
  and domain controllers are critical; other servers are high.
- Identities: every FROTHLY domain user seen running processes in Sysmon (first.last,
  also matched as FROTHLY\\first.last), plus any @froth.ly user seen in O365 and Azure AD logs. Names with
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
    "owners": ('search index={index} source="*Sysmon*" EventCode=1 User="FROTHLY\\\\*" '
               '| stats count by host User | sort host - count | dedup host'),
    "dcs": '| tstats count as ntds where index={index} sourcetype IN ("perfmon:ntds", "msad:nt6:health") by host',
    "users": ('search index={index} (sourcetype="ms:o365:management" OR sourcetype="o365:management:activity" '
              'OR sourcetype="ms:aad:signin" OR sourcetype="ms:aad:audit") '
              '| eval u=lower(coalesce(UserId, userPrincipalName, user)) | search u="*@' + DOMAIN + '" | stats count by u'),
}


def _windows(sourcetypes):
    return any(s.startswith(("wineventlog", "xmlwineventlog", "winhostmon", "perfmonmk", "symantec")) for s in sourcetypes)


def _owner_map(owner_rows):
    """{short host: first.last} from Sysmon's FROTHLY\\first.last on each workstation."""
    out = {}
    for r in owner_rows:
        user = (r.get("User") or "").split("\\")[-1].lower()
        if r.get("host") and user:
            out.setdefault(r["host"].split(".")[0].lower(), user)
    return out


def assets(host_rows, fqdn_rows, ip_rows, users=(), owner_rows=(), dc_rows=()):
    by_host = {}
    for r in host_rows:
        host = (r.get("host") or "").strip()
        if host and "/" not in host and " " not in host:
            by_host.setdefault(host, set()).add((r.get("sourcetype") or "").lower())
    fqdn = {r["host"].split(".")[0].lower(): r["fqdn"] for r in fqdn_rows if r.get("host") and r.get("fqdn")}
    ips = {r["nt_host"].upper(): r["ip"] for r in ip_rows
           if r.get("nt_host") and r.get("ip") and not r["ip"].endswith(".255") and r["ip"] != "0.0.0.0"}
    owners = _owner_map(owner_rows)
    dcs = {(r.get("host") or "").split(".")[0].lower() for r in dc_rows if r.get("ntds")}
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
        laptop = short.upper().endswith("-L") or short.lower().startswith("wrk-")
        owner = ""
        if short.upper().endswith("-L") and short[:-2].lower() in known:
            owner = f"{short[:-2].lower()}@{DOMAIN}"
        if short.lower() in owners:
            owner = f"{owners[short.lower()]}@{DOMAIN}"
        if CRITICAL.search(host) or short.lower() in dcs:
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


def identities(user_rows, owner_rows=()):
    rows = []
    domain_users = sorted(set(_owner_map(owner_rows).values()))
    for user in domain_users:
        first, _, last = user.partition(".")
        privileged = "admin" in user
        rows.append({"identity": f"{user}|FROTHLY\\{user}|{user}@{DOMAIN}", "first": first.title(), "last": last.title(),
                     "email": f"{user}@{DOMAIN}", "priority": "high" if privileged else "medium",
                     "bunit": "frothly", "category": "privileged" if privileged else "employee", "watchlist": "false"})
    seen = {f"{u}@{DOMAIN}" for u in domain_users}
    for user in sorted({(r.get("u") or "").lower() for r in user_rows if r.get("u")} - seen):
        name = user.split("@")[0]
        privileged = "admin" in name
        rows.append({"identity": f"{name}|{user}", "nickname": name, "first": name, "email": user,
                     "priority": "high" if privileged else "medium", "bunit": "frothly",
                     "category": "privileged" if privileged else "employee", "watchlist": "false"})
    return rows


def build(found):
    users = [r["u"] for r in found["users"] if r.get("u")]
    return (assets(found["hosts"], found["fqdn"], found["ip"], users, found["owners"], found["dcs"]),
            identities(found["users"], found["owners"]))
