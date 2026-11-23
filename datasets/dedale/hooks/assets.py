"""Derive ES asset and identity lists for DEDALE from index=dedale.

DEDALE ships no asset or identity lists. This writes lookups/dedale_assets.csv and
lookups/dedale_identities.csv, which the app's identity_manager inputs register with ES:

- Assets: every host. Windows clients (CLIENTn) are workstations, medium priority, owned by
  the BREACH domain user Sysmon shows on them (BREACH\\client2 on CLIENT2). The internal
  server runs Samba AD (the domain controller and file server) and is critical; the other
  Linux servers (DMZ, web, VPN) are high. extcompanyclient is a partner's machine outside the
  company, low priority. Each Windows asset's dns is its FQDN (CLIENT2.breach.local).
- Identities: every BREACH user seen running processes, matched as clientn, BREACH\\clientn and
  clientn@breach.local. Names with "admin" in them are privileged and high priority.
"""

DOMAIN = "breach.local"
SERVERS = {"internalserver": ("critical", "server|critical|domain_controller"),
           "dmzserver": ("high", "server|dmz"), "webserver": ("high", "server|dmz|web"),
           "vpnserver": ("high", "server|dmz|vpn"), "extcompanyclient": ("low", "external")}

SEARCHES = {
    "hosts": "| tstats count where index={index} by host, sourcetype",
    "owners": ('search index={index} source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 '
               'User="BREACH\\\\*" | stats count by host User | sort host - count | dedup host'),
}


def assets(host_rows, owner_rows):
    hosts = {}
    for r in host_rows:
        if r.get("host"):
            hosts.setdefault(r["host"], set()).add((r.get("sourcetype") or "").lower())
    owners = {r["host"].lower(): r["User"].split("\\")[-1].lower() for r in owner_rows
              if r.get("host") and r.get("User")}
    rows = []
    for host in sorted(hosts, key=str.lower):
        windows = "xmlwineventlog" in hosts[host]
        short = host.split(".")[0]
        if short.lower() in SERVERS:
            priority, category = SERVERS[short.lower()]
        elif windows:
            priority, category = "medium", "workstation"
        else:
            priority, category = "high", "server"
        if windows:
            category += "|windows"
        owner = owners.get(short.lower())
        rows.append({"nt_host": short, "dns": f"{short}.{DOMAIN}" if windows else short,
                     "owner": f"{owner}@{DOMAIN}" if owner else "", "priority": priority, "bunit": "breach",
                     "category": category, "is_expected": "true" if category.startswith("server") else "false",
                     "should_update": "true", "requires_av": "true" if windows else "false"})
    return rows


def identities(owner_rows):
    rows = []
    for user in sorted({r["User"].split("\\")[-1].lower() for r in owner_rows if r.get("User")}):
        privileged = "admin" in user
        rows.append({"identity": f"{user}|BREACH\\{user}|{user}@{DOMAIN}", "first": user, "email": f"{user}@{DOMAIN}",
                     "priority": "high" if privileged else "medium", "bunit": "breach",
                     "category": "privileged" if privileged else "employee", "watchlist": "false"})
    return rows


def build(found):
    return assets(found["hosts"], found["owners"]), identities(found["owners"])
