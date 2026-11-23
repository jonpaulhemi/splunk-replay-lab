# BOTSv2 pack

Plays seven days of Splunk's Boss of the SOC v2 dataset into `index=botsv2_live`, one day per real
day, back to back, with current timestamps.

## The dataset

BOTSv2 is a public capture-the-flag dataset: August 2017 at the same fictional company as BOTSv3,
about 230 million events. It ships as a pre-indexed Splunk app (`index=botsv2`). Get it from
<https://github.com/splunk/botsv2>, follow its instructions, and check the result with
`| tstats count where index=botsv2 earliest=0 by sourcetype`.

## What plays

The pack plays seven UTC days, chosen by surveying raw BOTSv2 for the days on which the most ESCU
detections fire. Each runs at real speed as one 24-hour segment, in this order:

| Segment | Day | Detections | Highlights |
|---|---|---|---|
| seg00 | Aug 24 | 31 | the APT: new local admin, UAC bypass, schtasks as SYSTEM, firewall off, WMI and PowerShell lateral movement |
| seg01 | Aug 19 | 25 | password spray, reg.exe, credentials in the registry |
| seg02 | Aug 26 | 26 | log clearing, executables in temp, MSIExec over HTTP |
| seg03 | Aug 16 | 21 | registry persistence, rundll32 |
| seg04 | Aug 25 | 19 | |
| seg05 | Aug 18 | 21 | password spray, ransomware file extensions |
| seg06 | Aug 10 | 21 | service LOLBAS, a Tor client |

How the segments play:

- `schedule = loop` with 24-hour segments plays segment k mod 7 in period k from the anchor.
- The anchor is a US Eastern midnight, so a segment's 00:00 UTC plays at 00:00 EST. After the
  daylight saving change it plays at 01:00 EDT.
- The attacker's activity falls around 03:00 to 08:00 UTC, early morning Eastern.

Host data plays: Windows logs, Sysmon, registry, host monitoring, PowerShell, Symantec, osquery,
Linux auth and audit, and the Splunk_TA_nix scripted inputs. Network, application and metrics
feeds ship with `enabled = 0`. These include Stream, Suricata, Palo Alto, web servers, MySQL,
collectd, Perfmon and O365.

Windows and Symantec in-text times are US Pacific and Linux text is UTC, both without a zone. The
affected feeds set `text_timezone = local`, and anchoring each event's first in-text time to its
own `_time` removes the 7-hour difference.

## Detections

`[rules] names` lists:

- ES's 24-hour risk rule;
- the 44 ESCU detections that fire on raw BOTSv2;
- one that fires only on the replay.

One detection is left out on purpose: "Windows Deleted Registry By A Non Critical Process File
Path" returned 13,584 results in 10 hours of replay, all of them registry housekeeping.

The risk rule keeps ES's own 24-hour window, because a 24-hour segment plays every hour of the
day.

## Asset and identity lists

`hooks/assets.py` derives the lists from `index=botsv2`.

**Assets**

- Workstations (`wrk-*`) are medium priority, owned by the domain user Sysmon sees on them.
- Domain controllers (hosts with NTDS counters) are critical.
- Symantec broadcast addresses are dropped.

**Identities**

- Users are matched both as `first.last` and as `DOMAIN\first.last`.
- The administrator account is privileged.
