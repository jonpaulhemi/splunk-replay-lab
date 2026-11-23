# BOTSv3 pack

Plays one workday of Splunk's Boss of the SOC v3 dataset into `index=botsv3_live` each day at real
speed, from 09:00 US Eastern, with current timestamps.

## The dataset

BOTSv3 is a public capture-the-flag dataset of a fictional brewing company: 1,944,092 events in
107 sourcetypes (about 1.06 GB), nearly all on 2018-08-20 between 09:00 and 15:30 UTC. It ships
as a pre-indexed Splunk app.

- Source: <https://github.com/splunk/botsv3>
- Download: `https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz` (320 MB, MD5
  `d7ccca99a01cff070dff3c139cdc10eb`)

## Loading it into Splunk

1. Check the MD5, untar it into `$SPLUNK_HOME/etc/apps/` (it makes the `botsv3_data_set` app,
   whose data is in `index=botsv3`), and restart.
2. Check: `| tstats count where index=botsv3 earliest=0 by sourcetype` shows 107 sourcetypes.

On a cluster, the source index only has to be searchable from the member that plays the dataset,
for the one-time export.

## What plays

- **Window:** 2018-08-20 09:00 to 15:30 UTC (`window_start = 1534755600`,
  `window_end = 1534779000`). That is where nearly all of BOTSv3 is. One stray
  `ess_content_importer` event from 2019 is left out.
- **Schedule:** `daily`. The 6.5-hour workday plays once a day from 09:00 America/New_York, and
  nothing plays the rest of the day. `loop` repeats it back to back instead, about 3.7 times a
  day.
- **Hourly shape:** about 335,000 to 390,000 events an hour until 12:00 UTC, a quiet hour, then
  205,000 to 300,000 an hour. About 40 minutes, roughly 3 h 20 min into the day, are sparse.

### Data fixes

All of these apply at replay time.

- Windows feeds select by `source`, because Splunk_TA_windows renames their sourcetypes at search
  time. `set_sourcetype` writes the exact indexed name, so the renames and extractions still
  apply.
- Sysmon is replayed under `source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, the
  source the Sysmon add-on expects. Under BOTSv3's own source, its 9,212 events get no CIM fields
  or tags.
- osquery process events get `columns.event_type=exec` (`json_set`), which the `osquery-process`
  eventtype needs.
- Feeds whose `_time` Splunk reads from zone-less text set `text_timezone = local`. These include
  Windows event logs, cisco:asa, syslog and Symantec. BOTSv3's Windows text is sometimes 12 hours
  off with the wrong AM/PM; each event's first in-text time is anchored to its own `_time`.
- `props.conf` keeps table-shaped Splunk_TA_nix sourcetypes (`ps`, `top`, `df`, ...) whole in this
  app's context. That lets the export get whole events, while ES still sees rows.

## Detections

`[rules] names` lists ES's 24-hour risk rule and 53 ESCU detections:

- 38 that fire on raw BOTSv3;
- 15 more that fire only on the fixed data (Sysmon registry and file events, Sysmon for Linux).

The list comes from `tools/survey.py rules botsv3 ... --raw` against ESCU's TTP and Anomaly
detections. Rerun the survey after an ESCU upgrade, since ESCU renames and retires detections.

While BOTSv3 plays, the risk rule changes as follows, and every change goes back when the dataset
is switched off:

- It sums the workday: `risk_earliest = -490m@m`, which is 8 hours ending at ES's -10m@m.
- It throttles for 20 hours: `suppress_period = 72000`.
- It keys the throttle on the entity only: `risk_suppress_fields = normalized_risk_object,
  risk_object_type`.
- It skips placeholder entities: `skip_risk_objects = unknown, null`.

The effect is one finding per entity per day, during work hours. `reset_lookups` empties
`previously_seen_running_windows_services` at each day's start, so first-seen detections fire
daily.

## Asset and identity lists

`hooks/assets.py` derives the lists from `index=botsv3`.

**Assets**

- Every host in the index is an asset.
- Hosts that differ only by case or domain are merged into one.
- Windows hosts take their FQDN from `ComputerName` and their IP from Symantec packet logs.
- Laptops (`*-L`) are medium priority and owned by their user.
- Firewalls, Splunk servers and domain controllers are critical. Other servers are high.

**Identities**

- Every domain user in the O365 and Azure AD logs is an identity.
- Names containing "admin" are privileged.
