# Methodology

## Goal

The goal is a steady daily findings queue for triage tooling, training and demos. ES detections
fire on their normal schedules over data with current timestamps. False positives are as useful
as true positives.

Two principles follow from that:

- Data formats are fixed where a fix makes more detections fire.
- Every change the app makes to the box is recorded so it can be undone.

## Choices and their reasons

| Choice | Why |
|---|---|
| Replay real events. Relabel only, and translate formats only when a feed opts in (translated events carry `replay_lab_synthetic=1`) | Detections should see the dataset, not an imitation of it |
| One stream at real speed | Burst and rate detections need the original spacing |
| One-time export to disk, then a modular input that ticks every 30 s | The replay needs no HEC token and no search load at play time; the same export always plays the same way |
| Daily or loop schedule | `daily` gives a workday rhythm, a quiet night and one finding per entity per day. `loop` gives continuous data |
| Segments | A month-long dataset plays its best days in turn, one per period |
| 7-day live index | Long enough for weekly baselines, short enough that the data and its accelerations stay small |
| Data fixes at replay time | Fixing a feed needs no re-export |

## Time shifting

Each event's `_time` and every timestamp in its text move by the same whole-second offset, so the
spacing between events is kept.

**Formats shifted:** ISO 8601, US (including Windows' 24-hour clock with an AM/PM suffix),
CLF/Apache/S3, RFC 2822, compact, glog, syslog, ctime, and epoch (seconds or milliseconds). A
feed's `timestamp_formats` narrows the list.

**What moves.** A value moves only if it parses and falls inside the window, give or take a day.
Formats with a year may be up to 400 days before the window. Anything else is left as it is.

**Zone-less text.** Splunk reads it in the indexer's time zone. Feeds whose `_time` comes from
such text set `text_timezone = local`, so the shifted text is written in the indexer's zone.
Text that carries a zone (`Z`, `+0000`, `UTC`) stays in UTC.

For those feeds, each event's first zone-less time is also anchored to the event's own `_time`:

- A whole-hour difference is measured per event and removed. This covers BOTSv3's Windows text,
  which is sometimes 12 hours behind with the wrong AM/PM.
- A first date more than 14 hours from the event's time is stale, and becomes the event's time.

`DATETIME_CONFIG = NONE` is set for the exact sourcetype names where Splunk can't take the time
from the text. It applies only to the names the replay writes, so real add-on data in another
case is untouched.

## The export

The export reads each feed as `search index=<source_index> <feed search>` and writes gzipped
hourly JSON-lines files per feed, plus a manifest.

- **Atomic.** It writes beside the data folder and swaps in only when complete.
- **Exact sourcetype case.** It takes the indexed name from `| metadata` (tstats lowercases it),
  and from the source for Windows logs. This lets case-sensitive add-on stanzas apply.
- **Whole events.** It runs in this app's context, where the packs set `KV_MODE = none` for
  table-shaped sourcetypes (Splunk_TA_nix `ps`, `top`, `df`, ..., and `perfmonmk:process`).
  Those stanzas are not exported, so ES still sees rows. The export stops and names any feed that
  still returns more results than events.
- **Robust parsing.** `_time` is carried as epoch seconds, because the export endpoint returns it
  as text. Bytes that aren't UTF-8 are decoded with replacement.

## Playing

Each dataset has its own input process, checkpoint, status log and status record.

- **Ticks.** Every `tick_seconds`, the input emits the events that came due since the last tick
  and saves its position.
- **Switching on and off.** `enabled` is re-read every tick, and switching on starts from now.
- **Downtime.** After downtime longer than `max_catchup_seconds`, the input skips ahead instead of
  flooding.
- **Clusters.** On a cluster only the member named in `run_on` plays. The others stay on standby.

## Detections

While a dataset plays, the detections its pack lists are switched on and scheduled, and when it
stops they go back exactly as they were.

**What the app changes:** `disabled`, `is_scheduled` and, when set, `alert.suppress.period`. On
the risk rule it may also change `search` (the skip marker), `dispatch.earliest_time` and
`alert.suppress.fields`. It never changes alert actions.

**Shared rules.** Ownership is kept in the `replay_lab_rules` KV collection:

- The first dataset to change a rule records its original settings.
- The last one to stop puts them back.
- Each change is made under a claim on the record's next version. A member whose KV copy lags
  re-reads instead of recording a switched-on rule as its original.

**Daily resets.** When a day or period starts, `reset_lookups` are emptied and `reset_searches`
run, so first-seen detections fire again.

**Risk rule.** ES sums risk over 24 hours and throttles for 24 hours. A once-a-day replay then
keeps entities over the threshold overnight, and their findings arrive when the throttle expires,
after the workday. The BOTSv3 pack changes four settings while it plays:

- it sums 8 hours (`risk_earliest = -490m@m`);
- it throttles 20 hours (`suppress_period = 72000`);
- it keys the throttle on the entity alone (`risk_suppress_fields`). ES's own key includes
  `source_count`, which fires again for every new contributing detection;
- it skips the placeholder entities `unknown` and `null`.

## Choosing detections

`tools/survey.py rules <pack> ... --raw` runs every ESCU detection that has a risk action over the
raw dataset:

- as ad hoc search jobs in ESCU's app context, so no alert action runs;
- four at a time, with a 120-second timeout each;
- skipping searches that write.

The packs list what fired. Earlier surveys ran over ESCU 6.10.0's TTP and Anomaly detections:
1,240 for BOTSv3 and 1,516 for BOTSv2 and DEDALE.

**BOTSv3:** 38 detections fire on the raw dataset, and 15 more fire on the fixed data. 11 never
complete: 4 write, 2 time out, and 5 need lookups the box doesn't have.

ESCU's `allow_skew` lets hourly detections start up to about 59 minutes late. Their search windows
are relative to the scheduled time, so nothing is missed.

## Problems this design avoids

Each of these happened in the earlier single-dataset apps:

- the export endpoint returning `_time` as text;
- payloads that aren't UTF-8;
- table sourcetypes splitting one event into rows (2.84 M results for 1.94 M events);
- an upgrade wiping the asset CSVs;
- zone-less text read in the indexer's zone (hours ahead, then 12 hours behind for Windows);
- lowercase sourcetypes that broke Splunk_TA_windows' case-sensitive props, so two detections
  never fired;
- a 7-day acceleration that also changed ES's own data models;
- many findings on `unknown` and `null`;
- findings landing after the workday;
- a throttle key that fired again for each new contributing detection.

## Known limits

- **Old events stay.** Events sent before a fix stay in the live index until they age out after
  7 days. Filter on `_indextime` to see only new ones.
- **First-seen burst.** First-seen detections burst early each day, by design.
- **A sparse stretch.** BOTSv3 has about 40 sparse minutes mid-day.
- **Ground truth.** The replay doesn't carry dataset labels. Grade findings against the source
  index (DEDALE's `dedale_label`).
