# Validation

## Offline

```
python3 -m pytest -q
```

The tests need no Splunk. They run the engine against fakes:

- a clock, checkpoints and the XML stream;
- the search export endpoint, including `_time` as text, non-UTF-8 bytes and split rows;
- saved-search, conf, role and KV store endpoints;
- a settings page in a headless browser.

They also run real BOTSv3 sample events (`tests/fixtures/botsv3_samples/`, 46 sourcetypes). Two
builds of one commit must be byte-identical.

## Live checks

Run these on a lab box, in order. In anything you save or share, mask account IDs and never
include passwords or tokens.

### Install and Prepare

1. **Setup.** Prepare's summary lists its changes. Check the data models with
   `| rest /servicesNS/-/-/data/models splunk_server=local | table title acceleration acceleration.earliest_time`:
   the CIM models show `-7d`.
2. **The input.** `| rest /services/data/inputs/replay_lab` lists one input per dataset, and the
   status log (`index=_internal sourcetype=replay_lab:status`) ticks about every 30 seconds.
3. **The export.** Per-feed counts in the export's `manifest.json` match
   `| tstats count where index=<source_index> earliest=<window_start> latest=<window_end> by sourcetype`.
   For BOTSv3 the total is one lower, because the stray `ess_content_importer` event is left
   out.

### First replayed day

4. **Status.** It shows `playing` with events each tick, a rising position, and no rule errors.
   Outside the workday it shows `idle until next start` with the next start time.
5. **Rules.** Every detection in the pack's `[rules] names` is enabled and scheduled. One reset
   happens a day, at the start.
6. **Lag.** Run
   `index=<live> _indextime>=<restart> | eval lag=_indextime-_time | stats min(lag) max(lag) by sourcetype`.
   Lag should be small and never more than a few seconds negative.
7. **Whole events and no leak.** A `ps` event in the replay_lab app has many lines. In the Search
   app `ps` still has row fields (`| stats count by COMMAND`).
8. **In-text times.** Raw Windows Security, Sysmon, cisco:asa, stream:dns and osquery events show
   the same time as `_time`, in the indexer's zone. For BOTSv3, the saved search "BOTSv3 replay -
   leftover 2018 timestamps" shows only `s3_key` rows (S3 object keys are names, not times).
9. **Detections fire.** Check each of these:
   - `index=_internal sourcetype=scheduler savedsearch_name="ESCU - *" | stats count sum(result_count) by savedsearch_name`
   - `index=risk earliest=-2h | stats count by source`
   - `` `notable` earliest=-2h | stats count by search_name ``
10. **Shape.** `| tstats count where index=<live> by _time span=1h` shows the dataset's hourly
    shape during the workday and nothing outside it.

### Data fixes and lists

11. **Sysmon tags.** `index=<live> source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" | stats count by tag`
    shows process, network, registry and filesystem.
12. **osquery.** `` index=<live> `osquery_process` | stats count `` returns events.
13. **Survey.** `tools/survey.py rules <pack> ...` after a replayed day finds results for every
    listed detection, and none marked NEW.
14. **Risk rule.** While a dataset plays, the risk rule shows the pack's settings, and its search
    ends with the skip marker. Findings arrive during the workday, with no repeats within 20 hours
    and none on `unknown` or `null`.
15. **Asset and identity lists.** `| inputlookup asset_lookup_by_str | search nt_host=<host>`
    returns the host, and `identity_lookup_expanded` has the users.

### Two datasets at once

16. **Shared rules.** Switch on two datasets whose rule lists overlap, then switch one off. The
    shared detections stay on. Switch the other off: they go back to how they were before either
    started, and `replay_lab_rules` is empty.

### Undo

17. **Switch off.** Switch every dataset off and wait a tick. Every rule shows its original
    settings, and the risk rule's search loses the marker.
18. **Undo setup.** `--undo-setup` puts back the macros, roles and accelerations.

## Reference results

From one reference run of BOTSv3 on its daily schedule:

- **Export.** 107 feeds, 1,943,659 events, about 6 minutes.
- **Lists.** 27 assets and 7 identities, merged by ES within about 5 minutes.
- **Detections.** All 53 listed detections had results on every replayed day, from 1 to about
  7,000 each. Two full-day surveys gave identical results.
- **Findings per day.**

  | Risk settings | Findings |
  |---|---|
  | ES's own 24-hour sum and throttle | bursts of over 100 at once, many on `unknown` and `null` |
  | 8-hour sum and 20-hour throttle, ES's own throttle key | about 227 on 76 entities |
  | The pack's settings, plus the two noisy detections made risk-only | about 77, one per entity, from about 75 minutes into the workday |

For DEDALE, a per-day survey of the raw data found:

- 35 detections fire on the weekend days;
- 37 to 43 fire on benign weekdays;
- 51 fire on the main attack day.

Twelve detections fire only on attack days. They include Spoolsv writing a DLL, Rundll32 creating
a remote thread, unsigned DLL side-loading, collection with copy utilities, and taskkill
misuse. No detection fires only on benign days.
