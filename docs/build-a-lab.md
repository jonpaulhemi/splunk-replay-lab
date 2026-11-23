# Build a lab

A replay lab is one search head with ES, or a search head cluster, that keeps a findings queue
filling from replayed datasets. This page goes from an empty ES box to findings. Each pack's
README has the dataset-specific parts.

## Tested with

| Component | Versions |
|---|---|
| Splunk Enterprise | 10.4.3 and 10.6.1.1 |
| ES | 8.6.1 and 8.8.0 |
| ESCU | 6.10.0 |
| Splunk_SA_CIM | 8.7.0 and 8.8 |
| Splunk_TA_windows | 11.0.2 |
| Splunk_TA_microsoft_sysmon | 5.0.1 |
| Splunk_TA_nix | 10.3.4 |
| Splunk_TA_aws | 8.3.0 |
| Splunk_TA_cisco-asa | 6.1.2 |
| splunk_ta_o365 | 6.1.0 |
| Splunk_TA_microsoft-cloudservices | 6.3.3 |
| TA-OSqueryv1 | 1.0.4 |
| splunk_app_stream | 8.1.6 |
| Splunk_TA_stream_wire_data | 8.1.7 |
| Splunk_TA_symantec-ep | BOTSv2 only |

ESCU upgrades rename and retire detections. Rerun the survey (step 6) after one.

## Capacity

- **License.** Replayed data counts against the license. BOTSv3 is about 1.06 GB a day.
- **Live indexes.** They keep 7 days, so about 7.5 GB for BOTSv3.
- **Exports.** They are gzipped hourly files on the playing member's disk. BOTSv2's seven
  segments take about 360 MB.
- **Export time.** A BOTSv3 export takes about 6 minutes.

## Steps

1. **Install the add-ons** each pack's `requires` lists. Restart.
2. **Load the datasets** into their source indexes, following each pack's README. BOTSv3 and
   BOTSv2 are pre-indexed apps. DEDALE is converted and loaded with the pack's `load/` tools.
3. **Install replay_lab** ([install.md](install.md)).
4. **Prepare each dataset** from the Datasets page. Prepare runs three steps.

   **Setup** points the box at the live index. Each change is recorded first, so
   `--undo-setup` can take it back:
   - CIM index macros (`cim_<Model>_indexes`) that name the source index also name the live
     index.
   - Accelerated CIM data models summarize 7 days (the live index's retention). ES's own models
     are left alone.
   - The admin role searches the live index by default, because most ESCU detections name no
     index.
   - Roles in the dataset's `extra_roles` may search it too.
   - If Falcon Search is installed, its `fs_<source>_index` macros that name specific indexes
     also name the live index. `fs_Risk_index` is never touched.

   It also checks ESCU's `summariesonly_config`, and warns if detections read data model
   summaries only.

   **Export** copies the window or segments from the source index to the playing member's disk.

   **Asset lists** derive ES assets and identities from the dataset, and register them with ES.
   ES merges them within about 5 minutes.
5. **Switch the dataset on.** It plays on its schedule. Its detections are switched on while it
   plays and put back when it stops.
6. **Survey** what fires, after a day of replay:

   ```
   SPLUNK_PASSWORD=... python3 tools/survey.py rules botsv3 https://sh.example.com:8089 --ca-file ca.pem
   ```

   Detections marked NEW have results but aren't in the pack's `[rules] names`.

## Making the queue useful

These are optional, by hand, outside the app.

- **Network data models.** Install Splunk_TA_stream_wire_data, so `stream:dns`, `stream:http`
  and `stream:tcp` get CIM tags. Then rebuild the accelerations; the 7-day window catches up by
  itself.
- **Noisy detections.** Make detections that raise hundreds of findings a day risk-only. For
  example, in BOTSv3, "Suspicious SearchProtocolHost no Command Line Arguments" and "Suspicious
  DLLHost no Command Line Arguments" each raise about 500 a day. Set `action.notable=0` and
  `action.risk=1` on each with a REST POST to
  `/servicesNS/nobody/DA-ESS-ContentUpdate/saved/searches/<url-quoted name>`. Undo with
  `action.notable=1`. The app itself never changes alert actions.

## Adding a dataset

See [pack-format.md](pack-format.md).
