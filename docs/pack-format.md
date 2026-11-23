# Pack format

A dataset is one folder, a **pack**, under `datasets/<name>/`. The build turns every pack into
stanzas, an input and an index in the one `replay_lab` app. Nothing in the engine names a dataset,
so adding a dataset means adding a folder.

Start a new pack from the template:

```
python3 tools/new_pack.py mylab --label "My lab"
python3 build.py
```

The name is lowercase letters, digits and `_`, starting with a letter. It names the input
(`replay_lab://mylab`), the stanzas, and the default indexes (`mylab` to read from, `mylab_live` to
write to).

## What a pack holds

| Path | Packaged as | Required |
|---|---|---|
| `pack.conf` | `[dataset:<name>]`, `[feed:<name>:<feed>]`, `[rules:<name>]` in `default/replay_lab.conf` | yes |
| `props.conf`, `transforms.conf`, `savedsearches.conf`, `inputs.conf`, `indexes.conf` | merged into the app's own files | no |
| `lookups/` | the app's `lookups/` | no |
| `hooks/` | the app's `bin/datasets/<name>/` | no |
| `load/` | not packaged: converters and loaders that fill the source index | no |
| `README.md` | not packaged: what the dataset is and how the pack plays it | yes, by convention |

The build also gives each pack:

- a `[replay_lab://<name>]` input;
- its live index in `indexes.conf`, with 7 days' retention, unless the pack's own `indexes.conf`
  defines that index.

## pack.conf

Three kinds of stanza, written without the pack's name. The build adds the name. Every setting,
with its default, is in [`replay_lab/README/replay_lab.conf.spec`](../replay_lab/README/replay_lab.conf.spec).

### `[dataset]`: how and when it plays

| Setting | What |
|---|---|
| `label` | the name on the settings page |
| `requires` | apps its detections need; Prepare warns about missing ones |
| `index`, `source_index` | write to, read from (default `<name>_live`, `<name>`) |
| `window_start`, `window_end` | the part replayed, in epoch seconds; empty means the whole source index |
| `segments` | several windows of equal length that play in turn, one per period; replaces the window |
| `schedule` | `loop` (back to back from the anchor) or `daily` (once a day from `daily_start` in `schedule_timezone`) |
| `rules_mode` | `escu` or `none`; overrides `[rules] mode` |
| `enabled` | ship `0`; switch on from the settings page |
| `extra_roles` | roles that Prepare lets search the live index |

### `[feed:<feed>]`: one per sourcetype or source

| Setting | What |
|---|---|
| `search` | added to `search index=<source_index>` by the export |
| `set_sourcetype`, `set_source` | written on the replayed events. Use the indexed name, so search-time renames in the add-ons still apply |
| `timestamp_formats` | which in-text time formats are shifted; default: all |
| `text_timezone` | the zone to write zone-less in-text times in (`utc`, `local` or a zone name). Use `local` where Splunk reads `_time` from such text |
| `json_set` | `dotted.path=value` pairs set inside JSON events at replay time |
| `translate` | an opt-in format translation; translated events carry `replay_lab_synthetic=1` |
| `enabled` | `0` leaves the feed out of the export and the replay |

Data fixes (`set_*`, `json_set`, `text_timezone`, `translate`) apply at replay time, so changing
one needs no re-export.

### `[rules]`: the detections it switches on

With `mode = escu`, the saved searches in `names` (one per line, `@risk_rule` for ES's 24-hour
risk rule) are switched on and scheduled while the dataset plays. When it stops, they go back to
exactly how they were. Datasets that list the same rule share it: the first to switch it on records
the original, and the last to stop puts it back. Optional settings (`reset_lookups`,
`reset_searches`, `suppress_period`, `risk_earliest`, `risk_suppress_fields`,
`skip_risk_objects`) are in the spec file.

## Merged .conf files

A pack's `props.conf`, `transforms.conf`, `savedsearches.conf`, `inputs.conf` and `indexes.conf`
are appended to the app's own files.

Two packs may set the same stanza only if they agree on every key they both set. Anything else
stops the build and names both packs.

Name pack-specific stanzas after the pack, for example `[<name>_assets_lookup]` or
`[<Label> replay - ...]`.

## Hooks

`hooks/assets.py` gives the pack ES asset and identity lists. It needs two things:

- `SEARCHES = {"key": "SPL", ...}`. Each search runs against the source index; `{index}` is
  filled in, and no other placeholder is.
- `build(found) -> (asset_rows, identity_rows)`, where `found` holds each key's results. Columns
  left out of a row are written empty.

Prepare writes the rows to `lookups/<name>_assets.csv` and `<name>_identities.csv` and registers
them through splunkd, so a cluster replicates them. The pack's `transforms.conf` and
`identity_manager` inputs hand them to ES. The template has all three pieces.

Hooks use the standard library only, because they run on Splunk's bundled Python (3.9 to 3.13).

## What the build checks

`python3 build.py` loads each pack the way the input will. It stops, naming the pack and the
problem, on any of these:

- a stanza or key given twice;
- an unknown stanza in `pack.conf`;
- a live index that is invalid, equal to the source index, or another pack's;
- a schedule or time zone the replay can't build;
- segments of unequal length;
- a window or segment that ends before it starts;
- no feeds;
- a hook that doesn't import.

## Checklist for a new pack

1. `python3 tools/new_pack.py <name>`, then fill in `pack.conf` and the README.
2. Load the dataset into its source index (`load/` for any tools; never commit the data).
3. Survey it: `python3 tools/survey.py <name> ...` lists the source index's sourcetypes and sources
   next to the pack's feeds, so none is missed or doubled.
4. Set the window or segments, the schedule and the rules. Then `python3 build.py`.
5. Run `python3 -m pytest -q`: `tests/test_packs.py` checks every pack automatically.
6. Install, run Prepare dataset, switch it on, and validate (see [validation.md](validation.md)).
7. Run `python3 tools/scrub_check.py` before pushing.
