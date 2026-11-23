# splunk-replay-lab

A Splunk app, `replay_lab`, that replays security datasets (BOTSv3, BOTSv2, DEDALE) with current timestamps, so Splunk Enterprise Security detections fire on their normal schedules and a findings queue keeps filling. One app, one folder per dataset, built to take more datasets.

> **Status:** under construction. The design is in [docs/DESIGN.md](docs/DESIGN.md) and the plan is issue #1 and its sub-issues.

## How it works

1. Load a dataset into its own source index (for example `index=botsv3`), once.
2. Install `replay_lab` and run **Prepare dataset** from its settings page: it points ES's data models at the live index, exports the dataset to local disk, and builds asset and identity lists.
3. Switch the dataset on. Every 30 seconds the replay writes the slice that is due into `<dataset>_live`, with timestamps shifted to now and each event's original spacing kept.

Several datasets can play at once, each on its own schedule. On a search head cluster, each dataset plays on the member you pick.

## Layout

| Path | What |
|---|---|
| `datasets/<name>/` | One folder per dataset (a pack): feeds, data fixes, schedule, rules, needed add-ons, loading tools, README |
| `replay_lab/` | The app skeleton and the shared replay engine |
| `tools/` | Tools that don't belong to one dataset |
| `build.py` | Validates the packs and builds `replay_lab-<version>.tgz` |
| `docs/` | Design, install and pack-format docs |
| `tests/` | Offline tests (`python3 -m pytest`) |

## License

Apache 2.0. See [LICENSE](LICENSE). The datasets themselves are not included and keep their own licenses.
