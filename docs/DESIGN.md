# Design decisions

Why `replay_lab` is built the way it is. The full spec is issue #1; its tickets are the sub-issues of #1. Each decision below was made in the design review before any code was written, with the reason it won.

## What it is

| Decision | Choice | Why |
|---|---|---|
| Scope | One app replays every dataset, starting with BOTSv3, BOTSv2 and DEDALE. | The three earlier apps carried forked copies of the same engine, so every fix was made three times. |
| App ID | `replay_lab` | Neutral across datasets. A new ID also let the earlier apps keep running until each dataset was moved over. |
| Repo | Public, Apache 2.0, started from one clean commit. | The replay is useful to others. The earlier history named private lab hosts, so it wasn't carried over. |

## How datasets plug in

| Decision | Choice | Why |
|---|---|---|
| Unit of a dataset | A **pack**: a folder `datasets/<name>/` with its feeds and data fixes, schedule, rule list, live index, needed add-ons, asset and identity hooks, any loading tools, and a README. One shared engine plays every pack. | Adding a dataset is a copy-and-edit of one folder, and the engine never changes for it. One package still installs everything. |
| Splunk-facing files | The build turns each pack into the app's `default/` files (`replay_lab.conf` stanzas, `inputs.conf`, `indexes.conf`, `props.conf`, `savedsearches.conf`) and its hooks into `bin/datasets/`. | Splunk only reads conf from `default/` and `local/`. The pack folder stays the single source. |
| Pre-load tools | Conversion and loading scripts (DEDALE's) live in the pack, outside the Splunk package. | They run before Splunk sees the data, and keeping them in the pack keeps everything about a dataset in one place. |
| Data fixes | Relabelling, JSON field patches, in-text timestamp rewriting and opt-in translations are per-feed pack settings applied at replay time. | The export stores events as they are, so a changed fix needs no re-export. |
| Add-ons | Each pack lists the add-ons it needs; Prepare warns about missing ones and still runs. | A missing add-on silently costs detections. A warning catches that without blocking a data-only run. Installing apps is left to the admin. |

## How it runs

| Decision | Choice | Why |
|---|---|---|
| Concurrency | Datasets replay independently and at the same time: each has its own on/off, schedule, live index, progress and rules mode. One modular input instance per dataset. | A lab can mix datasets in one findings queue, and one stuck dataset can't stall the others. |
| Data source per tick | Export each dataset once from its source index to local disk; the replay reads those files. | Lighter on the indexers than a search every 30 seconds per dataset, and an export is estimated at a few hundred MB per dataset. |
| Which member plays (cluster) | A named member per dataset. If it is down, that dataset pauses and resumes when it returns. | Simplest and predictable. Following the captain would need the export on every member, state in the KV store, and handovers that risk gaps or duplicates, and the captain is already the busiest member. |
| Timestamps | Each event keeps its original spacing, shifted by one whole-second offset per period; times inside the event text get the same offset. | Detections see realistic timing, and `_time` agrees with the raw text. |
| Rules | Per dataset: `escu` turns the pack's detection list on while it plays and puts it back after; `none` sends data only (for Falcon Search or hand-managed rules). | ESCU users get findings out of the box; others keep full control of their rules. |
| Shared rules | Rule ownership and original settings live in a KV store collection. The first dataset to use a rule turns it on; the last to stop puts it back. | Datasets that share a rule mustn't switch it off under each other, and the record must survive restarts and be readable from any member. |
| Falcon Search | Setup only adds the live index to Falcon Search's `fs_<source>_index` macros. Fixes to Falcon Search's own searches are out of scope. | Falcon Search rules can see replayed data, while patches to a third-party app stay out of this repo. |

## How it's managed

| Decision | Choice | Why |
|---|---|---|
| Settings | A settings page in Splunk Web that saves through splunkd's REST config endpoints. Hand-edited conf still works. | On a search head cluster, editing one member's `local/` doesn't replicate; REST does. |
| Member picker | A drop-down of the cluster's members; on a standalone search head, just that server. | No mistyped server names. |
| Prepare dataset | One action runs setup, export and assets. The page saves a request; the input on the dataset's named member picks it up on its next tick and runs it in the background, with progress shown on the page. It refuses while the dataset plays and asks before replacing an export. Each step is also a command-line script. | No shell needed on the playing member, and the export always lands on the disk that plays it, whichever member served the page. |
| Loading the source index | Stays a documented command-line step (untar a pre-indexed dataset app, or run a pack's loading tools). | It is a one-time job, partly outside Splunk, and large (DEDALE's raw files are tens of GB). |

## Moving an existing lab over

| Decision | Choice | Why |
|---|---|---|
| Live indexes | Unchanged: `botsv3_live`, `botsv2_live`, `dedale_live`. | Searches, ES settings and ground-truth checks that name them keep working. |
| Cutover | One dataset at a time, in the lab's maintenance window, carrying over each earlier app's progress and export with a `migrate` command; the earlier app is removed after one clean pass. | A daily replay is never interrupted, and nothing is replayed twice or re-exported. |
