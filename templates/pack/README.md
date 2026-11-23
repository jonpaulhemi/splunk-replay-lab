# EXAMPLE pack

Plays EXAMPLE into `index=example_live` with current timestamps.

## The dataset

What it is, who made it, its license and where to get it (with checksums). The dataset itself is
never committed.

## Loading it into Splunk

1. Create the source index `example` on the indexers.
2. Load the dataset into it (see `load/` for any converter or loader).
3. Check the expected count: `| tstats count where index=example by sourcetype`.

## What plays

The window or segments, the schedule, and why. One line per feed group, with any data fix
(json_set, set_source, text_timezone) and the reason for it.

## Detections

What `[rules] names` switches on and why each was chosen; which add-ons they need (the
`requires` list).

## Asset and identity lists

How `hooks/assets.py` derives them, if the pack has lists.
