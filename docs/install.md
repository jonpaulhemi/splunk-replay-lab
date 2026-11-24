# Install

One package, `replay_lab-<version>.tgz`, works on a standalone search head and on a search head
cluster. Build it with `python3 build.py`, or take it from a release.

**Requirements:** Splunk Enterprise with Enterprise Security, Splunk_SA_CIM and ESCU
(DA-ESS-ContentUpdate), plus the add-ons each pack lists in `requires`. Prepare dataset warns
about any that are missing. Every script runs on Splunk's bundled Python (`splunk cmd python3`),
standard library only.

## Standalone search head

1. `splunk install app replay_lab-<version>.tgz`, then restart. This creates every pack's live
   index (`<dataset>_live`, 7 days' retention).
2. Load each dataset you want into its source index. See the pack's README.
3. Open **Replay lab > Datasets**. For each dataset, open **Edit**, then **Prepare (all
   steps)**.
4. When Prepare reports **Finished**, tick **On** and **Save**.

## Search head cluster with indexers

Each dataset plays on one member, which you choose. The other members stay on standby, sending no
events and changing no rules. Events reach the indexers through the members' normal forwarding.

1. **Indexers.** Add each live index to the indexers' index app and push the bundle:

   ```
   [botsv3_live]
   homePath   = $SPLUNK_DB/botsv3_live/db
   coldPath   = $SPLUNK_DB/botsv3_live/colddb
   thawedPath = $SPLUNK_DB/botsv3_live/thaweddb
   frozenTimePeriodInSecs = 604800
   ```

   The same stanzas are in the package's `default/indexes.conf`. The source index (`botsv3`,
   `botsv2`, `dedale`) only has to be searchable from the members, for the one-time export.
2. **Deployer.** Put the app in `etc/shcluster/apps/` and run `splunk apply shcluster-bundle`.
   The app ships with every dataset off.
3. **Settings page, on any member.** For each dataset:
   - choose **Plays on** (the drop-down lists the members), and save;
   - run **Prepare (all steps)**.

   The request replicates. The chosen member runs it on its next tick and writes the export to
   its own disk (`$SPLUNK_HOME/var/lib/replay_lab/<dataset>`, outside the app, so a deployer push
   never touches it). Setup and the asset lists go through REST, so they replicate.
4. Tick **On** and save. The status line shows `playing` from the chosen member.

If you move a dataset to another member, run Prepare's **Export only** there.

## Command line

Every Prepare step also runs from a shell on the playing member:

```
export SPLUNK_PASSWORD=...        # never in a file
splunk cmd python3 $SPLUNK_HOME/etc/apps/replay_lab/bin/replay_lab_prepare.py botsv3 https://localhost:8089 \
    --ca-file /path/to/ca.pem                 # or --insecure on a throwaway lab
splunk cmd python3 .../replay_lab_prepare.py botsv3 https://localhost:8089 --steps export
splunk cmd python3 .../replay_lab_prepare.py botsv3 https://localhost:8089 --undo-setup
```

## Running datasets side by side

Datasets play at the same time, each on its own schedule and member. Packs that list the same
detection share it:

- The first to switch it on records its original settings, in the `replay_lab_rules` KV
  collection.
- The last to switch off puts them back.

## Changing the start point

`anchor` is read once. The first tick saves it in the checkpoint
(`$SPLUNK_HOME/var/lib/splunk/modinputs/replay_lab/<dataset>.json`). To move it:

1. Switch the dataset off and wait one tick, so its rules go back.
2. Change `anchor`.
3. Delete the checkpoint.
4. Switch the dataset on.

Never delete a checkpoint while the dataset is on.

## Upgrades

`splunk install app replay_lab-<version>.tgz -update 1` (or a deployer push) keeps the
checkpoints, the exports and the rule records. Replaying continues where it was.

Any change to the risk rule's settings resets ES's throttle, so every entity over the threshold
raises a finding at once. Install an upgrade that changes rule settings only while the risk
rule's window is empty:

- For BOTSv3's daily schedule, that is from at least 8 h 10 min after the workday ends until the
  next `daily_start`.
- Allow for hourly detections that run up to an hour late (ESCU's `allow_skew`). With a 09:00
  start, install between about 01:10 and 08:50.

If a burst happens anyway, switch the dataset off and on before the next workday.

## Moving from the single-dataset apps

`replay_lab_migrate.py` moves a dataset from `botsv3_replay`, `botsv2_replay` or `dedale_replay`.
It carries the checkpoint, the local settings and the saved rule originals, so the replay
continues where the old app stopped. Run it on the member that played the old app, after stopping
that app. On a single box, disable the app. On a search head cluster, where a deployer-pushed app
can't be disabled on one member, set the old app's `[replay] run_on` to a name no member has
(`nobody`); migrate then makes the member it runs on the one that plays. Disabling only the old
input doesn't stop it: splunkd restarts the input instead.

```
splunk cmd python3 $SPLUNK_HOME/etc/apps/replay_lab/bin/replay_lab_migrate.py botsv3_replay https://localhost:8089 \
    --ca-file /path/to/ca.pem --copy-export
```

`--copy-export` copies the old export to replay_lab's data folder. Without it, `data_dir` points
at the old export, and removing the old app would delete it. Then remove the old app.

## Removing it

1. Switch every dataset off and wait one tick, so the rules go back.
2. Run `replay_lab_prepare.py <dataset> ... --undo-setup` for each dataset you prepared.
3. Remove the app and restart.
4. Delete the `*_live` indexes and `$SPLUNK_HOME/var/lib/replay_lab/` if you want the space back.
