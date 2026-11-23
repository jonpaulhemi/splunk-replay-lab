# replay_lab.conf: one set of stanzas per dataset. The build writes them into default/ from each
# pack (datasets/<name>/pack.conf); change them from the settings page or in local/.

[dataset:<name>]
label = <string>
* The dataset's name on the settings page.
enabled = <boolean>
* 1 sends events; 0 pauses. Switching back on starts from now, with no flood.
* Default: 0
index = <string>
* Where replayed events go.
* Default: <name>_live
source_index = <string>
* Where the export reads from.
* Default: <name>
tick_seconds = <number>
* Seconds between ticks.
* Default: 30
max_catchup_seconds = <number>
* After downtime longer than this, skip ahead instead of catching up.
* Default: 3600
anchor = <epoch seconds or empty>
* The time the replay counts from (the first loop, or the first day). Empty: the first tick after
  switching on.
window_start = <epoch seconds or empty>
window_end = <epoch seconds or empty>
* The part of the dataset replayed. Empty: all of it.
segments = <start-end epoch pairs, space or line separated, all one length>
* Windows that play in turn, one per period (segment k mod n). Replaces window_start/end.
schedule = loop | daily
* loop: the window repeats back to back from the anchor. daily: it plays once a day at real
  speed from daily_start, and nothing plays the rest of the day.
* Default: loop
daily_start = <HH:MM>
* Default: 09:00
schedule_timezone = <zone name, or local>
* Default: America/New_York
run_on = <serverName or empty>
* Which server plays this dataset. Empty: any server the app is on (a standalone search head).
  On a search head cluster name one member; the input stays on standby on the others (no events,
  no rule changes).
data_dir = <path or empty>
* Where the export writes and the replay reads. $SPLUNK_HOME is expanded.
* Default: $SPLUNK_HOME/var/lib/replay_lab/<name>
rules_mode = escu | none
* Overrides [rules:<name>] mode when set.

[feed:<name>:<feed>]
search = <SPL filter>
* Added to `search index=<source_index>` by the export.
enabled = <boolean>
set_source = <string>
set_sourcetype = <string>
timestamp_formats = <space separated: iso us clf rfc2822 compact glog syslog ctime epoch>
* Which in-text time formats are shifted. Default: all.
text_timezone = utc | local | <zone name, e.g. America/New_York>
* The zone to write shifted times that carry no zone in. Use local for sourcetypes whose _time
  Splunk extracts from such text, so the indexer reads the right time.
* Default: utc
json_set = <dotted.path=value ...>
* Fields set inside JSON events at replay time.
translate = <translation name>
* Opt-in format translation; every translated event is marked replay_lab_synthetic=1.

[rules:<name>]
mode = escu | none
* escu: while the dataset plays, the listed detections are switched on and scheduled, and put
  back as they were when it's switched off. none: data only; saved searches are never touched.
  Switching from escu to none puts back what escu switched on.
* Default: escu
names = <one saved search name per line; @risk_rule = ES's 24-hour risk rule>
reset_lookups = <lookup names, one per line>
* Cleared when a period starts, so first-seen rules fire again.
reset_searches = <SPL, one per line>
* Run when a period starts.
suppress_period = <seconds or empty>
* While on, a listed rule that throttles for longer is set to this. Switching off puts it back.
risk_earliest = <relative time or empty>
* The risk rule's dispatch.earliest_time while on.
risk_suppress_fields = <comma separated fields or empty>
* The risk rule's throttle fields while on.
skip_risk_objects = <comma separated values or empty>
* Risk objects the risk rule raises no finding on while on (such as unknown, null).
