"""Each dataset's latest status in the replay_lab_status KV collection, for the settings page.

The input on the member that plays a dataset writes one record per tick (key: the dataset). A
member on standby doesn't write, so it never hides the playing member's status. The last error
stays on the record until a tick runs without one. Writing is best effort: a KV store that is
busy or down never stops the replay; the status log in _internal still has every tick.
"""

import time
import urllib.parse

PATH = "/servicesNS/nobody/replay_lab/storage/collections/data/replay_lab_status"
FIELDS = ("state", "at", "index", "events", "loop", "segment", "position", "loop_seconds", "playing",
          "next_start", "next_start_text", "mode", "skipped_seconds", "run_on", "export")


class StatusKv:
    def __init__(self, rest, dataset, member, now=time.time):
        self.rest = rest
        self.dataset = dataset
        self.member = member
        self.now = now
        self.record = {"dataset": dataset}
        self._fresh_error = False  # an error came in since the last state record

    def __call__(self, record):
        error = record.get("rules_error") or record.get("config_error") or record.get("error")
        if error:
            self.record.update(last_error=error, last_error_at=self.now())
            self._fresh_error = True
        if "state" not in record:
            return  # an error report during a tick: written with the tick's state record
        if record["state"] == "standby":
            return
        if not self._fresh_error:  # a whole tick without an error clears the last one
            self.record.pop("last_error", None)
            self.record.pop("last_error_at", None)
        self._fresh_error = False
        self.record.update({k: record[k] for k in FIELDS if k in record})
        self.record.update(member=self.member, updated=self.now())
        self.write()

    def write(self):
        key = urllib.parse.quote(self.dataset, safe="")
        try:
            status, _ = self.rest.call("POST", f"{PATH}/{key}", body=self.record)
            if status == 404:
                self.rest.call("POST", PATH, body={**self.record, "_key": self.dataset})
        except Exception:  # best effort, see above
            pass
