"""Who holds which detection, and its settings from before anyone changed it.

Datasets that play at the same time can list the same rule (every pack lists ES's risk rule).
The first one to switch a rule on records its original settings; the last one to switch off puts
them back. The record for a rule:

    {"name": <saved search>, "app": <its app>, "original": {<setting>: <value before>},
     "holders": [<dataset>, ...]}

Two ledgers keep it:

- KvLedger: the replay_lab_rules KV store collection, shared by every dataset and every search
  head cluster member, and kept across restarts. Each change to a record is made under a claim
  on its next version, so changes made at the same time from several processes or members
  happen one after another.
- LocalLedger: one dataset's own checkpoint. For a box with no KV store, and for tests.

change(name, step) runs step(record) -> (new record, after) with no one else changing that
record, saves the new record, then calls after() (the changes to splunkd that the saved record
already describes, so a crash between the two loses no original). It returns whether there was
an after().
"""

import hashlib
import json
import time
import urllib.parse

RULES = "replay_lab_rules"
CLAIMS = "replay_lab_claims"
APP = "replay_lab"
CLAIM_SECONDS = 60  # a claim older than this was left by a process that died; it may be taken over
WAIT_SECONDS = 20  # how long to wait for a claim, or for this member's copy to catch up
OLD_CLAIMS = 600  # claims past this are cleaned up


class Busy(RuntimeError):
    """The record stayed claimed by someone else, or this member's KV copy stayed behind."""


def empty(name):
    return {"name": name, "app": "", "original": {}, "holders": []}


class LocalLedger:
    """The rule records of one dataset, in its checkpoint state as {name: {"app", <setting>: <original>}}."""

    def __init__(self, dataset, state, save):
        self.dataset = dataset
        self.saved = state.setdefault("rules", {})
        self.save = save

    def held(self):
        return sorted(self.saved)

    def change(self, name, step):
        record = empty(name)
        if name in self.saved:
            original = dict(self.saved[name])
            record.update(app=original.pop("app"), original=original, holders=[self.dataset])
        new, after = step(record)
        if self.dataset in new["holders"]:
            self.saved[name] = {"app": new["app"], **new["original"]}
        else:
            self.saved.pop(name, None)
        self.save()
        if after:
            after()
        return after is not None


class KvLedger:
    """The rule records in the replay_lab_rules collection."""

    def __init__(self, dataset, rest, now=time.time, sleep=time.sleep):
        self.dataset = dataset
        self.rest = rest
        self.now = now
        self.sleep = sleep

    # -- the KV store --

    @staticmethod
    def _path(collection, key=None):
        base = f"/servicesNS/nobody/{APP}/storage/collections/data/{collection}"
        return base if key is None else f"{base}/{urllib.parse.quote(key, safe='')}"

    def _get(self, collection, key):
        status, body = self.rest.call("GET", self._path(collection, key), query={"output_mode": "json"})
        if status == 404:
            return None
        if status != 200:
            raise Busy(f"KV store read of {collection} failed (HTTP {status})")
        return body

    def _find(self, collection, where=None):
        query = {"output_mode": "json", **({"query": json.dumps(where)} if where else {})}
        status, body = self.rest.call("GET", self._path(collection), query=query)
        if status != 200:
            raise Busy(f"KV store query of {collection} failed (HTTP {status})")
        return body if isinstance(body, list) else []

    def _insert(self, collection, doc):
        status, _ = self.rest.call("POST", self._path(collection), body=doc)
        if status == 409:
            return False
        if status not in (200, 201):
            raise Busy(f"KV store insert into {collection} failed (HTTP {status})")
        return True

    def _save(self, collection, key, doc):
        status, _ = self.rest.call("POST", self._path(collection, key), body=doc)
        if status == 404:  # not there yet: create it
            return self._insert(collection, {**doc, "_key": key})
        if status not in (200, 201):
            raise Busy(f"KV store write to {collection} failed (HTTP {status})")
        return True

    def _delete(self, collection, where):
        status, _ = self.rest.call("DELETE", self._path(collection), query={"query": json.dumps(where)})
        if status not in (200, 204, 404):
            raise Busy(f"KV store delete from {collection} failed (HTTP {status})")

    # -- records --

    @staticmethod
    def key(name):
        return hashlib.sha1(name.encode("utf-8")).hexdigest()

    def held(self):
        return sorted(r["name"] for r in self._find(RULES) if self.dataset in (r.get("holders") or []))

    def records(self):
        return {r["name"]: r for r in self._find(RULES)}

    def _claim(self, key):
        """Read the record and claim its next version. Returns (record or None, version).

        The claim is an insert, which the KV store's leader refuses when that version is already
        claimed. A member whose copy lags the leader can read an old version; its claim on the
        version after it is then refused, and it reads again until its copy catches up."""
        deadline = self.now() + WAIT_SECONDS
        while True:
            record = self._get(RULES, key)
            version = int((record or {}).get("version", 0)) + 1
            claim = {"_key": f"{key}@{version}", "rule": key, "version": version, "at": self.now(),
                     "by": self.dataset}
            if self._insert(CLAIMS, claim):
                return record, version
            # taken: by a live writer (wait), a dead one (take it over), or this read was stale
            self._delete(CLAIMS, {"$and": [{"_key": claim["_key"]}, {"at": {"$lt": self.now() - CLAIM_SECONDS}}]})
            if self.now() >= deadline:
                raise Busy(f"rule record {key} stayed claimed, or this member's KV store copy stayed behind")
            self.sleep(1)

    def change(self, name, step):
        key = self.key(name)
        stored, version = self._claim(key)
        record = empty(name)
        if stored:
            record.update(app=stored.get("app", ""), original=json.loads(stored.get("original") or "{}"),
                          holders=list(stored.get("holders") or []))
        new, after = step(record)
        self._save(RULES, key, {"name": name, "app": new["app"], "original": json.dumps(new["original"],
                                sort_keys=True), "holders": sorted(set(new["holders"])), "version": version})
        self._delete(CLAIMS, {"$and": [{"rule": key}, {"version": {"$lt": version - 1}},
                                       {"at": {"$lt": self.now() - OLD_CLAIMS}}]})
        if after:
            after()
        return after is not None
