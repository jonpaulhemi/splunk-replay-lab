"""The replay rule set: enable the listed detections on their normal schedules while the
replay is on, put them back as they were when it's switched off, and clear their state when the
loop wraps so first-seen and throttled rules fire on every loop.

Original settings and who holds each rule are kept in a ledger (see ledger.py): the shared
replay_lab_rules KV store collection, so a put-back survives a restart and datasets that share a
rule don't switch it off under each other.
"""

import fnmatch
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

RISK_RULE_PATTERNS = ("*24 hour risk threshold exceeded*", "*risk threshold exceeded for object over 24 hour period*")
RISK_RULE = "@risk_rule"  # in [rules] names: ES's 24-hour risk threshold rule, found by name
SKIP_MARK = "``` replay_lab: skip_risk_objects ```"


def skip_filter(values):
    """SPL appended to the risk rule so it raises no finding on a placeholder entity ("unknown", "null")."""
    quoted = ", ".join('"{}"'.format(v.lower().replace('"', '')) for v in values)
    return (f' | where NOT lower(coalesce(risk_object, normalized_risk_object, "")) IN ({quoted}) {SKIP_MARK}')


def _truthy(value):
    return str(value).strip().lower() in ("1", "true", "t", "yes", "y")


def _path(owner, app, *parts):
    return "/servicesNS/{}/{}/{}".format(owner, app, "/".join(urllib.parse.quote(p, safe="") for p in parts))


class Rest:
    """splunkd REST with the modular input's session key."""

    def __init__(self, base, session_key, verify=False):
        self.base = base.rstrip("/")
        self.auth = f"Splunk {session_key}"
        # splunkd's own cert on localhost is often self-signed; the call never leaves the box.
        self.context = ssl.create_default_context() if verify else ssl._create_unverified_context()

    def call(self, method, path, query=None, form=None, timeout=120, body=None):
        """form: a urlencoded body; body: a JSON one (the KV store's)."""
        url = self.base + path + ("?" + urllib.parse.urlencode(query, doseq=True) if query else "")
        headers = {"Authorization": self.auth}
        data = urllib.parse.urlencode(form, doseq=True).encode() if form is not None else None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=timeout) as response:
                return response.status, _parse(response.read())
        except urllib.error.HTTPError as e:
            return e.code, _parse(e.read())


def _parse(raw):
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return {}


_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _seconds(value):
    """alert.suppress.period ("86400", "86400s", "24h", "1d") in seconds, or None."""
    text = str(value or "").strip().lower()
    if not text:
        return None
    unit = _UNITS.get(text[-1])
    try:
        return int(float(text[:-1] if unit else text) * (unit or 1))
    except ValueError:
        return None


class RuleError(Exception):
    pass


class Rules:
    def __init__(self, rest, names, reset_lookups=(), reset_searches=(), log=lambda record: None,
                 suppress_period=None, skip_risk_objects=(), risk_earliest=None, risk_suppress_fields=None):
        self.rest = rest
        # Settings the risk rule takes while the replay is on, each saved and put back on switch-off.
        # risk_suppress_fields: ES throttles on source_count too, so every new contributing rule re-fires an
        # entity; throttling on the entity alone gives one finding per entity a day.
        # The risk rule's dispatch.earliest_time while the replay is on (ES: -24h). With a daily replay,
        # summing only the workday lets each entity drop below the threshold overnight, so its finding
        # comes when it crosses again during the next workday instead of when the throttle runs out.
        self.risk_earliest = (risk_earliest or "").strip() or None
        self.risk_settings = {key: value for key, value in (
            ("dispatch.earliest_time", self.risk_earliest),
            ("alert.suppress.fields", (risk_suppress_fields or "").strip() or None)) if value}
        # Risk objects the risk rule raises no finding on while the replay is on. BOTSv3, for one, has
        # no user in WinHostMon, osquery and Perfmon events, and no src_ip in many Stream records, so
        # ESCU writes risk on "unknown" and "null". The risk events stay; only the findings are skipped.
        self.skip_risk_objects = [v for v in skip_risk_objects if v]
        # Longest throttle a listed rule may keep while the replay is on, so that the same entities
        # can produce a new finding on the next loop (ES's risk rule throttles for 24 h).
        self.suppress_period = int(suppress_period) if suppress_period else None
        self.names = list(names)
        self.reset_lookups = list(reset_lookups)
        self.reset_searches = list(reset_searches)
        self.log = log

    # -- finding rules --

    def _entry(self, name):
        if name == RISK_RULE:
            query = " OR ".join(f'name="{p}"' for p in RISK_RULE_PATTERNS)
            status, body = self.rest.call("GET", "/servicesNS/-/-/saved/searches",
                                          query={"output_mode": "json", "count": "0", "search": query})
            entries = [e for e in (body.get("entry") or []) if status == 200
                       and any(fnmatch.fnmatchcase(e["name"].lower(), p) for p in RISK_RULE_PATTERNS)]
            entries.sort(key=lambda e: _truthy(e["content"].get("disabled")))
            return entries[0] if entries else None
        status, body = self.rest.call("GET", _path("-", "-", "saved", "searches", name), query={"output_mode": "json"})
        return body["entry"][0] if status == 200 and body.get("entry") else None

    def _set(self, app, name, form):
        form = dict(form)
        disabled = form.pop("disabled", None)
        if form:
            status, _ = self.rest.call("POST", _path("nobody", app, "saved", "searches", name),
                                       form={**form, "output_mode": "json"})
            if status not in (200, 201):
                raise RuleError(f"couldn't change {name} (HTTP {status})")
        if disabled is not None:
            action = "disable" if _truthy(disabled) else "enable"
            status, _ = self.rest.call("POST", _path("nobody", app, "saved", "searches", name, action),
                                       form={"output_mode": "json"})
            if status not in (200, 201):
                raise RuleError(f"couldn't {action} {name} (HTTP {status})")

    # -- on / off --

    def enable(self, ledger, dataset):
        """Enable and schedule every listed rule for `dataset`, recording originals in `ledger` first.

        A rule some other dataset already changed is joined (its original is kept as recorded), so it
        stays on until the last dataset holding it switches off. With different tuning per dataset,
        the latest dataset to switch on sets it."""
        missing = []
        for listed in self.names:
            entry = self._entry(listed)
            if entry is None:
                missing.append(listed)
                continue
            name = entry["name"]
            if ledger.change(name, lambda record, listed=listed: self._take(record, listed, dataset)):
                yield name  # changed on splunkd
        if missing:
            self.log({"rules_missing": missing})

    def _take(self, record, listed, dataset):
        entry = self._entry(listed)  # read again under the ledger's claim: what is on splunkd now
        if entry is None:
            return record, None
        name, app, content = entry["name"], entry["acl"]["app"], entry["content"]
        on = not _truthy(content.get("disabled")) and _truthy(content.get("is_scheduled"))
        period = _seconds(content.get("alert.suppress.period"))
        shorten = (self.suppress_period is not None and _truthy(content.get("alert.suppress"))
                   and period is not None and period > self.suppress_period)
        search = content.get("search") or ""
        skip = listed == RISK_RULE and bool(self.skip_risk_objects) and SKIP_MARK not in search
        window = {key: value for key, value in self.risk_settings.items()
                  if listed == RISK_RULE and content.get(key) != value}
        changed = bool(record["original"])  # some dataset changed it and hasn't put it back
        if (on or changed) and not shorten and not skip and not window:
            if changed and dataset not in record["holders"]:
                record["holders"].append(dataset)  # someone else switched it on: hold it too
            return record, None
        original = record["original"]
        if not changed:
            record["app"] = app
            original.update({"disabled": "1" if _truthy(content.get("disabled")) else "0",
                             "is_scheduled": "1" if _truthy(content.get("is_scheduled")) else "0"})
        if shorten:
            original.setdefault("alert.suppress.period", content.get("alert.suppress.period"))
        if skip:
            original.setdefault("search", search)
        for key in window:
            original.setdefault(key, content.get(key) or "")
        if dataset not in record["holders"]:
            record["holders"].append(dataset)

        def apply():  # after the record is saved
            if window:
                self._set(app, name, window)
            if skip:
                self._set(app, name, {"search": search.rstrip() + skip_filter(self.skip_risk_objects)})
            if shorten:
                self._set(app, name, {"alert.suppress.period": f"{self.suppress_period}s"})
            if not on:
                self._set(app, name, {"is_scheduled": "1"})
                self._set(app, name, {"disabled": "0"})
        return record, apply

    def put_back(self, ledger, dataset):
        """Let go of every rule `dataset` holds; the last holder puts the original back."""
        for name in ledger.held():
            ledger.change(name, lambda record, name=name: self._release(record, name, dataset))
            yield name

    def _release(self, record, name, dataset):
        holders = [h for h in record["holders"] if h != dataset]
        if holders or not record["original"]:
            record["holders"] = holders
            return record, None
        original, app = record["original"], record["app"]
        # Put back before the record is cleared: a crash in between leaves the record, and the next
        # tick puts back again.
        restore = {key: original[key] for key in ("dispatch.earliest_time", "alert.suppress.fields")
                   if key in original}
        if restore:
            self._set(app, name, restore)
        if original.get("search"):
            self._set(app, name, {"search": original["search"]})
        if original.get("alert.suppress.period"):
            self._set(app, name, {"alert.suppress.period": original["alert.suppress.period"]})
        self._set(app, name, {"disabled": original["disabled"]})
        self._set(app, name, {"is_scheduled": original["is_scheduled"]})
        return {"name": name, "app": "", "original": {}, "holders": []}, None

    # -- loop wrap --

    def reset(self, loop):
        searches = [f"| makeresults | where false() | outputlookup {lookup}" for lookup in self.reset_lookups]
        searches += self.reset_searches
        for spl in searches:
            status, _ = self.rest.call("POST", "/services/search/jobs", form={
                "search": spl, "exec_mode": "oneshot", "output_mode": "json"})
            self.log({"reset": spl, "loop": loop, "status": status})
