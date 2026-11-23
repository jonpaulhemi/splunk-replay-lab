"""The settings API behind the settings page: list datasets, validate and save their settings,
list the members that can play one.

Settings are saved through splunkd's conf endpoint, so on a search head cluster they replicate to
every member; conf edited by hand in local/ still works. Only admins may read or change them.

    GET  /services/replay_lab/datasets            every dataset: settings, status, members
    GET  /services/replay_lab/datasets/<name>     one dataset
    POST /services/replay_lab/datasets/<name>     change settings (form fields, see EDITABLE)
    GET  /services/replay_lab/members             the members a dataset can play on
"""

import json
import re
import urllib.parse

APP = "replay_lab"
CONF = f"/servicesNS/nobody/{APP}/configs/conf-replay_lab"
STATUS = f"/servicesNS/nobody/{APP}/storage/collections/data/replay_lab_status"
CAPABILITY = "admin_all_objects"
CLOCK = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
INDEX = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
TRUE = {"1", "true", "yes", "t", "y", "on"}
FALSE = {"0", "false", "no", "f", "n", "off"}


class Invalid(ValueError):
    def __init__(self, errors):
        super().__init__("; ".join(f"{k}: {v}" for k, v in errors.items()))
        self.errors = errors


# -- validation: each takes the submitted text and returns the value to save, or raises ValueError --

def _boolean(text):
    value = text.strip().lower()
    if value in TRUE:
        return "1"
    if value in FALSE:
        return "0"
    raise ValueError("use 1 or 0")


def _integer(low, high):
    def check(text):
        try:
            value = int(text.strip())
        except ValueError:
            raise ValueError("a whole number") from None
        if not low <= value <= high:
            raise ValueError(f"between {low} and {high}")
        return str(value)
    return check


def _optional_epoch(text):
    return "" if not text.strip() else _integer(0, 4_102_444_800)(text)


def _choice(*options):
    def check(text):
        value = text.strip().lower()
        if value not in options:
            raise ValueError("one of " + ", ".join(options))
        return value
    return check


def _clock(text):
    if not CLOCK.match(text.strip()):
        raise ValueError("HH:MM, 24-hour")
    return text.strip()


def _timezone(text):
    value = text.strip()
    if value == "local":
        return value
    try:
        from zoneinfo import ZoneInfo
        ZoneInfo(value)
    except Exception:
        raise ValueError("a time zone name such as America/New_York, or local") from None
    return value


def _index(text):
    value = text.strip()
    if not INDEX.match(value):
        raise ValueError("an index name: lower case letters, digits, _ and -")
    return value


def _data_dir(text):
    value = text.strip()
    if value and not (value.startswith("/") or value.startswith("$SPLUNK_HOME") or re.match(r"^[A-Za-z]:\\", value)):
        raise ValueError("an absolute path, or one starting with $SPLUNK_HOME")
    if ".." in value.replace("\\", "/").split("/"):
        raise ValueError("no .. in the path")
    return value


EDITABLE = {
    "enabled": _boolean,
    "run_on": None,  # checked against the member list
    "schedule": _choice("loop", "daily"),
    "daily_start": _clock,
    "schedule_timezone": _timezone,
    "anchor": _optional_epoch,
    "tick_seconds": _integer(5, 300),
    "max_catchup_seconds": _integer(60, 7 * 86400),
    "rules_mode": _choice("escu", "none"),
    "index": _index,
    "data_dir": _data_dir,
}


def validate(form, members):
    """The settings to save from a submitted form, or Invalid naming each bad field.

    Unknown fields are refused, so a typo never saves silently. run_on must be one of `members`
    (or empty: any server the app is on)."""
    out, errors = {}, {}
    for key, raw in form.items():
        text = raw if isinstance(raw, str) else str(raw)
        if key not in EDITABLE:
            errors[key] = "not a setting the page can change"
            continue
        if key == "run_on":
            value = text.strip()
            if value and value not in members:
                errors[key] = "not a member of this cluster"
            else:
                out[key] = value
            continue
        try:
            out[key] = EDITABLE[key](text)
        except ValueError as e:
            errors[key] = str(e)
    if errors:
        raise Invalid(errors)
    return out


# -- splunkd --

def _ok(status):
    return 200 <= status < 300


def members(rest):
    """The serverNames a dataset can play on: the cluster's members, or this box's own name."""
    status, body = rest.call("GET", "/services/shcluster/member/members",
                             query={"output_mode": "json", "count": "0"})
    if _ok(status) and body.get("entry"):
        names = sorted({(e.get("content") or {}).get("label") or e.get("name") for e in body["entry"]} - {None, ""})
        if names:
            return {"cluster": True, "members": names}
    status, body = rest.call("GET", "/services/server/info", query={"output_mode": "json"})
    name = ((body.get("entry") or [{}])[0].get("content") or {}).get("serverName", "") if _ok(status) else ""
    return {"cluster": False, "members": [name] if name else []}


def can_admin(rest):
    status, body = rest.call("GET", "/services/authentication/current-context", query={"output_mode": "json"})
    content = ((body.get("entry") or [{}])[0].get("content") or {}) if _ok(status) else {}
    return CAPABILITY in (content.get("capabilities") or [])


def datasets(rest):
    """{name: settings} from the merged conf (default/ and local/), via the conf endpoint."""
    status, body = rest.call("GET", CONF, query={"output_mode": "json", "count": "0"})
    if not _ok(status):
        raise RuntimeError(f"couldn't read replay_lab.conf (HTTP {status})")
    out = {}
    for entry in body.get("entry") or []:
        if entry["name"].startswith("dataset:"):
            content = {k: v for k, v in (entry.get("content") or {}).items()
                       if not k.startswith("eai:") and k != "disabled"}
            out[entry["name"].split(":", 1)[1]] = content
    return out


def statuses(rest):
    status, body = rest.call("GET", STATUS, query={"output_mode": "json"})
    if not _ok(status) or not isinstance(body, list):
        return {}
    return {r.get("dataset") or r.get("_key"): r for r in body}


def save(rest, name, values):
    status, _ = rest.call("POST", f"{CONF}/{urllib.parse.quote('dataset:' + name, safe='')}",
                          form={**values, "output_mode": "json"})
    if not _ok(status):
        raise RuntimeError(f"couldn't save [dataset:{name}] (HTTP {status})")


# -- the handler's logic, free of splunkd's request format --

def handle(rest, method, path, form):
    """(HTTP status, JSON-able body) for one request. path is what follows /replay_lab/."""
    if not can_admin(rest):
        return 403, {"error": f"the {CAPABILITY} capability is needed"}
    parts = [p for p in path.strip("/").split("/") if p]
    if parts == ["members"] and method == "GET":
        return 200, members(rest)
    if not parts or parts[0] != "datasets" or len(parts) > 2:
        return 404, {"error": "unknown endpoint"}
    known = datasets(rest)
    if len(parts) == 1:
        if method != "GET":
            return 405, {"error": "GET only"}
        state = statuses(rest)
        return 200, {"datasets": [{"name": n, "settings": s, "status": state.get(n, {})} for n, s in known.items()],
                     **members(rest)}
    name = parts[1]
    if name not in known:
        return 404, {"error": f"no dataset {name!r}"}
    if method == "GET":
        return 200, {"name": name, "settings": known[name], "status": statuses(rest).get(name, {})}
    if method != "POST":
        return 405, {"error": "GET or POST"}
    try:
        values = validate({k: v for k, v in form.items() if k != "output_mode"}, members(rest)["members"])
    except Invalid as e:
        return 400, {"error": "invalid settings", "fields": e.errors}
    if values:
        save(rest, name, values)
    return 200, {"name": name, "saved": values, "settings": datasets(rest).get(name, {})}


def parse_request(in_string):
    """splunkd's persistent-handler request: (method, path after /replay_lab/, form, token, rest_uri)."""
    request = json.loads(in_string)
    path = request.get("path_info") or ""
    rest_path = request.get("rest_path") or ""
    if not path and "/replay_lab/" in rest_path:
        path = rest_path.split("/replay_lab/", 1)[1]
    form = dict(request.get("form") or [])
    payload = request.get("payload")
    if payload and not form:
        try:
            form = json.loads(payload) if payload.strip().startswith("{") else dict(urllib.parse.parse_qsl(payload))
        except ValueError:
            form = {}
    session = request.get("session") or {}
    return (request.get("method") or "GET").upper(), path, form, session.get("authtoken", ""), \
        (request.get("server") or {}).get("rest_uri", "https://127.0.0.1:8089")
