"""The settings API (validation, saving through the conf endpoint, the member list) and status in the KV store."""

import io
import json
import sys
import urllib.parse
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "replay_lab" / "bin"))

import replay_lab_rest  # noqa: E402
from replaylib import settings  # noqa: E402
from replaylib.runner import Runner  # noqa: E402
from replaylib.status import StatusKv  # noqa: E402

MEMBERS = {"entry": [{"name": "1", "content": {"label": "sh2"}}, {"name": "2", "content": {"label": "sh1"}},
                     {"name": "3", "content": {"label": "sh3"}}]}


class FakeSplunkd:
    """The endpoints the settings API calls, as a cluster member or a standalone search head."""

    def __init__(self, cluster=True, capabilities=("admin_all_objects",)):
        self.cluster = cluster
        self.capabilities = list(capabilities)
        self.conf = {"dataset:botsv3": {"enabled": "0", "label": "BOTSv3", "run_on": "", "eai:acl": {}},
                     "dataset:dedale": {"enabled": "1", "label": "DEDALE", "run_on": "sh2"},
                     "feed:botsv3:x": {"search": "x"}}
        self.status = {"botsv3": {"_key": "botsv3", "dataset": "botsv3", "state": "on", "member": "sh1"}}
        self.posts = []

    def call(self, method, path, query=None, form=None, timeout=120, body=None):
        if path == "/services/authentication/current-context":
            return 200, {"entry": [{"content": {"capabilities": self.capabilities}}]}
        if path == "/services/shcluster/member/members":
            return (200, MEMBERS) if self.cluster else (503, {"messages": [{"text": "not a cluster member"}]})
        if path == "/services/server/info":
            return 200, {"entry": [{"content": {"serverName": "standalone-sh"}}]}
        if path == settings.CONF:
            return 200, {"entry": [{"name": k, "content": dict(v)} for k, v in self.conf.items()]}
        if path.startswith(settings.CONF + "/") and method == "POST":
            stanza = urllib.parse.unquote(path.rsplit("/", 1)[1])
            values = {k: v for k, v in form.items() if k != "output_mode"}
            self.posts.append((stanza, values))
            self.conf.setdefault(stanza, {}).update(values)
            return 200, {}
        if path == settings.STATUS and method == "GET":
            return 200, list(self.status.values())
        if path.startswith(settings.STATUS + "/") and method == "POST":
            key = urllib.parse.unquote(path.rsplit("/", 1)[1])
            if key not in self.status:
                return 404, {}
            self.status[key] = dict(body)
            return 200, {}
        if path == settings.STATUS and method == "POST":
            self.status[body["_key"]] = dict(body)
            return 201, {}
        return 404, {}


# --- members ---

def test_on_a_cluster_the_members_are_its_server_names_sorted():
    assert settings.members(FakeSplunkd()) == {"cluster": True, "members": ["sh1", "sh2", "sh3"]}


def test_on_a_standalone_search_head_the_member_is_the_box_itself():
    assert settings.members(FakeSplunkd(cluster=False)) == {"cluster": False, "members": ["standalone-sh"]}


# --- validation ---

def test_good_settings_are_normalised():
    values = settings.validate({"enabled": "true", "run_on": "sh2", "schedule": "Daily", "daily_start": "09:00",
                                "schedule_timezone": "America/New_York", "anchor": "", "tick_seconds": " 30 ",
                                "rules_mode": "NONE", "data_dir": "$SPLUNK_HOME/var/lib/replay_lab/x"},
                               ["sh1", "sh2"])
    assert values == {"enabled": "1", "run_on": "sh2", "schedule": "daily", "daily_start": "09:00",
                      "schedule_timezone": "America/New_York", "anchor": "", "tick_seconds": "30",
                      "rules_mode": "none", "data_dir": "$SPLUNK_HOME/var/lib/replay_lab/x"}


@pytest.mark.parametrize("field,value", [
    ("enabled", "maybe"), ("run_on", "sh9"), ("schedule", "weekly"), ("daily_start", "9am"),
    ("daily_start", "24:00"), ("schedule_timezone", "US/Eastrn"), ("anchor", "soon"), ("tick_seconds", "1"),
    ("max_catchup_seconds", "-5"), ("rules_mode", "falcon"), ("index", "Bad Index"), ("data_dir", "relative/x"),
    ("data_dir", "/opt/../etc"), ("search", "index=*"), ("label", "renamed")])
def test_a_bad_or_unknown_field_is_refused_by_name(field, value):
    with pytest.raises(settings.Invalid) as error:
        settings.validate({field: value}, ["sh1", "sh2"])
    assert list(error.value.errors) == [field]


def test_an_empty_member_means_any_server_the_app_is_on():
    assert settings.validate({"run_on": ""}, ["sh1"]) == {"run_on": ""}


# --- the handler ---

def test_the_list_has_every_dataset_with_its_settings_status_and_the_members():
    status, body = settings.handle(FakeSplunkd(), "GET", "datasets", {})
    assert status == 200
    assert [d["name"] for d in body["datasets"]] == ["botsv3", "dedale"]
    assert body["datasets"][0]["status"]["state"] == "on" and body["datasets"][1]["status"] == {}
    assert "eai:acl" not in body["datasets"][0]["settings"] and body["members"] == ["sh1", "sh2", "sh3"]


def test_a_change_is_saved_through_the_conf_endpoint_on_the_datasets_stanza():
    splunkd = FakeSplunkd()
    status, body = settings.handle(splunkd, "POST", "datasets/botsv3", {"enabled": "1", "run_on": "sh3"})
    assert status == 200 and body["saved"] == {"enabled": "1", "run_on": "sh3"}
    assert splunkd.posts == [("dataset:botsv3", {"enabled": "1", "run_on": "sh3"})]


def test_a_bad_change_saves_nothing_and_names_the_fields():
    splunkd = FakeSplunkd()
    status, body = settings.handle(splunkd, "POST", "datasets/botsv3", {"enabled": "1", "run_on": "elsewhere"})
    assert status == 400 and list(body["fields"]) == ["run_on"] and splunkd.posts == []


def test_an_unknown_dataset_or_endpoint_is_not_found():
    assert settings.handle(FakeSplunkd(), "POST", "datasets/nope", {"enabled": "1"})[0] == 404
    assert settings.handle(FakeSplunkd(), "GET", "secrets", {})[0] == 404


def test_only_admins_may_read_or_change_settings():
    splunkd = FakeSplunkd(capabilities=["search"])
    assert settings.handle(splunkd, "GET", "datasets", {})[0] == 403
    assert settings.handle(splunkd, "POST", "datasets/botsv3", {"enabled": "1"})[0] == 403
    assert splunkd.posts == []


def test_the_persistent_handler_answers_splunkds_request_format(monkeypatch):
    splunkd = FakeSplunkd()
    monkeypatch.setattr(replay_lab_rest, "Rest", lambda uri, token: splunkd)
    request = {"method": "POST", "path_info": "datasets/dedale", "form": [["enabled", "0"]],
               "session": {"authtoken": "t", "user": "admin"}, "server": {"rest_uri": "https://127.0.0.1:8089"}}
    reply = json.loads(replay_lab_rest.Settings().handle(json.dumps(request)))
    assert reply["status"] == 200 and splunkd.conf["dataset:dedale"]["enabled"] == "0"


def test_a_json_payload_works_too(monkeypatch):
    splunkd = FakeSplunkd()
    monkeypatch.setattr(replay_lab_rest, "Rest", lambda uri, token: splunkd)
    request = {"method": "POST", "path_info": "datasets/botsv3", "payload": json.dumps({"rules_mode": "none"}),
               "session": {"authtoken": "t"}, "server": {}}
    assert json.loads(replay_lab_rest.Settings().handle(json.dumps(request)))["status"] == 200
    assert splunkd.conf["dataset:botsv3"]["rules_mode"] == "none"


def test_a_failure_inside_the_handler_is_a_500_with_a_message(monkeypatch):
    def broken(uri, token):
        raise RuntimeError("splunkd unreachable")
    monkeypatch.setattr(replay_lab_rest, "Rest", broken)
    reply = json.loads(replay_lab_rest.Settings().handle(json.dumps({"method": "GET", "path_info": "datasets"})))
    assert reply == {"status": 500, "payload": {"error": "splunkd unreachable"}}


# --- status in the KV store ---

def test_the_playing_member_writes_the_datasets_status_record():
    splunkd = FakeSplunkd()
    kv = StatusKv(splunkd, "dedale", "sh2", now=lambda: 100)
    kv({"state": "on", "at": 99, "events": 5, "position": 30, "wrapped": [], "export": {"ready": True}})
    assert splunkd.status["dedale"] == {"_key": "dedale", "dataset": "dedale", "state": "on", "at": 99, "events": 5,
                                        "position": 30, "export": {"ready": True}, "member": "sh2", "updated": 100}


def test_a_standby_member_never_overwrites_the_playing_members_status():
    splunkd = FakeSplunkd()
    StatusKv(splunkd, "botsv3", "sh2")({"state": "standby", "at": 1, "run_on": "sh1"})
    assert splunkd.status["botsv3"]["member"] == "sh1"


def test_an_error_stays_on_the_record_until_a_tick_runs_clean():
    splunkd = FakeSplunkd()
    kv = StatusKv(splunkd, "botsv3", "sh1", now=lambda: 5)
    kv({"rules_error": "couldn't enable X (HTTP 500)"})
    kv({"state": "on", "at": 1})
    assert splunkd.status["botsv3"]["last_error"] == "couldn't enable X (HTTP 500)"
    kv({"state": "on", "at": 2})
    assert "last_error" not in splunkd.status["botsv3"]


def test_a_kv_store_that_is_down_never_stops_the_replay():
    class Down:
        def call(self, *a, **k):
            raise OSError("connection refused")
    StatusKv(Down(), "botsv3", "sh1")({"state": "on", "at": 1})


def test_a_dataset_with_no_export_yet_says_so_and_touches_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("SPLUNK_HOME", str(tmp_path / "home"))
    (tmp_path / "default").mkdir()
    (tmp_path / "default" / "replay_lab.conf").write_text("[dataset:alpha]\nenabled = 1\n[feed:alpha:f]\nsearch = x\n")
    class Rules:
        calls = []

        def enable(self, ledger, dataset):
            self.calls.append("enable")
            yield from ()

    records = []
    runner = Runner(tmp_path, tmp_path / "c.json", io.StringIO(), status=records.append, now=lambda: 1_800_000_000,
                    sleep=lambda s: None, dataset="alpha", rules=lambda cfg: Rules())
    assert runner.tick() == 0
    assert records[-1]["state"] == "no_export" and records[-1]["export"] == {"ready": False}
    assert Rules.calls == []  # no rule is switched on for a dataset that can't play
