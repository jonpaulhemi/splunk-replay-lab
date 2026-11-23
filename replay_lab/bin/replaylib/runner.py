"""The replay loop behind the modular input: tick, emit what's due, checkpoint, sleep.

State in the checkpoint file: {"anchor": A, "next": w}. Each tick emits events
due in [next, now) and then saves next = now, so a crash between the two repeats
at most one tick, and a restart resumes where the last tick ended. A gap longer
than max_catchup_seconds (Splunk was down, or the replay was switched off) is
skipped rather than flooded, and logged.
"""

import json
import os
import re
import threading
import time
from pathlib import Path
from xml.sax.saxutils import escape

from . import config as config_mod
from . import prepare as prepare_mod
from . import schedule as schedule_mod
from .engine import Engine
from .ledger import LocalLedger
from .store import open_all

SCHEME = "replay_lab"
# Characters XML 1.0 can't carry; splunkd would reject the whole stream.
_NOT_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")


def _xml(text):
    return escape(_NOT_XML.sub("\ufffd", text))


def stanza(dataset):
    return f"{SCHEME}://{dataset}"


def event_xml(event, stanza="replay_lab://botsv3"):
    return (f'<event stanza="{_xml(stanza)}"><time>{event["time"]:.6f}</time>'
            f'<index>{_xml(event["index"])}</index><sourcetype>{_xml(event["sourcetype"])}</sourcetype>'
            f'<source>{_xml(event["source"])}</source><host>{_xml(event["host"])}</host>'
            f'<data>{_xml(event["raw"])}</data></event>\n')


def _short(name):
    return name.strip().lower().split(".")[0]


class Checkpoint:
    def __init__(self, path):
        self.path = Path(path)

    def load(self):
        try:
            return json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}

    def save(self, state):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, sort_keys=True))
        os.replace(tmp, self.path)


class Runner:
    """Plays one dataset. Each dataset has its own input instance, checkpoint and status log."""

    def __init__(self, app_dir, checkpoint_path, out, status=None, now=time.time, sleep=time.sleep,
                 on_wrap=None, data_dir=None, rules=None, server_name=None, dataset=None, ledger=None,
                 prepare=None):
        if not dataset:
            raise ValueError("Runner needs a dataset name")
        self.app_dir = Path(app_dir)
        self.name = dataset
        self.stanza = stanza(dataset)
        self._data_dir_arg = Path(data_dir) if data_dir else None
        self.data_dir = self._data_dir_arg
        self.server_name = server_name
        self.checkpoint = Checkpoint(checkpoint_path)
        self.out = out
        self.status = status or (lambda record: None)
        self.now = now
        self.sleep = sleep
        self.on_wrap = on_wrap or (lambda loop: None)
        self.rules = rules or (lambda cfg: None)  # cfg -> Rules, or None when there's no splunkd
        # () -> the ledger of who holds which rule: KvLedger on splunkd; default, this checkpoint
        self.ledger_factory = ledger
        # (cfg, steps, progress) -> summary: runs Prepare (prepare.run with a splunkd client); None = ignore requests
        self.prepare_factory = prepare
        self._job = None
        self._progress = {}
        self.state = self.checkpoint.load()
        self._dataset = None
        self._opened = False

    def dataset(self, cfg=None):
        if self.data_dir is None:
            cfg = cfg or config_mod.load(self.app_dir, self.name)
        if cfg is not None and self._data_dir_arg is None:
            folder = config_mod.data_dir(cfg.replay)
            if folder != self.data_dir:
                self.data_dir, self._dataset = folder, None
        if self._dataset is None:
            self._dataset = open_all(self.data_dir)
        return self._dataset

    def tick(self):
        """One tick. Returns how many events it emitted."""
        cfg = config_mod.load(self.app_dir, self.name)
        now = int(self.now())
        run_on = cfg.replay.get("run_on", "").strip()
        # splunkd hands the input its host name (sh1.example.com), not always the serverName
        # (sh1): compare the short names.
        if run_on and self.server_name and _short(run_on) != _short(self.server_name):
            # Another member plays the replay; this one stays out of the way (no events, no rules).
            self.status({"state": "standby", "at": now, "run_on": run_on, "server": self.server_name})
            return 0
        if self._prepare(cfg, now):
            return 0
        rules = self.rules(cfg)
        if getattr(cfg, "rules_mode", "escu") == "none":
            # Data only. Rules this app switched on earlier (mode was escu) go back first.
            self._rules_off(rules)
            rules = None
        if not cfg.enabled:
            # Off: forget the position, so switching back on starts from now, not a flood.
            if "next" in self.state:
                self.state.pop("next")
                self.checkpoint.save(self.state)
            self._rules_off(rules)
            self.status({"state": "off", "at": now})
            return 0
        # Everything enable() applies, so a change to any of it re-applies the rule set.
        applied = list(cfg.rules) + ([f"suppress_period={cfg.suppress_period}"] if cfg.suppress_period else [])
        if cfg.skip_risk_objects:
            applied.append("skip_risk_objects=" + ",".join(cfg.skip_risk_objects))
        if cfg.risk_earliest:
            applied.append(f"risk_earliest={cfg.risk_earliest}")
        if cfg.risk_suppress_fields:
            applied.append(f"risk_suppress_fields={cfg.risk_suppress_fields}")
        try:
            data = self.dataset(cfg)
        except (OSError, ValueError) as e:  # no export yet (run Prepare dataset), or a broken one
            self._dataset = None
            self.status({"state": "no_export", "at": now, "export": {"ready": False},
                         "error": f"no usable export in {self.data_dir}: {e.__class__.__name__}"})
            return 0
        anchor = self.state.get("anchor")
        if anchor is None:
            anchor = int(float(cfg.replay["anchor"])) if cfg.replay["anchor"].strip() else now
        try:  # before any rule changes, so a bad setting changes nothing on the box
            schedule = schedule_mod.build(cfg.replay, anchor, data[0].loop_seconds)
        except Exception as e:  # a typo in the schedule settings, or no time zone database
            self.status({"state": "on", "at": now, "config_error": f"[replay] schedule settings: {e}"})
            return 0
        self.state["anchor"] = anchor
        self._rules_on(rules, applied)
        engine = Engine(data, cfg.feeds, cfg.replay["index"], schedule)
        start = int(self.state.get("next", now))
        w0 = start
        catchup = int(cfg.number("max_catchup_seconds"))
        skipped = 0
        if now - w0 > catchup:
            skipped = now - catchup - w0
            w0 = now - catchup
        events = engine.due(w0, now)
        if not self._opened:
            self.out.write("<stream>\n")
            self._opened = True
        for event in events:
            self.out.write(event_xml(event, self.stanza))
        self.out.flush()
        # Starts inside skipped downtime count too, so per-period state still resets; once is enough.
        wrapped = engine.wraps(start, now)
        if wrapped:
            self.on_wrap(wrapped[-1])
            if rules is not None:
                rules.reset(wrapped[-1])
        self.state["next"] = now
        self.checkpoint.save(self.state)
        self.status({"state": "on", "at": now, "index": cfg.replay["index"], "events": len(events), "from": w0, "to": now,
                     **engine.status(now), "skipped_seconds": skipped, "wrapped": wrapped,
                     "export": {"ready": True, "segments": len(data)}})
        return len(events)

    def _prepare(self, cfg, now):
        """Start a new Prepare request, or report one that is running. True while one runs.

        A request is new when it differs from the last one this member handled. It is refused
        while the dataset is on, so a re-export never swaps files under a running replay."""
        if self._job is not None and self._job.is_alive():
            self.status({"state": "preparing", "at": now, "prepare": dict(self._progress)})
            return True
        if self._job is not None:  # just finished
            self._job = None
            self.status({"state": "prepared", "at": now, "prepare": dict(self._progress)})
        request = cfg.replay.get("prepare_request", "").strip()
        if not request or request == self.state.get("prepare_handled") or self.prepare_factory is None:
            return False
        self.state["prepare_handled"] = request
        self.checkpoint.save(self.state)
        parsed = prepare_mod.parse_request(request)
        if parsed is None:
            self.status({"state": "prepare_refused", "at": now, "error": f"malformed prepare_request {request!r}"})
            return False
        if cfg.enabled:
            self.status({"state": "prepare_refused", "at": now,
                         "error": "switch the dataset off before Prepare; a re-export can't swap files under a replay"})
            return False
        _, steps = parsed
        self._progress = {"request": request, "steps": steps, "log": []}
        self._dataset = None  # the export may change under us

        def progress(record):
            log = self._progress["log"]
            log.append(record)
            del log[:-50]  # the latest records are enough for the page

        def job():
            try:
                self._progress["summary"] = self.prepare_factory(cfg, steps, progress)
            except Exception as e:  # never kills the input
                self._progress["summary"] = {"ok": False, "error": str(e)}

        self._job = threading.Thread(target=job, name=f"prepare-{self.name}", daemon=True)
        self._job.start()
        self.status({"state": "preparing", "at": now, "prepare": dict(self._progress)})
        return True

    def _ledger(self):
        if self.ledger_factory is not None:
            return self.ledger_factory()
        return LocalLedger(self.name, self.state, lambda: self.checkpoint.save(self.state))

    def _rules_on(self, rules, names):
        if rules is None or self.state.get("rules_for") == names:
            return
        try:
            ledger = self._ledger()
            if "rules_for" in self.state:  # the settings changed: let go of everything, then apply the new ones
                for _ in rules.put_back(ledger, self.name):
                    pass
                self.state.pop("rules_for")
            self.state["holding"] = True  # on disk before the first change, so a crash still puts back
            self.checkpoint.save(self.state)
            for _ in rules.enable(ledger, self.name):
                pass
            self.state["rules_for"] = names
            self.checkpoint.save(self.state)
        except Exception as e:  # retried next tick
            self.status({"rules_error": str(e)})

    def _rules_off(self, rules):
        if rules is None or not (self.state.get("rules") or "rules_for" in self.state or self.state.get("holding")):
            return
        try:
            for _ in rules.put_back(self._ledger(), self.name):
                pass
            self.state.pop("rules_for", None)
            self.state.pop("holding", None)
            self.checkpoint.save(self.state)
        except Exception as e:
            self.status({"rules_error": str(e)})

    def run(self, ticks=None):
        done = 0
        while ticks is None or done < ticks:
            self.tick()
            done += 1
            cfg = config_mod.load(self.app_dir, self.name)
            self.sleep(cfg.number("tick_seconds"))
