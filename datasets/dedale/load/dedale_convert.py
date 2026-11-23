#!/usr/bin/env python3
"""Turn DEDALE's Elastic JSON host logs back into the formats Splunk's add-ons read.

DEDALE ships Windows logs as Winlogbeat 7.10 JSON (ECS) and Linux audit logs as
Auditbeat 7.3 JSON, exported from Elasticsearch. Splunk_TA_windows,
Splunk_TA_microsoft_sysmon and ESCU expect Windows events as rendered XML
(sourcetype XmlWinEventLog, source XmlWinEventLog:<channel>) and Linux audit as
auditd text (sourcetype auditd). This rebuilds those, one output event per input
event, without inventing any values:

- Windows: <Event><System>...</System><EventData>...</EventData></Event>. Sysmon's
  fields come from the event's rendered message ("Image: C:\\...", one per line),
  because Winlogbeat's sysmon module moves most of event_data into ECS fields.
  Other channels use winlog.event_data as is.
- Auditbeat: a type=SYSCALL line (plus EXECVE and PROCTITLE for executions) in
  auditd's own key=value layout, from auditd.data, process, user and file.
- Syslog: the original line from the message field.

Every output line is JSON {"time", "host", "source", "sourcetype", "raw"} so it can
be sent to HEC or written as files. Labels (DEDALE's malicious event lists) are
matched by (host, @timestamp, record id or sequence) and set "label" to 1 or 2.

usage: dedale_convert.py winlogbeat|auditbeat|syslog <zip> <out_dir> [--from YYYY-MM-DD --to YYYY-MM-DD]
       [--labels system_logs_labels.zip] [--drop-sysmon 7]
"""

import argparse
import bz2
import gzip
import io
import json
import os
import re
import sys
import zipfile
from datetime import datetime, timezone
from xml.sax.saxutils import escape


def quoteattr(v):
    """Single-quoted, as Windows renders event XML; the Sysmon and Windows add-ons' regexes expect it."""
    return "'" + escape(str(v), {"'": "&apos;"}) + "'"

SYSMON = "Microsoft-Windows-Sysmon/Operational"
_FIELD = re.compile(r"^([A-Za-z][A-Za-z0-9]*): ?(.*)$")


def _xml_text(v):
    return escape("" if v is None else str(v))


def sysmon_fields(message):
    """Sysmon's own field list from its rendered message: 'Name: value' per line, first line is the title."""
    fields = []
    for line in (message or "").splitlines()[1:]:
        m = _FIELD.match(line.rstrip("\r"))
        if m:
            fields.append((m.group(1), m.group(2)))
        elif fields:  # a value that runs over several lines (rare: CommandLine with newlines)
            k, v = fields[-1]
            fields[-1] = (k, v + "\n" + line)
    return fields


def _flat(v):
    if isinstance(v, (list, tuple)):
        return " ".join(str(x) for x in v)
    if isinstance(v, dict):
        return json.dumps(v, sort_keys=True)
    return v


def windows_xml(e):
    w = e.get("winlog") or {}
    channel = w.get("channel") or ""
    ts = e.get("@timestamp", "")
    # SystemTime='2025-01-06T10:03:44.5040000Z', the 7-digit form Windows writes
    m = re.match(r"(.*T\d\d:\d\d:\d\d)(?:\.(\d+))?Z$", ts)
    systime = f"{m.group(1)}.{(m.group(2) or '0').ljust(7, '0')[:7]}Z" if m else ts
    if channel == SYSMON:
        data = sysmon_fields(e.get("message"))
    else:
        data = [(k, _flat(v)) for k, v in (w.get("event_data") or {}).items()]
    if not data and str(w.get("event_id")) == "4104":
        # Winlogbeat's powershell module moves 4104's fields into powershell.* and file.*
        ps = e.get("powershell") or {}
        pf = ps.get("file") or {}
        data = [("MessageNumber", ps.get("sequence", 1)), ("MessageTotal", ps.get("total", 1)),
                ("ScriptBlockText", pf.get("script_block_text", "")), ("ScriptBlockId", pf.get("script_block_id", "")),
                ("Path", (e.get("file") or {}).get("path", ""))]
    elif not data and e.get("message"):
        # classic PowerShell (400/600/800) and 4103 render their data as Name=Value lines
        data = [(m.group(1), m.group(2)) for m in re.finditer(r"(?m)^\s*([A-Za-z][A-Za-z ]*?)\s*=\s*(.*)$", e["message"])
                if " " not in m.group(1).strip()]
        if str(w.get("event_id")) in ("400", "403", "600", "800"):
            data = [("Data", e["message"])] + data
    proc = w.get("process") or {}
    user = w.get("user") or {}
    kw = "0x8020000000000000" if (e.get("event") or {}).get("outcome") == "success" and channel == "Security" else "0x8000000000000000"
    system = (
        f"<System><Provider Name={quoteattr(w.get('provider_name') or '')}"
        + (f" Guid={quoteattr(w.get('provider_guid'))}" if w.get("provider_guid") else "")
        + f"/><EventID>{_xml_text(w.get('event_id'))}</EventID>"
        + (f"<Version>{_xml_text(w.get('version'))}</Version>" if w.get("version") is not None else "")
        + f"<Level>{4 if (e.get('log') or {}).get('level') in (None, 'information') else 2}</Level>"
        + f"<Task>0</Task><Opcode>0</Opcode><Keywords>{kw}</Keywords>"
        + f"<TimeCreated SystemTime={quoteattr(systime)}/>"
        + f"<EventRecordID>{_xml_text(w.get('record_id'))}</EventRecordID><Correlation/>"
        + f"<Execution ProcessID={quoteattr(str(proc.get('pid', 0)))} ThreadID={quoteattr(str((proc.get('thread') or {}).get('id', 0)))}/>"
        + f"<Channel>{_xml_text(channel)}</Channel><Computer>{_xml_text(w.get('computer_name'))}</Computer>"
        + (f"<Security UserID={quoteattr(user['identifier'])}/>" if user.get("identifier") else "<Security/>")
        + "</System>"
    )
    body = "".join(f"<Data Name={quoteattr(k)}>{_xml_text(v)}</Data>" for k, v in data)
    raw = f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>{system}<EventData>{body}</EventData></Event>"
    return {"source": f"XmlWinEventLog:{channel}", "sourcetype": "XmlWinEventLog", "raw": raw}


def _epoch(ts):
    return datetime.strptime(ts.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S.%f%z" if "." in ts else "%Y-%m-%dT%H:%M:%S%z").timestamp()


def _kv(pairs):
    out = []
    for k, v in pairs:
        if v is None or v == "":
            continue
        v = str(v)
        out.append(f"{k}={v}" if re.fullmatch(r"[^\s\"']+", v) else f'{k}="{v}"')
    return " ".join(out)


def auditd_lines(e):
    """auditd text for one Auditbeat event: SYSCALL, plus EXECVE/PROCTITLE when a program ran."""
    a = e.get("auditd") or {}
    d = a.get("data") or {}
    p = e.get("process") or {}
    u = e.get("user") or {}
    t = _epoch(e["@timestamp"])
    stamp = f"msg=audit({t:.3f}:{a.get('sequence', 0)}):"
    mtype = (a.get("message_type") or "syscall").upper()
    lines = []
    if mtype == "SYSCALL":
        lines.append(f"type=SYSCALL {stamp} " + _kv([
            ("arch", "c000003e" if d.get("arch") == "x86_64" else d.get("arch")), ("syscall", d.get("syscall")),
            ("success", "yes" if a.get("result") == "success" else "no"), ("exit", d.get("exit")),
            ("a0", d.get("a0")), ("a1", d.get("a1")), ("a2", d.get("a2")), ("a3", d.get("a3")),
            ("ppid", p.get("ppid")), ("pid", p.get("pid")), ("auid", (u.get("audit") or {}).get("id") or "4294967295"),
            ("uid", u.get("id")), ("gid", (u.get("group") or {}).get("id")),
            ("euid", (u.get("effective") or {}).get("id")), ("tty", d.get("tty")),
            ("comm", p.get("name")), ("exe", p.get("executable")), ("key", (a.get("tags") or [None])[0] if a.get("tags") else None),
        ]))
        args = p.get("args") or []
        if d.get("syscall") == "execve" and args:
            lines.append(f"type=EXECVE {stamp} argc={len(args)} " + " ".join(f'a{i}="{x}"' for i, x in enumerate(args)))
            lines.append(f"type=PROCTITLE {stamp} proctitle={' '.join(args).encode().hex().upper()}")
        for i, path in enumerate(a.get("paths") or []):
            lines.append(f"type=PATH {stamp} " + _kv([("item", path.get("item", i)), ("name", path.get("name")),
                                                     ("inode", path.get("inode")), ("dev", path.get("dev")),
                                                     ("mode", path.get("mode")), ("ouid", path.get("ouid")),
                                                     ("ogid", path.get("ogid")), ("nametype", path.get("nametype"))]))
    else:
        # USER_LOGIN, USER_AUTH, CRED_ACQ, ...: auditd's msg='...' form
        summary = a.get("summary") or {}
        inner = _kv([("op", (e.get("event") or {}).get("action")), ("acct", (summary.get("actor") or {}).get("secondary")),
                     ("exe", p.get("executable")), ("hostname", d.get("hostname")), ("addr", d.get("addr") or (e.get("source") or {}).get("ip")),
                     ("terminal", d.get("terminal")), ("res", "success" if a.get("result") == "success" else "failed")])
        lines.append(f"type={mtype} {stamp} " + _kv([("pid", p.get("pid")), ("uid", u.get("id")),
                                                    ("auid", (u.get("audit") or {}).get("id"))]) + f" msg='{inner}'")
    return lines


def _open_member(z, info):
    raw = z.open(info)
    if info.filename.endswith(".bz2"):
        return io.TextIOWrapper(bz2.BZ2File(raw), encoding="utf-8", errors="replace")
    if info.filename.endswith(".gz"):
        return io.TextIOWrapper(gzip.GzipFile(fileobj=raw), encoding="utf-8", errors="replace")
    return io.TextIOWrapper(raw, encoding="utf-8", errors="replace")


def _member_day(name):
    m = re.search(r"(\d{4}-\d{2}-\d{2})T(\d{2})", name)
    return m.group(1) if m else None


def load_labels(path):
    """{(host_lower, @timestamp, record_or_sequence): class} from DEDALE's label zip."""
    out = {}
    if not path:
        return out
    z = zipfile.ZipFile(path)
    for info in z.infolist():
        if not info.filename.endswith(".jsonl"):
            continue
        cls = 1 if info.filename.endswith("class_1.jsonl") else 2
        with z.open(info) as f:
            for line in f:
                e = json.loads(line)
                k = _label_key(e)
                if cls == 1 or k not in out:
                    out[k] = cls if cls == 1 else out.get(k, 2)
    return out


def _label_key(e):
    host = ((e.get("host") or {}).get("name") or (e.get("agent") or {}).get("hostname") or "").lower()
    rid = (e.get("winlog") or {}).get("record_id") or (e.get("auditd") or {}).get("sequence")
    return (host, e.get("@timestamp"), rid)


def convert(kind, path, out_dir, day_from=None, day_to=None, labels=None, drop_sysmon=(), full_hosts=()):
    z = zipfile.ZipFile(path)
    os.makedirs(out_dir, exist_ok=True)
    stats = {}
    for info in sorted(z.infolist(), key=lambda i: i.filename):
        if info.is_dir():
            continue
        day = _member_day(info.filename)
        if day and ((day_from and day < day_from) or (day_to and day > day_to)):
            continue
        outs = {}
        with _open_member(z, info) as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    stats["bad_json"] = stats.get("bad_json", 0) + 1
                    continue
                ts = e.get("@timestamp")
                if not ts:
                    continue
                d = ts[:10]
                if (day_from and d < day_from) or (day_to and d > day_to):
                    continue
                host = ((e.get("agent") or {}).get("hostname") or (e.get("host") or {}).get("hostname")
                        or (e.get("host") or {}).get("name") or "unknown")
                if kind == "winlogbeat":
                    w = e.get("winlog") or {}
                    if (w.get("channel") == SYSMON and str(w.get("event_id")) in drop_sysmon
                            and host.split(".")[0].upper() not in full_hosts):
                        stats["dropped"] = stats.get("dropped", 0) + 1
                        continue
                    rec = windows_xml(e)
                    raws = [rec["raw"]]
                elif kind == "auditbeat":
                    rec = {"source": "/var/log/audit/audit.log", "sourcetype": "auditd"}
                    raws = ["\n".join(auditd_lines(e))]
                else:
                    rec = {"source": "/var/log/syslog", "sourcetype": "syslog"}
                    raws = [e.get("message") or ""]
                label = labels.get(_label_key(e)) if labels else None
                for raw in raws:
                    out = {"time": round(_epoch(ts), 3), "host": host.split(".")[0], "source": rec["source"],
                           "sourcetype": rec["sourcetype"], "raw": raw}
                    if label:
                        out["dedale_label"] = label
                    fh = outs.get(d)
                    if fh is None:
                        fh = outs[d] = gzip.open(os.path.join(out_dir, f"{kind}_{d}.jsonl.gz"), "at")
                    fh.write(json.dumps(out) + "\n")
                    key = (d, rec["source"])
                    stats[key] = stats.get(key, 0) + 1
        for fh in outs.values():
            fh.close()
        print(f"{info.filename} done", file=sys.stderr, flush=True)
    return stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kind", choices=["winlogbeat", "auditbeat", "syslog"])
    ap.add_argument("zip"); ap.add_argument("out_dir")
    ap.add_argument("--from", dest="day_from"); ap.add_argument("--to", dest="day_to")
    ap.add_argument("--labels"); ap.add_argument("--drop-sysmon", default="",
                    help="Sysmon event IDs to drop, except on --full-hosts (image loads, process access, file events are 95%% of the volume)")
    ap.add_argument("--full-hosts", default="", help="hosts that keep every event (the attacked ones)")
    a = ap.parse_args()
    labels = load_labels(a.labels)
    stats = convert(a.kind, a.zip, a.out_dir, a.day_from, a.day_to, labels,
                    tuple(x for x in a.drop_sysmon.replace(",", " ").split() if x),
                    tuple(x.upper() for x in a.full_hosts.replace(",", " ").split() if x))
    json.dump({"|".join(map(str, k)) if isinstance(k, tuple) else k: v for k, v in sorted(stats.items(), key=str)},
              sys.stdout, indent=1)


if __name__ == "__main__":
    main()
