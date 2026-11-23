"""datasets/dedale/load: Winlogbeat/Auditbeat JSON rebuilt as the formats Splunk's add-ons read."""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "datasets" / "dedale" / "load"))

import dedale_convert as c  # noqa: E402

SYSMON_1 = {
    "@timestamp": "2025-01-06T10:03:44.504Z",
    "agent": {"hostname": "CLIENT2", "type": "winlogbeat"},
    "message": "Process Create:\nRuleName: -\nUtcTime: 2025-01-06 10:03:44.504\nImage: C:\\Users\\client2\\scvhost.exe\n"
               "CommandLine: \"C:\\Users\\client2\\scvhost.exe\" --commands-page index.php\nUser: BREACH\\client2\n"
               "ParentImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "computer_name": "CLIENT2.breach.local",
               "event_id": 1, "provider_name": "Microsoft-Windows-Sysmon",
               "provider_guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "record_id": 3298994, "version": 5,
               "process": {"pid": 2876, "thread": {"id": 3588}}, "user": {"identifier": "S-1-5-18"},
               "event_data": {"Company": "-"}},
}


def test_sysmon_is_rebuilt_from_its_message_with_single_quoted_names():
    out = c.windows_xml(SYSMON_1)
    raw = out["raw"]

    assert (out["source"], out["sourcetype"]) == ("XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", "XmlWinEventLog")
    # the Sysmon add-on's regex is <Data Name='(.*?)'>(.*?)</Data>: single quotes only
    fields = dict(re.findall(r"<Data Name='(.*?)'>(.*?)</Data>", raw))
    assert fields["Image"] == "C:\\Users\\client2\\scvhost.exe"
    assert fields["ParentImage"].endswith("powershell.exe") and fields["User"] == "BREACH\\client2"
    assert fields["CommandLine"] == "&quot;C:\\Users\\client2\\scvhost.exe&quot; --commands-page index.php" or \
        fields["CommandLine"] == "\"C:\\Users\\client2\\scvhost.exe\" --commands-page index.php"
    assert "<EventID>1</EventID>" in raw and "<Computer>CLIENT2.breach.local</Computer>" in raw
    assert "SystemTime='2025-01-06T10:03:44.5040000Z'" in raw and '"' not in raw.split("<EventData>")[0]


def test_powershell_4104_gets_its_script_block_back():
    e = {"@timestamp": "2025-01-06T10:02:30.192Z",
         "powershell": {"file": {"script_block_text": "IEX (New-Object Net.WebClient)", "script_block_id": "abc"},
                        "sequence": 1, "total": 1},
         "winlog": {"channel": "Microsoft-Windows-PowerShell/Operational", "event_id": 4104,
                    "provider_name": "Microsoft-Windows-PowerShell", "computer_name": "CLIENT2.breach.local"}}

    assert "<Data Name='ScriptBlockText'>IEX (New-Object Net.WebClient)</Data>" in c.windows_xml(e)["raw"]


def test_an_auditbeat_execve_becomes_syscall_execve_and_proctitle_lines():
    e = {"@timestamp": "2025-01-10T11:34:09.060Z",
         "auditd": {"data": {"arch": "x86_64", "syscall": "execve", "exit": "0", "tty": "(none)"},
                    "message_type": "syscall", "result": "success", "sequence": 42},
         "process": {"args": ["/bin/sh", "-c", "id"], "executable": "/bin/dash", "name": "sh", "pid": 7, "ppid": 1},
         "user": {"id": "33", "group": {"id": "33"}, "effective": {"id": "33"}}}

    lines = c.auditd_lines(e)

    assert lines[0].startswith("type=SYSCALL msg=audit(1736508849.060:42): arch=c000003e syscall=execve success=yes")
    assert "comm=sh exe=/bin/dash" in lines[0]
    assert lines[1] == 'type=EXECVE msg=audit(1736508849.060:42): argc=3 a0="/bin/sh" a1="-c" a2="id"'
    assert lines[2] == "type=PROCTITLE msg=audit(1736508849.060:42): proctitle=" + "/bin/sh -c id".encode().hex().upper()


def test_labels_match_by_host_time_and_record():
    key = c._label_key({**SYSMON_1, "host": {"name": "CLIENT2.breach.local"}})
    assert key == ("client2.breach.local", "2025-01-06T10:03:44.504Z", 3298994)
