# DEDALE pack

Plays DEDALE's Windows and Linux host logs into `index=dedale_live` with current timestamps,
sixteen days in turn (one per 24 hours): seven benign days first, then the attack.

## The dataset

DEDALE (Dataset for Evaluating Detection of APT among Logs and Events, Inria/DGA,
doi:10.57745/Y5JLDG, v2.0) is four weeks of a simulated company (30 Windows 10 clients in the
BREACH domain, Linux DMZ/web/VPN servers and a Samba AD internal server), 2024-12-22 to
2025-01-19 UTC. The first two weeks are benign; a stealthy APT runs 2025-01-06 to 01-13.
Benign activity comes from the Aura user simulator. DEDALE labels the attack's host events
(`system_logs_labels.zip`): class 1 is a malicious action, class 2 its consequence.

Host files used (network captures are not): `system_logs_winlogbeat.zip` (27 GB),
`system_logs_auditbeat.zip` (11 GB), `system_logs_labels.zip`. MD5s are in the dataset's metadata.

## Loading it into Splunk (load/)

DEDALE's logs are Elastic JSON (Winlogbeat 7.10 ECS, Auditbeat 7.3). ESCU and the add-ons read
Windows events as rendered XML and Linux audit as auditd text, so `dedale_convert.py` rebuilds
those, one output event per input event, inventing no values:

- Windows -> `sourcetype=XmlWinEventLog`, `source=XmlWinEventLog:<channel>`. Sysmon fields come from
  the rendered message (Winlogbeat's sysmon module moves most of event_data into ECS), PowerShell
  4104 from `powershell.file.*`, everything else from `winlog.event_data`. Attributes are
  single-quoted, as Windows writes them: the add-ons' regexes don't match double quotes.
- Auditbeat -> `sourcetype=auditd`: type=SYSCALL (plus EXECVE and PROCTITLE for executions, PATH
  records) and USER_*/CRED_* records in auditd's key=value layout.
- Labels ride along as the indexed field `dedale_label` (1 or 2), so `index=dedale` is the ground truth.

Volume filters, applied before indexing (labeled events always kept):
- Sysmon 7, 10, 11 and 26 (image load, process access, file create/delete) are 95% of the Windows
  volume. They're kept on the two attacked clients (CLIENT1, CLIENT2) and dropped on the other 28.
- Auditd file-descriptor syscalls (fcntl, close, mmap, mprotect, madvise, lseek, ...) and Samba's
  own setresuid/setresgid churn (2.5M an hour on the file server) are dropped.

Result: 2024-12-30 to 2025-01-14 in `index=dedale`, about 1.1M Windows and 3M Linux events
per weekday.

    python3 load/dedale_convert.py winlogbeat system_logs_winlogbeat.zip converted --from 2025-01-06 --to 2025-01-06 \
        --labels system_logs_labels.zip --drop-sysmon 7,10,11,26 --full-hosts CLIENT1,CLIENT2
    python3 load/dedale_convert.py auditbeat system_logs_auditbeat.zip converted --from 2025-01-06 --to 2025-01-06 \
        --labels system_logs_labels.zip
    HEC_TOKEN=... python3 load/dedale_load.py converted/*_2025-01-06.jsonl.gz     # to index=dedale over HEC


The loading tools run outside Splunk and are not part of the app package. `dedale_load.py`
verifies TLS: set `HEC_CA` for a private CA, or `HEC_INSECURE=1` on a local test box only.
After loading, run **Prepare dataset** for DEDALE from the app's settings page.
