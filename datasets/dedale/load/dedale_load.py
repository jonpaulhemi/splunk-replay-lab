#!/usr/bin/env python3
"""Send dedale_convert.py output to HEC (index=dedale). DEDALE's labels ride along as the
indexed field dedale_label (1 = malicious action, 2 = its consequence).

usage: HEC_TOKEN=... dedale_load.py converted/winlogbeat_2025-01-06.jsonl.gz [...]

HEC_URL defaults to https://127.0.0.1:8088/services/collector/event. TLS is verified; set HEC_CA
to a CA bundle for a private CA, or HEC_INSECURE=1 to skip the check (a local test box only).
"""
import gzip, json, os, re, ssl, sys, urllib.request

# Auditbeat recorded every file-descriptor syscall on the Linux servers (1.2 GB a day, 80% fcntl,
# close, mmap, mprotect, lseek). No ESCU rule reads those, so they're dropped unless DEDALE
# labels the event malicious. execve, open/openat, connect, socket, setresuid and the
# USER_*/CRED_* records all stay.
NOISY = {"fcntl", "close", "mmap", "mprotect", "lseek", "dup2", "dup", "fstat", "stat", "lstat", "read", "write",
         "munmap", "brk", "access", "getdents", "getdents64", "poll", "select", "futex", "rt_sigaction", "madvise"}
# Samba's smbd switches identity a million times an hour on the file server (setresuid/setresgid);
# those go too. Identity changes by anything else stay.
NOISY_BY_COMM = {("setresuid", "smbd"), ("setresgid", "smbd")}
_SYSCALL = re.compile(r"^type=SYSCALL \S+ arch=\S+ syscall=(\S+)")
_COMM = re.compile(r" comm=(\S+)")

URL = os.environ.get("HEC_URL", "https://127.0.0.1:8088/services/collector/event")


def _context():
    if os.environ.get("HEC_INSECURE", "").strip() == "1":
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=os.environ.get("HEC_CA") or None)


CTX = _context()


def post(batch):
    body = "".join(json.dumps(b) for b in batch).encode()
    req = urllib.request.Request(URL, data=body, headers={"Authorization": f"Splunk {os.environ['HEC_TOKEN']}"})
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, context=CTX, timeout=120) as r:
                r.read()
                return
        except Exception as e:  # HEC busy: retry with backoff
            if attempt == 4:
                raise
            import time
            time.sleep(2 ** attempt)


def main(paths):
    for path in paths:
        n, batch = 0, []
        with gzip.open(path, "rt") as f:
            for line in f:
                e = json.loads(line)
                if e["sourcetype"] == "auditd" and not e.get("dedale_label"):
                    m = _SYSCALL.match(e["raw"])
                    if m and m.group(1) in NOISY:
                        continue
                    if m and (m.group(1), (_COMM.search(e["raw"]) or [None, None])[1]) in NOISY_BY_COMM:
                        continue
                item = {"time": e["time"], "host": e["host"], "source": e["source"], "sourcetype": e["sourcetype"],
                        "index": "dedale", "event": e["raw"]}
                if e.get("dedale_label"):
                    item["fields"] = {"dedale_label": str(e["dedale_label"])}
                batch.append(item)
                if len(batch) >= 2000:
                    post(batch); n += len(batch); batch = []
        if batch:
            post(batch); n += len(batch)
        print(f"{path}: {n} events", flush=True)


if __name__ == "__main__":
    main(sys.argv[1:])
