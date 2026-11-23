"""The Datasets page in a headless browser, against the real settings handler over a fake splunkd.

Needs Node.js with Playwright and a Chromium for it; skipped where they are missing.
"""

import json
import shutil
import subprocess
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "replay_lab" / "bin"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from replaylib import settings  # noqa: E402
from test_settings_api import FakeSplunkd  # noqa: E402

STATIC = REPO / "replay_lab" / "appserver" / "static"
PAGE = Path(__file__).resolve().parent / "page"


def _has_playwright():
    if not shutil.which("node"):
        return False
    probe = subprocess.run(["node", "-e", "require('playwright')"], capture_output=True, cwd=PAGE)
    return probe.returncode == 0


@pytest.fixture
def server():
    splunkd = FakeSplunkd()
    splunkd.status["botsv3"].update(playing=True, loop=3, position=5400, loop_seconds=23400, events=12,
                                    export={"ready": True, "segments": 1}, updated=4_000_000_000)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, status, body, kind="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _api(self, method):
            url = urllib.parse.urlparse(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            form = dict(urllib.parse.parse_qsl(self.rfile.read(length).decode())) if length else {}
            status, body = settings.handle(splunkd, method, url.path[len("/api/"):], form)
            self._send(status, body)

        def do_GET(self):
            if self.path.startswith("/api/"):
                return self._api("GET")
            name = self.path.lstrip("/").split("?")[0]
            folder = PAGE if name == "harness.html" else STATIC
            kind = {"html": "text/html", "js": "text/javascript", "css": "text/css"}.get(name.rsplit(".", 1)[-1])
            if not kind or not (folder / name).is_file():
                return self._send(404, {})
            self._send(200, (folder / name).read_bytes(), kind)

        def do_POST(self):
            self._api("POST")

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", splunkd
    httpd.shutdown()


@pytest.mark.skipif(not _has_playwright(), reason="needs Node.js with Playwright")
def test_the_page_lists_datasets_refuses_a_bad_value_and_saves_a_good_one(server):
    base, splunkd = server
    run = subprocess.run(["node", str(PAGE / "smoke.mjs"), base], capture_output=True, text=True, timeout=120,
                         cwd=PAGE)
    seen = json.loads(run.stdout.strip().splitlines()[-1]) if run.stdout.strip() else {"error": run.stderr}
    assert "error" not in seen, seen
    rows = {r["name"]: r for r in seen["rows"]}
    assert rows["botsv3"]["state"] == "off" and rows["dedale"]["state"] == "waiting for first tick"
    assert seen["members"] == ["", "sh1", "sh2", "sh3"]
    assert "HH:MM" in seen["fieldError"]
    assert splunkd.conf["dataset:botsv3"]["daily_start"] == "10:30"
    assert splunkd.conf["dataset:botsv3"]["run_on"] == "sh3" and splunkd.conf["dataset:botsv3"]["enabled"] == "1"
