"""A splunkd client for Prepare's steps: REST calls and streamed search exports.

The input passes its session key; the command-line scripts pass a user and password. TLS is
verified unless the caller says otherwise (a local splunkd with its default self-signed cert).
"""

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

APP = "replay_lab"


class Client:
    def __init__(self, base_url, session_key=None, user=None, password=None, ca_file=None, verify=True):
        self.base = base_url.rstrip("/")
        if session_key is not None:
            self.auth = f"Splunk {session_key}"
            self.owner = "nobody"
        else:
            self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
            self.owner = user
        self.context = ssl.create_default_context(cafile=ca_file) if verify else ssl._create_unverified_context()

    def call(self, method, path, query=None, form=None, timeout=120, body=None):
        """(HTTP status, parsed JSON body). form is urlencoded, body is JSON."""
        query = {"output_mode": "json", **(query or {})}
        url = self.base + path + "?" + urllib.parse.urlencode(query, doseq=True)
        headers = {"Authorization": self.auth}
        data = urllib.parse.urlencode(form, doseq=True).encode() if form is not None else None
        if body is not None:
            data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=timeout) as response:
                return response.status, _json(response.read())
        except urllib.error.HTTPError as e:
            return e.code, _json(e.read())

    def export(self, search, earliest="0", latest="+10y"):
        """Yield each result of a search, streamed from the export endpoint.

        It runs in this app's context, so the packs' props (KV_MODE = none for multi-row
        sourcetypes) win over the add-ons'; otherwise splunkd returns one result per table row."""
        form = {"search": search, "output_mode": "json", "earliest_time": earliest, "latest_time": latest}
        path = f"/servicesNS/{urllib.parse.quote(self.owner, safe='')}/{APP}/search/v2/jobs/export"
        request = urllib.request.Request(self.base + path, data=urllib.parse.urlencode(form).encode(),
                                         headers={"Authorization": self.auth}, method="POST")
        with urllib.request.urlopen(request, context=self.context, timeout=3600) as response:
            for line in response:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line.decode("utf-8", "replace"))  # some payloads aren't UTF-8
                if record.get("preview"):
                    continue
                if "result" in record:
                    yield record["result"]


def _json(raw):
    try:
        return json.loads(raw.decode("utf-8", "replace") or "{}")
    except ValueError:
        return {}
