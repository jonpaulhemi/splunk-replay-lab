"""REST handler for the settings page (see replaylib/settings.py for the endpoints)."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from replaylib import settings  # noqa: E402
from replaylib.rules import Rest  # noqa: E402

try:
    from splunk.persistconn.application import PersistentServerConnectionApplication
except ImportError:  # outside splunkd (tests)
    PersistentServerConnectionApplication = object


class Settings(PersistentServerConnectionApplication):
    def __init__(self, command_line=None, command_arg=None):
        super().__init__()

    def handle(self, in_string):
        try:
            method, path, form, token, rest_uri = settings.parse_request(in_string)
            status, body = settings.handle(Rest(rest_uri, token), method, path, form)
        except Exception as e:  # never a stack trace to the page
            status, body = 500, {"error": str(e)}
        return json.dumps({"status": status, "payload": body})
