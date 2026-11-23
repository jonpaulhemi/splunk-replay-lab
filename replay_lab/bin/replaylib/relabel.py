"""Format fixes applied during replay.

Relabelling keeps each event a real dataset event: a feed may set its source or
sourcetype, and set fields inside JSON events (`json_set = columns.event_type=exec`).

Translation (one format into another) is opt-in per feed (`translate = <name>`)
and every translated event is marked synthetic, so the evaluation can tell real
and synthetic events apart. No translations ship yet; each one is a deliberate choice.
"""

import json

SYNTHETIC_FIELD = "replay_lab_synthetic"

# name -> function(event dict) -> event dict, or None to drop the event
TRANSLATIONS = {}


def parse_json_set(text):
    pairs = []
    for item in text.replace(",", " ").split():
        path, _, value = item.partition("=")
        if path and _:
            pairs.append((path.split("."), value))
    return pairs


def apply_json_set(raw, pairs):
    """Set each dotted path in a JSON object event, when its parent object exists."""
    if not pairs:
        return raw
    try:
        doc = json.loads(raw)
    except ValueError:
        return raw
    if not isinstance(doc, dict):
        return raw
    changed = False
    for path, value in pairs:
        node = doc
        for key in path[:-1]:
            node = node.get(key) if isinstance(node, dict) else None
        if isinstance(node, dict) and node.get(path[-1]) != value:
            node[path[-1]] = value
            changed = True
    return json.dumps(doc, separators=(",", ":")) if changed else raw


def mark_synthetic(raw):
    try:
        doc = json.loads(raw)
    except ValueError:
        doc = None
    if isinstance(doc, dict):
        doc[SYNTHETIC_FIELD] = 1
        return json.dumps(doc, separators=(",", ":"))
    return raw + f"\n{SYNTHETIC_FIELD}=1"


def translate(name, event):
    if name not in TRANSLATIONS:
        raise KeyError(f"unknown translation {name!r}")
    out = TRANSLATIONS[name](dict(event))
    if out is not None:
        out["raw"] = mark_synthetic(out["raw"])
    return out
