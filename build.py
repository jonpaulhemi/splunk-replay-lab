#!/usr/bin/env python3
"""Build dist/replay_lab-<version>.tgz from the app skeleton and the dataset packs.

    python3 build.py                 # dist/replay_lab-<VERSION>.tgz
    python3 build.py --out DIR       # somewhere else
    python3 build.py --stage DIR     # also leave the unpacked app in DIR (for a look, or tests)

The app skeleton is replay_lab/. Each folder datasets/<name>/ with a pack.conf is a pack:
  pack.conf          [dataset], [feed:<feed>] and [rules] stanzas; written into
                     default/replay_lab.conf as [dataset:<name>], [feed:<name>:<feed>], [rules:<name>]
  props.conf, transforms.conf, savedsearches.conf, inputs.conf, indexes.conf
                     appended to the app's own; the same stanza and key set two ways is an error
  lookups/           copied into the app's lookups/
  hooks/             copied into the app's bin/datasets/<name>/
Every pack also gets a replay_lab://<name> input, and its live index in indexes.conf unless the
pack defines that index itself.

Two builds of one commit are byte-identical: entries are sorted, owners and times are fixed
(SOURCE_DATE_EPOCH, else the last commit's time), and gzip writes no name or time.
"""

import argparse
import configparser
import gzip
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
APP = "replay_lab"
MERGED = ("props.conf", "transforms.conf", "savedsearches.conf", "inputs.conf", "indexes.conf")
# Never packaged: a box's own settings and export (top level), caches, and hidden files.
SKIP = re.compile(r"^(local|data)(/|$)|(^|/)__pycache__(/|$)|\.pyc$|(^|/)\.")
HEADER = re.compile(r"^\[(.*)\]\s*$")
NAME = re.compile(r"^[a-z][a-z0-9_]*$")


class BuildError(Exception):
    pass


def packs(root=ROOT):
    """[(name, folder)] for every datasets/<name>/ with a pack.conf, sorted by name."""
    found = []
    for folder in sorted((Path(root) / "datasets").iterdir()):
        if (folder / "pack.conf").is_file():
            if not NAME.match(folder.name):
                raise BuildError(f"pack folder {folder.name!r}: use lower case letters, digits and _")
            found.append((folder.name, folder))
    return found


def pack_stanzas(name, text):
    """pack.conf text with its stanza headers renamed for dataset `name`; comments and values kept."""
    out = []
    for number, line in enumerate(text.splitlines(), 1):
        match = HEADER.match(line)
        if match:
            section = match.group(1).strip()
            if section == "dataset":
                line = f"[dataset:{name}]"
            elif section == "rules":
                line = f"[rules:{name}]"
            elif section.startswith("feed:") and section[5:].strip():
                line = f"[feed:{name}:{section[5:].strip()}]"
            else:
                raise BuildError(f"datasets/{name}/pack.conf:{number}: unknown stanza [{section}] "
                                 "(use [dataset], [feed:<name>] or [rules])")
        out.append(line)
    return "\n".join(out).rstrip("\n") + "\n"


def parse(text, source):
    parser = configparser.RawConfigParser(strict=False, interpolation=None, delimiters=("=",),
                                          comment_prefixes=("#",), empty_lines_in_values=False)
    parser.optionxform = str
    try:
        parser.read_string("[__top__]\n" + text.replace("\\\n", "\n    "), source=source)
    except configparser.Error as e:
        raise BuildError(f"{source}: {e}") from None
    return parser


def check_merge(seen, text, source):
    """Refuse a stanza key that an earlier file set to something else. `seen` collects them."""
    parser = parse(text, source)
    for section in parser.sections():
        for key, value in parser.items(section):
            where = (section, key)
            if where in seen and seen[where][0] != value:
                raise BuildError(f"{source}: [{section}] {key} is also set, differently, in {seen[where][1]}")
            seen.setdefault(where, (value, source))
    return parser


def input_stanza(name):
    return (f"[replay_lab://{name}]\n"
            "disabled = 0\n"
            "python.version = python3\n"
            "python.required = 3.9, 3.13\n")


def index_stanza(index):
    return (f"# Replayed events. Seven days, then frozen (deleted). The source index is never written to.\n"
            f"[{index}]\n"
            f"homePath = $SPLUNK_DB/{index}/db\n"
            f"coldPath = $SPLUNK_DB/{index}/colddb\n"
            f"thawedPath = $SPLUNK_DB/{index}/thaweddb\n"
            "frozenTimePeriodInSecs = 604800\n")


def _copy_tree(src, dst):
    for path in sorted(Path(src).rglob("*")):
        rel = path.relative_to(src).as_posix()
        if SKIP.search(rel) or not path.is_file():
            continue
        target = Path(dst) / rel
        if target.exists():
            raise BuildError(f"{path}: {target} already exists in the app")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)


def stage(out_dir, root=ROOT):
    """Write the unpacked app into out_dir/replay_lab and return that path."""
    root = Path(root)
    version = (root / "VERSION").read_text().strip()
    app = Path(out_dir) / APP
    if app.exists():
        shutil.rmtree(app)
    _copy_tree(root / APP, app)
    default = app / "default"
    conf = default / "app.conf"
    conf.write_text(conf.read_text().replace("@VERSION@", version))

    texts = {name: (default / name).read_text() if (default / name).exists() else "" for name in MERGED}
    seen = {name: {} for name in MERGED}
    for name, text in texts.items():
        if text:
            check_merge(seen[name], text, f"{APP}/default/{name}")
    replay_conf = ["# Written by build.py from datasets/<name>/pack.conf. Change settings in local/, or\n"
                   "# from the settings page; never here.\n"]
    for name, folder in packs(root):
        stanzas = pack_stanzas(name, (folder / "pack.conf").read_text())
        parsed = parse(stanzas, f"datasets/{name}/pack.conf")
        index = (parsed.get(f"dataset:{name}", "index", fallback="") or f"{name}_live").strip()
        replay_conf.append(f"\n# ---- {name} (from datasets/{name}/pack.conf) ----\n" + stanzas)
        for conf_name in MERGED:
            source = folder / conf_name
            text = source.read_text() if source.exists() else ""
            if conf_name == "inputs.conf":
                text = input_stanza(name) + ("\n" + text if text else "")
            if conf_name == "indexes.conf" and not parse(text, str(source)).has_section(index):
                text = index_stanza(index) + ("\n" + text if text else "")
            if not text:
                continue
            check_merge(seen[conf_name], text, f"datasets/{name}/{conf_name}")
            texts[conf_name] += f"\n# ---- {name} (from datasets/{name}) ----\n" + text.rstrip("\n") + "\n"
        if (folder / "lookups").is_dir():
            _copy_tree(folder / "lookups", app / "lookups")
        if (folder / "hooks").is_dir():
            _copy_tree(folder / "hooks", app / "bin" / "datasets" / name)
    (default / "replay_lab.conf").write_text("".join(replay_conf))
    for name, text in texts.items():
        if text:
            (default / name).write_text(text.lstrip("\n"))
    return app


def source_date_epoch(root=ROOT):
    if os.environ.get("SOURCE_DATE_EPOCH", "").strip():
        return int(os.environ["SOURCE_DATE_EPOCH"])
    try:
        out = subprocess.run(["git", "log", "-1", "--format=%ct"], cwd=root, capture_output=True, text=True)
        return int(out.stdout.strip())
    except (OSError, ValueError):
        return 0


def package(app, out_file, mtime):
    """A reproducible .tgz of the staged app folder."""
    app = Path(app)
    paths = [app] + sorted(app.rglob("*"), key=lambda p: p.relative_to(app).as_posix())
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in paths:
            arcname = (Path(APP) / path.relative_to(app)).as_posix()
            info = tar.gettarinfo(str(path), arcname)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = mtime
            executable = path.is_dir() or (path.suffix == ".py" and path.parent.name == "bin")
            info.mode = 0o755 if executable else 0o644
            info.pax_headers = {}
            if path.is_file():
                with open(path, "rb") as f:
                    tar.addfile(info, f)
            else:
                tar.addfile(info)
    Path(out_file).parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "wb") as f:
        with gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=0) as gz:
            gz.write(raw.getvalue())
    return Path(out_file)


def build(out_dir, root=ROOT, stage_dir=None):
    root = Path(root)
    version = (root / "VERSION").read_text().strip()
    with tempfile.TemporaryDirectory() as tmp:
        app = stage(stage_dir or tmp, root)
        return package(app, Path(out_dir) / f"{APP}-{version}.tgz", source_date_epoch(root))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=str(ROOT / "dist"))
    parser.add_argument("--stage", help="also leave the unpacked app in this folder")
    args = parser.parse_args(argv)
    try:
        out = build(args.out, stage_dir=args.stage)
    except BuildError as e:
        print(f"build.py: {e}", file=sys.stderr)
        return 1
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
