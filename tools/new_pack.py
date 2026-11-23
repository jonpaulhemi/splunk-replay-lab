#!/usr/bin/env python3
"""Start a new dataset pack from templates/pack.

    python3 tools/new_pack.py <name> [--label "Label"]

Copies templates/pack to datasets/<name>/ and renames "example" (and "EXAMPLE", "Example")
throughout, file names included. Then edit datasets/<name>/pack.conf and run python3 build.py.
"""

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME = re.compile(r"^[a-z][a-z0-9_]*$")


def new_pack(name, label=None, root=ROOT):
    if not NAME.match(name):
        raise ValueError("a pack name is lowercase letters, digits and _ , starting with a letter")
    target = Path(root) / "datasets" / name
    if target.exists():
        raise ValueError(f"{target} already exists")
    template = Path(root) / "templates" / "pack"
    label = label or name.upper()
    for src in sorted(template.rglob("*")):
        if "__pycache__" in src.parts or src.suffix == ".pyc":
            continue
        dest = target / Path(*[p.replace("example", name) for p in src.relative_to(template).parts])
        if src.is_dir():
            dest.mkdir(parents=True, exist_ok=True)
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        text = src.read_text()
        text = text.replace("EXAMPLE", label).replace("Example", label)
        text = re.sub(r"\bexample(?!\.com)", name, text)
        dest.write_text(text)
    return target


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("name")
    parser.add_argument("--label")
    args = parser.parse_args(argv)
    try:
        print(new_pack(args.name, args.label))
    except ValueError as e:
        parser.error(str(e))
    return 0


if __name__ == "__main__":
    sys.exit(main())
