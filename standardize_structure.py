#!/usr/bin/env python3
"""
standardize_structure.py

Standardizes the folder layout of the Netskope Malware IOC repository so that
IOC data can be parsed consistently.

Observed inconsistencies handled:
  1. IOC folder casing/spelling: "IoC" (Doge Ransomware) -> renamed to "IOCs".
  2. Campaign date folders living at the family root (e.g. Emotet/2021-11-18,
     RedLine Stealer/2022-05-12) -> moved under an "IOCs/<date>/" subfolder.
  3. Date folders already nested inside IOCs (XWorm, Python Nodestealer) -> left
     as-is (already conformant).
  4. Families with no IOC data at all (e.g. Dirtyfrag) -> reported, left untouched.

After running, every family that has IOC data will expose it beneath an "IOCs/"
folder, either directly (IOCs/README.md and/or data files) or in dated
subfolders (IOCs/<YYYY-MM-DD>/README.md).

Usage:
    python3 standardize_structure.py            # dry run (default, no changes)
    python3 standardize_structure.py --apply    # actually rename/move
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

# Root of the malware families relative to this script.
MALWARE_ROOT = Path(__file__).resolve().parent / "Malware"

# Canonical name for the IOC folder.
CANONICAL_IOC_DIR = "IOCs"

# Case-insensitive match for any IOC folder variant: IOC, IOCs, IoC, iocs, ...
IOC_DIR_RE = re.compile(r"^ioc[s]?$", re.IGNORECASE)

# Campaign date folder, e.g. 2021-11-18.
DATE_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Auxiliary (non-IOC) sibling folders that should never be treated as IOC data.
AUX_DIRS = {"scripts", "yara", "code"}


class Action:
    """A single planned filesystem change, for dry-run reporting and applying."""

    def __init__(self, kind: str, src: Path, dst: Path):
        self.kind = kind  # "rename" or "move"
        self.src = src
        self.dst = dst

    def describe(self, root: Path) -> str:
        rel_src = self.src.relative_to(root)
        rel_dst = self.dst.relative_to(root)
        return f"[{self.kind}] {rel_src}  ->  {rel_dst}"

    def apply(self) -> None:
        self.dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(self.src), str(self.dst))


def plan_family(family_dir: Path, root: Path) -> tuple[list[Action], list[str]]:
    """Return (actions, notes) for a single malware family folder."""
    actions: list[Action] = []
    notes: list[str] = []

    # Find an existing IOC folder (any casing) if present.
    ioc_dir: Path | None = None
    for child in family_dir.iterdir():
        if child.is_dir() and IOC_DIR_RE.match(child.name):
            ioc_dir = child
            break

    # 1. Normalize IOC folder name to the canonical "IOCs".
    if ioc_dir is not None and ioc_dir.name != CANONICAL_IOC_DIR:
        canonical = family_dir / CANONICAL_IOC_DIR
        if canonical.exists():
            notes.append(
                f"conflict: both '{ioc_dir.name}' and '{CANONICAL_IOC_DIR}' exist; "
                f"skipping rename to avoid clobbering"
            )
        else:
            actions.append(Action("rename", ioc_dir, canonical))
            ioc_dir = canonical  # subsequent moves target the canonical name

    # 2. Move root-level date folders into the IOCs folder.
    date_dirs = [
        c for c in family_dir.iterdir()
        if c.is_dir() and DATE_DIR_RE.match(c.name)
    ]
    if date_dirs:
        target_ioc = ioc_dir if ioc_dir is not None else (family_dir / CANONICAL_IOC_DIR)
        for d in date_dirs:
            dst = target_ioc / d.name
            if dst.exists():
                notes.append(f"conflict: {dst.name} already exists under IOCs; skipping")
                continue
            actions.append(Action("move", d, dst))

    # 3. Report families with no discernible IOC data.
    if ioc_dir is None and not date_dirs:
        has_data_hint = any(
            c.is_dir() and c.name.lower() not in AUX_DIRS
            for c in family_dir.iterdir()
        )
        if not has_data_hint:
            notes.append("no IOC folder and no date folders found (no IOC data)")

    return actions, notes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually perform the renames/moves (default is a dry run).",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=MALWARE_ROOT,
        help="Path to the Malware folder (default: ./Malware).",
    )
    args = parser.parse_args()

    root: Path = args.root.resolve()
    if not root.is_dir():
        print(f"error: malware root not found: {root}", file=sys.stderr)
        return 1

    all_actions: list[Action] = []
    print(f"Scanning: {root}\n")

    for family_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        actions, notes = plan_family(family_dir, root)
        if actions or notes:
            print(f"=== {family_dir.name} ===")
            for a in actions:
                print("  " + a.describe(root))
            for n in notes:
                print(f"  note: {n}")
            print()
        all_actions.extend(actions)

    if not all_actions:
        print("Nothing to change. Structure is already standardized.")
        return 0

    print(f"Planned changes: {len(all_actions)}")
    if not args.apply:
        print("\nDry run only. Re-run with --apply to perform these changes.")
        return 0

    print("\nApplying changes...")
    for a in all_actions:
        a.apply()
        print("  done: " + a.describe(root))
    print("\nStandardization complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
