#!/usr/bin/env python3
"""
standardize_structure.py

Standardizes the folder layout of the Netskope Malware IOC repository so that
IOC data can be parsed consistently.

Detection is content-based, not name-based: a README is considered IOC data if
its fenced code blocks contain genuine indicators (hashes / IPs / domains /
URLs / emails). Folder names ("IoC", "IOCs", date folders, etc.) are NOT used
to decide what holds IOCs -- the same detection logic as parse_iocs.py is used.

What it does, per malware family:
  * Finds every README that actually contains IOC data.
  * Ensures each such README lives under the family's "IOCs/" folder:
      - README directly at family root      -> IOCs/README.md
      - README in a campaign subfolder <x>  -> IOCs/<x>/README.md
    (a README already under IOCs/ is left alone).
  * Moves ONLY the IOC README. Everything else (Scripts/, Yara/, Code/, data
    files, non-IOC READMEs) is left untouched where it is.

Auxiliary folders (those containing code files: .py/.yar/.cpp/...) are never
treated as IOC sources, so an example-output block in a Scripts README is not
mistaken for IOC data.

Usage:
    python3 standardize_structure.py            # dry run (default, no changes)
    python3 standardize_structure.py --apply    # actually move READMEs
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

# Reuse the parser's content-based detection so both scripts agree on what an
# IOC README is and which folders are auxiliary.
from parse_iocs import is_auxiliary_dir, readme_contains_iocs

# Root of the malware families relative to this script.
MALWARE_ROOT = Path(__file__).resolve().parent / "Malware"

# Canonical name for the IOC folder.
CANONICAL_IOC_DIR = "IOCs"


class Action:
    """A single planned README move, for dry-run reporting and applying."""

    def __init__(self, src: Path, dst: Path):
        self.src = src
        self.dst = dst

    def describe(self, root: Path) -> str:
        rel_src = self.src.relative_to(root)
        rel_dst = self.dst.relative_to(root)
        return f"[move] {rel_src}  ->  {rel_dst}"

    def apply(self) -> None:
        self.dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(self.src), str(self.dst))


def find_ioc_readmes(family_dir: Path) -> list[Path]:
    """
    Return every README under a family that contains genuine IOC data.

    Auxiliary (code-bearing) folders are skipped entirely, so their example
    output is never mistaken for indicators.
    """
    readmes: list[Path] = []

    def walk(directory: Path) -> None:
        if is_auxiliary_dir(directory):
            return
        for child in sorted(directory.iterdir()):
            if child.is_dir():
                walk(child)
            elif child.is_file() and child.name.lower() == "readme.md":
                if readme_contains_iocs(child):
                    readmes.append(child)

    walk(family_dir)
    return readmes


def ioc_target_for(readme: Path, family_dir: Path) -> Path:
    """
    Compute where an IOC README should live under the family's IOCs/ folder,
    preserving any intermediate campaign subfolder name (e.g. a date).

    Examples (family = Emotet):
      Emotet/README.md                 -> Emotet/IOCs/README.md
      Emotet/2021-11-18/README.md      -> Emotet/IOCs/2021-11-18/README.md
      Emotet/IOCs/2021-11-18/README.md -> unchanged (already under IOCs/)
    """
    ioc_root = family_dir / CANONICAL_IOC_DIR
    rel = readme.relative_to(family_dir)          # e.g. 2021-11-18/README.md
    parts = rel.parts

    # Already under an IOC folder (any casing)? Leave it where it is.
    if parts and parts[0].lower() in {"ioc", "iocs"}:
        return readme

    if len(parts) == 1:
        # README.md directly at family root.
        return ioc_root / "README.md"

    # README.md inside one or more subfolders -> keep the subfolder path.
    return ioc_root / rel


def plan_family(family_dir: Path) -> tuple[list[Action], list[str]]:
    """Return (actions, notes) for a single malware family folder."""
    actions: list[Action] = []
    notes: list[str] = []

    ioc_readmes = find_ioc_readmes(family_dir)

    if not ioc_readmes:
        # Distinguish "truly no IOCs" from "IOCs live in data files, not a
        # README" so the note is not misleading.
        has_data_file = any(
            p.is_file() and p.suffix.lower() in {".txt", ".csv", ".json"}
            and p.name.lower() != "requirements.txt"
            for p in family_dir.rglob("*")
        )
        if has_data_file:
            notes.append(
                "no IOC README to move; IOC data is in data files (left untouched)"
            )
        else:
            notes.append("no README with IOC data found (nothing to standardize)")
        return actions, notes

    for readme in ioc_readmes:
        dst = ioc_target_for(readme, family_dir)
        if dst == readme:
            continue  # already correctly placed under IOCs/
        if dst.exists():
            rel = dst.relative_to(family_dir.parent)
            notes.append(f"conflict: {rel} already exists; skipping")
            continue
        actions.append(Action(readme, dst))

    return actions, notes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually perform the README moves (default is a dry run).",
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
        actions, notes = plan_family(family_dir)
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
