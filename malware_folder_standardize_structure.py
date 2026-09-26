#!/usr/bin/env python3
"""
standardize_structure.py

Standardizes the folder layout of the Netskope Malware IOC repository so that
IOC data can be parsed consistently.

Detection is content-based, not name-based: a README is considered IOC data if
its plain-text code blocks or Markdown tables contain genuine indicators
(hashes / IPs / domains / URLs / emails). Folder names ("IoC", "IOCs", date
folders, etc.) are NOT used to decide what holds IOCs.

This script is self-contained (standard library only) and has no external
dependencies, so it runs unchanged locally and in GitHub Actions.

What it does, per malware family:
  * Finds every README that actually contains IOC data.
  * Ensures each such README lives under the family's "IOCs/" folder:
      - README directly at family root      -> IOCs/README.md
      - README in a campaign subfolder <x>  -> IOCs/<x>/README.md
    (a README already under IOCs/ is left alone).
    * Moves ONLY the IOC README. Everything else (Scripts/, Yara/, Code/, data
        files, non-IOC READMEs) is left untouched where it is.
    * Normalizes IOC folder variants such as "IoC" to the canonical "IOCs" name.

Usage:
    python3 standardize_structure.py            # dry run (default, no changes)
    python3 standardize_structure.py --apply    # actually move READMEs
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path

# Root of the malware families relative to this script.
MALWARE_ROOT = Path(__file__).resolve().parent / "Malware"

# Canonical name for the IOC folder.
CANONICAL_IOC_DIR = "IOCs"

# ---- content-based IOC detection --------------------------------------------

# Genuine IOC lists in this repository use untagged or plain-text fences.
# Ignoring shell/code fences prevents command examples from becoming IOCs.
IOC_FENCE_LANGUAGES = {"", "text", "txt", "plaintext"}

# Indicator patterns used to decide whether a README truly holds IOCs.
_RE_HASH = re.compile(r"(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", re.IGNORECASE)
_RE_URL = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", re.IGNORECASE)
_RE_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_RE_IPV4 = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
)
_RE_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


def _refang(value: str) -> str:
    """Convert defanged indicators (hxxp, [.]) back to their real form."""
    v = value.strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.IGNORECASE)
    v = v.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    v = v.replace("[:]", ":").replace("[://]", "://")
    v = v.replace("[@]", "@").replace("(@)", "@")
    return v


def _looks_like_ioc(value: str) -> bool:
    """Return True if a single token is a strong indicator (hash/ip/domain/url/email)."""
    v = _refang(value)
    if _RE_HASH.fullmatch(v) or _RE_URL.match(v) or _RE_EMAIL.fullmatch(v):
        return True
    host = v.split(":", 1)[0] if ":" in v else v
    return bool(_RE_IPV4.fullmatch(host) or _RE_DOMAIN.fullmatch(host))


def _iter_ioc_candidates(text: str) -> Iterator[str]:
    """Yield values from IOC-style fences and Markdown table cells."""
    in_fence = False
    fence_language = ""

    for line in text.splitlines():
        stripped = line.strip()

        if stripped.startswith("```"):
            if in_fence:
                in_fence = False
                fence_language = ""
            else:
                in_fence = True
                fence_language = stripped[3:].strip().casefold()
            continue

        if in_fence:
            if fence_language in IOC_FENCE_LANGUAGES and stripped:
                yield stripped
            continue

        if stripped.startswith("|") and stripped.endswith("|"):
            for cell in stripped.strip("|").split("|"):
                value = cell.strip().strip("`*_ ")
                if value:
                    yield value


def readme_contains_iocs(path: Path) -> bool:
    """Return whether a README contains at least one strong IOC."""
    text = path.read_text(encoding="utf-8", errors="replace")
    return any(_looks_like_ioc(value) for value in _iter_ioc_candidates(text))


class Action:
    """A single planned filesystem move, for dry-run reporting and applying."""

    def __init__(self, src: Path, dst: Path, family_dir: Path):
        self.src = src
        self.dst = dst
        self.family_dir = family_dir

    def describe(self, root: Path) -> str:
        rel_src = self.src.relative_to(root)
        rel_dst = self.dst.relative_to(root)
        return f"[move] {rel_src}  ->  {rel_dst}"

    def apply(self) -> None:
        # A case-only directory rename (for example iocs -> IOCs) needs an
        # intermediate name on case-insensitive filesystems such as macOS.
        if self.dst.exists() and _same_file(self.src, self.dst):
            temporary = self.src.with_name(f".{self.src.name}.standardize-tmp")
            if temporary.exists():
                raise FileExistsError(f"temporary path already exists: {temporary}")
            self.src.rename(temporary)
            try:
                temporary.rename(self.dst)
            except OSError:
                temporary.rename(self.src)
                raise
            return

        self.dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(self.src), str(self.dst))

        # Git does not track empty directories. Remove only newly empty source
        # directories; stop immediately when scripts, rules, or other files remain.
        directory = self.src.parent
        while directory != self.family_dir:
            try:
                directory.rmdir()
            except OSError:
                break
            directory = directory.parent


def _same_file(first: Path, second: Path) -> bool:
    """Return whether two existing paths identify the same filesystem object."""
    try:
        return first.samefile(second)
    except OSError:
        return False


def find_ioc_readmes(family_dir: Path) -> list[Path]:
    """Return every README under a family that contains genuine IOC data."""
    return [
        path
        for path in sorted(family_dir.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and path.name.casefold() == "readme.md"
        and readme_contains_iocs(path)
    ]


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

    # Leave only the exact canonical path unchanged. Variants such as IoC/iocs
    # are remapped to IOCs while preserving any nested campaign path.
    if parts[0] == CANONICAL_IOC_DIR:
        return readme

    if parts[0].casefold() in {"ioc", "iocs"}:
        return ioc_root.joinpath(*parts[1:])

    if len(parts) == 1:
        # README.md directly at family root.
        return ioc_root / "README.md"

    # README.md inside one or more subfolders -> keep the subfolder path.
    return ioc_root / rel


def plan_family(family_dir: Path) -> tuple[list[Action], list[str]]:
    """Return (actions, conflicts) for a single malware family folder."""
    actions: list[Action] = []
    conflicts: list[str] = []
    planned_case_renames: set[tuple[Path, Path]] = set()

    for readme in find_ioc_readmes(family_dir):
        dst = ioc_target_for(readme, family_dir)
        if dst == readme:
            continue  # already correctly placed under IOCs/
        if dst.exists():
            if _same_file(readme, dst):
                source_root = family_dir / readme.relative_to(family_dir).parts[0]
                canonical_root = family_dir / CANONICAL_IOC_DIR
                rename = (source_root, canonical_root)
                if rename not in planned_case_renames:
                    actions.append(Action(source_root, canonical_root, family_dir))
                    planned_case_renames.add(rename)
                continue
            conflicts.append(f"{dst.relative_to(family_dir.parent)} already exists")
            continue
        actions.append(Action(readme, dst, family_dir))

    return actions, conflicts


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
    all_conflicts: list[str] = []
    print(f"Scanning: {root}\n")

    for family_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        actions, conflicts = plan_family(family_dir)
        if actions or conflicts:
            print(f"=== {family_dir.name} ===")
            for a in actions:
                print("  " + a.describe(root))
            for conflict in conflicts:
                print(f"  conflict: {conflict}")
            print()
        all_actions.extend(actions)
        all_conflicts.extend(conflicts)

    if all_conflicts:
        print(
            f"error: {len(all_conflicts)} destination conflict(s); no changes applied.",
            file=sys.stderr,
        )
        return 1

    if not all_actions:
        print("Nothing to change. Structure is already standardized.")
        return 0

    print(f"Planned changes: {len(all_actions)}")
    if not args.apply:
        print("\nDry run only. Re-run with --apply to perform these changes.")
        return 0

    print("\nApplying changes...")
    for a in all_actions:
        try:
            a.apply()
        except OSError as exc:
            print(f"error applying {a.describe(root)}: {exc}", file=sys.stderr)
            return 1
        print("  done: " + a.describe(root))
    print("\nStandardization complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
