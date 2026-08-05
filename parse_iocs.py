#!/usr/bin/env python3
"""
parse_iocs.py

Walks the Netskope Malware IOC repository, finds every folder that holds IOC
data, extracts the indicators, and writes them (with their source file) to a
results file.

Where IOCs live (see standardize_structure.py for the layout):
  * IOC folders named "IOCs" (or the "IoC" variant) under each malware family.
  * Campaign date folders (e.g. 2021-11-18) either at the family root or nested
    inside an IOC folder.
  * README.md files: IOCs are inside fenced ``` code blocks under labeled
    headers. Three header styles are handled:
        * **MD5**            (bullet + bold)
        #### Downloader (md5)  (markdown heading)
        __URLs__:              (bold-underscore + colon)
  * Dedicated data files: .txt (one IOC per line), .csv (header + rows),
    .json (REvil decrypted config).

Each extracted indicator is classified (md5/sha1/sha256/ipv4/domain/url/email/
registry/mutex/other), refanged (hxxp -> http, [.] -> .), and de-duplicated.

Usage:
    python3 parse_iocs.py                 # writes ioc_results.csv + prints summary
    python3 parse_iocs.py -o out.csv
    python3 parse_iocs.py --format txt    # human-readable text report instead
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

MALWARE_ROOT = Path(__file__).resolve().parent / "Malware"

# ---- folder / file matching -------------------------------------------------

IOC_DIR_RE = re.compile(r"^ioc[s]?$", re.IGNORECASE)
DATE_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Data file extensions we know how to parse.
TEXT_EXTS = {".txt"}
CSV_EXTS = {".csv"}
JSON_EXTS = {".json"}

# Source/code file extensions. A folder that directly contains any of these is
# an auxiliary folder (Scripts/Yara/Code), not an IOC folder, regardless of its
# name. This content-based signal is more reliable than matching folder names:
# every auxiliary folder co-resides a script/rule/source file with its README,
# while genuine IOC folders never contain code files.
CODE_EXTS = {".py", ".yar", ".yara", ".cpp", ".c", ".cc", ".cs", ".h", ".hpp",
             ".sh", ".ps1", ".js", ".go", ".rb"}

# Data-extension files that are build metadata, not IOC data.
IGNORE_FILENAMES = {"requirements.txt"}

# Fenced code block: ```lang\n ... \n```  (lang optional).
FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)

# ---- IOC classification regexes ---------------------------------------------

RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_IPV4 = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
)
RE_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
RE_URL = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", re.IGNORECASE)
RE_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)
RE_REGISTRY = re.compile(r"^(HKEY_|HKLM|HKCU|HKCR|HKU|SOFTWARE\\|SYSTEM\\)", re.IGNORECASE)

# Lines to skip entirely (noise inside decrypted-string dumps and README prose).
SKIP_LINE_RE = re.compile(r"^[\s\-=*_#>|]*$")


def refang(value: str) -> str:
    """Convert defanged indicators back to their real form."""
    v = value.strip()
    v = re.sub(r"h[xX]{2}p", "http", v)          # hxxp / hXXp -> http
    v = v.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    v = v.replace("[:]", ":").replace("[://]", "://")
    v = v.replace("[@]", "@").replace("(@)", "@")
    return v


def classify(value: str) -> str:
    """Return the IOC type for a single (already refanged) value."""
    v = value.strip()
    if RE_SHA256.match(v):
        return "sha256"
    if RE_SHA1.match(v):
        return "sha1"
    if RE_MD5.match(v):
        return "md5"
    if RE_URL.match(v):
        return "url"
    if RE_EMAIL.match(v):
        return "email"
    # host:port pattern -> classify the host part.
    host = v.split(":", 1)[0] if ":" in v and not v.startswith("HK") else v
    if RE_IPV4.match(host):
        return "ipv4"
    if RE_REGISTRY.match(v):
        return "registry"
    if RE_DOMAIN.match(host):
        return "domain"
    return "other"


@dataclass(frozen=True)
class IOC:
    value: str
    ioc_type: str
    label: str           # the header/section the IOC was found under
    family: str          # malware family name
    source_file: str     # path relative to Malware root


def normalize_label(raw: str) -> str:
    """Clean a header line into a short label."""
    s = raw.strip()
    s = re.sub(r"^#+\s*", "", s)                 # strip leading markdown #'s
    s = re.sub(r"^[\*\-]\s*", "", s)             # strip leading bullet
    s = s.strip("*_ :")                          # strip bold/underscore/colon
    return s.strip() or "(unlabeled)"


def parse_markdown(text: str) -> list[tuple[str, list[str]]]:
    """
    Return a list of (label, [raw_ioc_lines]) from a README.

    Strategy: walk line by line, remember the most recent header/label line,
    and collect the contents of the fenced code block that follows it.
    """
    results: list[tuple[str, list[str]]] = []
    lines = text.splitlines()
    i = 0
    current_label = "(unlabeled)"

    def is_header(line: str) -> bool:
        s = line.strip()
        if not s:
            return False
        if s.startswith("#"):
            return True
        if s.startswith("*") or s.startswith("-"):
            # bullet with bold label, e.g. "* **MD5**"
            return "**" in s or "__" in s
        if s.startswith("__") and s.endswith(":"):
            return True
        if s.startswith("**") and (s.endswith("**") or s.endswith("**:")):
            return True
        return False

    while i < len(lines):
        line = lines[i]
        if line.strip().startswith("```"):
            # Collect until the closing fence.
            block: list[str] = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                block.append(lines[i])
                i += 1
            i += 1  # skip closing fence
            if block:
                results.append((current_label, block))
            continue
        if is_header(line):
            current_label = normalize_label(line)
        i += 1

    return results


def extract_iocs_from_lines(
    lines: list[str],
    label: str,
    family: str,
    source_file: str,
) -> list[IOC]:
    out: list[IOC] = []
    for raw in lines:
        line = raw.strip()
        if not line or SKIP_LINE_RE.match(line):
            continue
        value = refang(line)
        ioc_type = classify(value)
        out.append(IOC(value, ioc_type, label, family, source_file))
    return out


def parse_readme(path: Path, family: str, root: Path) -> list[IOC]:
    text = path.read_text(encoding="utf-8", errors="replace")
    rel = str(path.relative_to(root))
    iocs: list[IOC] = []
    for label, block in parse_markdown(text):
        iocs.extend(extract_iocs_from_lines(block, label, family, rel))
    return iocs


# Real IOC types (i.e. not the "other" catch-all). Used to decide whether a
# README actually contains indicators, as opposed to prose or example output.
STRONG_IOC_TYPES = {"md5", "sha1", "sha256", "ipv4", "domain", "url", "email"}


def readme_contains_iocs(path: Path, min_iocs: int = 1) -> bool:
    """
    Content-based test: does this README hold genuine IOC data?

    Returns True only if the README's fenced code blocks yield at least
    ``min_iocs`` strongly-typed indicators (hash/ip/domain/url/email). This
    reuses the same markdown + classification logic as the parser, so the
    standardizer and parser agree on what counts as an IOC folder.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    count = 0
    for _label, block in parse_markdown(text):
        for raw in block:
            line = raw.strip()
            if not line or SKIP_LINE_RE.match(line):
                continue
            if classify(refang(line)) in STRONG_IOC_TYPES:
                count += 1
                if count >= min_iocs:
                    return True
    return False


def parse_txt(path: Path, family: str, root: Path) -> list[IOC]:
    text = path.read_text(encoding="utf-8", errors="replace")
    rel = str(path.relative_to(root))
    label = path.stem
    return extract_iocs_from_lines(text.splitlines(), label, family, rel)


def parse_csv(path: Path, family: str, root: Path) -> list[IOC]:
    rel = str(path.relative_to(root))
    out: list[IOC] = []
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh)
        rows = list(reader)
    if not rows:
        return out
    header = [h.strip() for h in rows[0]]
    for row in rows[1:]:
        for col_idx, cell in enumerate(row):
            cell = cell.strip()
            if not cell:
                continue
            # A cell may contain several values (e.g. TroyDen IPs column).
            for token in re.split(r"[;,\s]+", cell):
                token = token.strip()
                if not token:
                    continue
                value = refang(token)
                ioc_type = classify(value)
                if ioc_type == "other":
                    continue  # skip descriptive CSV columns (names, counts)
                label = header[col_idx] if col_idx < len(header) else path.stem
                out.append(IOC(value, ioc_type, label, family, rel))
    return out


def parse_json(path: Path, family: str, root: Path) -> list[IOC]:
    rel = str(path.relative_to(root))
    out: list[IOC] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return out

    def walk(obj, key_path: str) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, f"{key_path}.{k}" if key_path else str(k))
        elif isinstance(obj, list):
            for item in obj:
                walk(item, key_path)
        elif isinstance(obj, str):
            # Values may be ;-delimited (REvil "dmn" field).
            for token in re.split(r"[;,\s]+", obj):
                token = token.strip()
                if not token:
                    continue
                value = refang(token)
                ioc_type = classify(value)
                if ioc_type != "other":
                    out.append(IOC(value, ioc_type, key_path, family, rel))

    walk(data, "")
    return out


def is_auxiliary_dir(directory: Path) -> bool:
    """
    Decide, by content rather than name, whether a directory is an auxiliary
    (Scripts / Yara / Code) folder that should be skipped when collecting IOCs.

    A directory is auxiliary if it directly contains any source/code file. This
    correctly excludes Scripts folders (whose README.md may otherwise embed
    IOC-looking tokens inside shell/bash example blocks) and Yara/Code folders,
    while never excluding real IOC folders, which contain no code files.
    """
    for child in directory.iterdir():
        if child.is_file() and child.suffix.lower() in CODE_EXTS:
            return True
    return False


def _walk_ioc_files(base: Path, family: str, results: list[tuple[Path, str]]) -> None:
    """
    Recurse a candidate folder, collecting parseable IOC files but skipping any
    subtree that is an auxiliary (code-bearing) folder.
    """
    if is_auxiliary_dir(base):
        return
    for child in sorted(base.iterdir()):
        if child.is_dir():
            _walk_ioc_files(child, family, results)
            continue
        if not child.is_file():
            continue
        name = child.name.lower()
        ext = child.suffix.lower()
        if name in IGNORE_FILENAMES:
            continue
        if name == "readme.md" or ext in TEXT_EXTS | CSV_EXTS | JSON_EXTS:
            results.append((child, family))


def find_ioc_files(root: Path) -> list[tuple[Path, str]]:
    """
    Return (file_path, family_name) for every parseable IOC file under any
    IOC folder or date folder in the repository. Auxiliary folders
    (Scripts/Yara/Code) are skipped based on their contents, not their names.
    """
    results: list[tuple[Path, str]] = []
    for family_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        family = family_dir.name
        # Candidate roots that may hold IOC data for this family:
        for child in family_dir.iterdir():
            if not child.is_dir():
                continue
            if IOC_DIR_RE.match(child.name) or DATE_DIR_RE.match(child.name):
                _walk_ioc_files(child, family, results)
    return results


def collect_iocs(root: Path) -> list[IOC]:
    iocs: list[IOC] = []
    for path, family in find_ioc_files(root):
        name = path.name.lower()
        ext = path.suffix.lower()
        if name == "readme.md":
            iocs.extend(parse_readme(path, family, root))
        elif ext in CSV_EXTS:
            iocs.extend(parse_csv(path, family, root))
        elif ext in JSON_EXTS:
            iocs.extend(parse_json(path, family, root))
        elif ext in TEXT_EXTS:
            iocs.extend(parse_txt(path, family, root))
    # De-duplicate on (value, type, family, source_file).
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[IOC] = []
    for ioc in iocs:
        key = (ioc.value, ioc.ioc_type, ioc.family, ioc.source_file)
        if key in seen:
            continue
        seen.add(key)
        unique.append(ioc)
    return unique


def write_csv(iocs: list[IOC], out_path: Path) -> None:
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["family", "ioc_type", "ioc", "label", "source_file"])
        for ioc in iocs:
            writer.writerow(
                [ioc.family, ioc.ioc_type, ioc.value, ioc.label, ioc.source_file]
            )


def write_txt(iocs: list[IOC], out_path: Path) -> None:
    by_family: dict[str, list[IOC]] = {}
    for ioc in iocs:
        by_family.setdefault(ioc.family, []).append(ioc)
    with out_path.open("w", encoding="utf-8") as fh:
        for family in sorted(by_family):
            fh.write(f"# {family}\n")
            for ioc in by_family[family]:
                fh.write(f"  [{ioc.ioc_type}] {ioc.value}  <- {ioc.source_file}\n")
            fh.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-o", "--output", type=Path, default=None,
        help="Output file (default: ioc_results.csv, or ioc_results.txt for --format txt).",
    )
    parser.add_argument(
        "--format", choices=["csv", "txt"], default="csv",
        help="Output format (default: csv).",
    )
    parser.add_argument(
        "--root", type=Path, default=MALWARE_ROOT,
        help="Path to the Malware folder (default: ./Malware).",
    )
    args = parser.parse_args()

    root: Path = args.root.resolve()
    if not root.is_dir():
        print(f"error: malware root not found: {root}", file=sys.stderr)
        return 1

    iocs = collect_iocs(root)

    out_path = args.output or Path(f"ioc_results.{args.format}")
    if args.format == "csv":
        write_csv(iocs, out_path)
    else:
        write_txt(iocs, out_path)

    # Summary to stdout.
    type_counts: dict[str, int] = {}
    family_set: set[str] = set()
    for ioc in iocs:
        type_counts[ioc.ioc_type] = type_counts.get(ioc.ioc_type, 0) + 1
        family_set.add(ioc.family)

    print(f"Parsed {len(iocs)} IOCs from {len(family_set)} malware families.")
    print(f"Results written to: {out_path}")
    print("\nBy type:")
    for t in sorted(type_counts, key=lambda k: -type_counts[k]):
        print(f"  {t:10s} {type_counts[t]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
