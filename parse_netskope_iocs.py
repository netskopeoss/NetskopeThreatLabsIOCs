#!/usr/bin/env python3
"""Extract Netskope Threat Labs IOC READMEs into a normalized CSV file.

Only README.md files below canonical ``IOCs/`` directories in ``Malware/`` and
``Phishing/`` are parsed. Published values are preserved as written, including
defanging; normalization is used only for type detection and deduplication.

Usage:
    python3 parse_netskope_iocs.py
    python3 parse_netskope_iocs.py --output /path/to/netskope_iocs.csv
    python3 parse_netskope_iocs.py --root /path/to/NetskopeThreatLabsIOCs
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

SOURCE_FEED = "Netskope Threat Labs"
CATEGORIES = ("Malware", "Phishing")
CANONICAL_IOC_DIR = "IOCs"
DEFAULT_OUTPUT = "netskope_iocs.csv"
CSV_FIELDS = (
    "IOC_type",
    "Value",
    "Source_feed",
    "Confidence_Additional_info",
    "Last_modified_date",
)
IOC_FENCE_LANGUAGES = {"", "text", "txt", "plaintext"}

_HASH_TYPES_BY_LENGTH = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
_HEX_RE = re.compile(r"[a-f0-9]+", re.IGNORECASE)
_TLSH_RE = re.compile(r"T[0-9A-F]{69,71}", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")
_DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"[a-z][a-z0-9+.-]*://\S+", re.IGNORECASE)
_REGISTRY_RE = re.compile(
    r"(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)|"
    r"HKLM|HKCU|HKCR|HKU)\\",
    re.IGNORECASE,
)
_INLINE_CODE_RE = re.compile(r"`([^`]+)`")
_BOLD_LABEL_RE = re.compile(r"(?:\*\*|__)(.+?)(?:\*\*|__)")
_TABLE_SEPARATOR_RE = re.compile(r":?-{3,}:?")
_GITHUB_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")

# These suffixes are common file extensions in this repository. Excluding them
# avoids treating values such as payload.exe and config.txt as domains.
_FILE_SUFFIXES = {
    "7z",
    "bat",
    "bin",
    "cab",
    "cmd",
    "cpp",
    "csv",
    "dat",
    "dll",
    "doc",
    "docm",
    "docx",
    "exe",
    "gif",
    "hta",
    "htm",
    "html",
    "jar",
    "js",
    "json",
    "lnk",
    "msi",
    "pdf",
    "png",
    "ps1",
    "py",
    "rar",
    "rtf",
    "sh",
    "svg",
    "txt",
    "vbs",
    "xls",
    "xlsm",
    "xlsx",
    "xml",
    "yar",
    "yara",
    "zip",
}

_LABEL_TYPE_RULES = (
    (re.compile(r"\bsha[ -]?512\b", re.IGNORECASE), "sha512"),
    (re.compile(r"\bsha[ -]?256\b", re.IGNORECASE), "sha256"),
    (re.compile(r"\bsha[ -]?1\b", re.IGNORECASE), "sha1"),
    (re.compile(r"\bmd5\b", re.IGNORECASE), "md5"),
    (re.compile(r"\btlsh\b", re.IGNORECASE), "tlsh"),
    (re.compile(r"\bvhash\b", re.IGNORECASE), "vhash"),
    (re.compile(r"\burls?\b", re.IGNORECASE), "url"),
    (re.compile(r"\bemails?\b", re.IGNORECASE), "email"),
    (re.compile(r"\bdomains?\b", re.IGNORECASE), "domain"),
    (re.compile(r"\b(?:ipv4|ip addresses?|ips)\b", re.IGNORECASE), "ipv4"),
    (re.compile(r"\bregistry(?: keys?)?\b", re.IGNORECASE), "registry_key"),
    (re.compile(r"\bmutex(?:es)?\b", re.IGNORECASE), "mutex"),
    (re.compile(r"\bgithub repositories\b", re.IGNORECASE), "github_repository"),
    (re.compile(r"\bpremium-sms\b", re.IGNORECASE), "uri"),
)

_WALLET_LABELS = {
    "btc": "btc_address",
    "bitcoin": "btc_address",
    "eth": "eth_address",
    "ethereum": "eth_address",
    "xmr": "xmr_address",
    "monero": "xmr_address",
    "xlm": "xlm_address",
    "stellar": "xlm_address",
    "xrp": "xrp_address",
    "ripple": "xrp_address",
    "ltc": "ltc_address",
    "litecoin": "ltc_address",
    "doge": "doge_address",
    "dogecoin": "doge_address",
}


@dataclass(frozen=True)
class Candidate:
    value: str
    context: str = ""
    explicit_type: str = ""


@dataclass(frozen=True)
class IOC:
    ioc_type: str
    value: str
    normalized_value: str


def normalize_for_detection(value: str) -> str:
    """Normalize defanging without changing the value written to the CSV."""
    normalized = value.strip()
    normalized = re.sub(r"^hxxp", "http", normalized, flags=re.IGNORECASE)
    normalized = normalized.replace("[.]", ".").replace("(.)", ".")
    normalized = normalized.replace("{.}", ".").replace("[:]", ":")
    normalized = normalized.replace("[://]", "://")
    normalized = normalized.replace("[@]", "@").replace("(@)", "@")
    return normalized


def clean_value(value: str) -> str:
    """Remove Markdown wrappers while preserving the published IOC value."""
    cleaned = value.strip().strip("`*_ ")
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in {'"', "'"}:
        cleaned = cleaned[1:-1].strip()
    return cleaned


def type_from_label(label: str) -> str:
    """Map an explicit section/table label to an IOC type when possible."""
    normalized = re.sub(r"[^a-z0-9]+", " ", label.casefold()).strip()
    if normalized in _WALLET_LABELS:
        return _WALLET_LABELS[normalized]
    if "bitcoin address" in normalized:
        return "btc_address"
    for pattern, ioc_type in _LABEL_TYPE_RULES:
        if pattern.search(label):
            return ioc_type
    return ""


def host_from_host_port(value: str) -> str | None:
    """Return the host from a non-URL value with a valid port."""
    if value.startswith("[") and "]:" in value:
        host, port_text = value[1:].split("]:", 1)
    elif value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
    else:
        return None
    if not port_text.isdigit():
        return None
    port = int(port_text)
    if not 1 <= port <= 65535:
        return None
    return host


def classify_candidate(candidate: Candidate) -> IOC | None:
    """Classify a candidate conservatively, returning None for ambiguous data."""
    value = clean_value(candidate.value)
    if not value or any(character in value for character in ("\n", "\r", "\t")):
        return None

    normalized = normalize_for_detection(value)
    label_type = type_from_label(candidate.explicit_type or candidate.context)

    if label_type == "vhash" and re.fullmatch(
        r"[a-f0-9]{16,128}", normalized, re.IGNORECASE
    ):
        return IOC("vhash", value, normalized.casefold())

    if _HEX_RE.fullmatch(normalized):
        hash_type = _HASH_TYPES_BY_LENGTH.get(len(normalized))
        if hash_type:
            return IOC(hash_type, value, normalized.casefold())

    if _TLSH_RE.fullmatch(normalized):
        return IOC("tlsh", value, normalized.casefold())
    if _URL_RE.fullmatch(normalized):
        return IOC("url", value, normalized)
    if normalized.casefold().startswith("sms:"):
        return IOC("uri", value, normalized)
    if _EMAIL_RE.fullmatch(normalized):
        return IOC("email", value, normalized.casefold())
    if _REGISTRY_RE.match(normalized):
        return IOC("registry_key", value, normalized.casefold())

    host = host_from_host_port(normalized)
    if host:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            if _is_domain(host):
                return IOC("domain:port", value, normalized.casefold())
        else:
            return IOC(f"ipv{ip.version}:port", value, normalized.casefold())

    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        pass
    else:
        return IOC(f"ipv{ip.version}", value, normalized.casefold())

    if "/" in normalized:
        host = normalized.split("/", 1)[0]
        if _is_domain(host):
            return IOC("url", value, normalized)

    if _is_domain(normalized):
        return IOC("domain", value, normalized.casefold())

    if label_type == "github_repository" and _GITHUB_REPOSITORY_RE.fullmatch(value):
        return IOC("github_repository", value, value.casefold())
    if label_type == "mutex" and " " not in value and len(value) <= 256:
        return IOC("mutex", value, value)
    if label_type in _WALLET_LABELS.values() and " " not in value:
        return IOC(label_type, value, value)

    return None


def _is_domain(value: str) -> bool:
    if not _DOMAIN_RE.fullmatch(value):
        return False
    return value.rsplit(".", 1)[-1].casefold() not in _FILE_SUFFIXES


def extract_label(line: str) -> str:
    """Extract a Markdown heading or bold list label used by the next block."""
    stripped = line.strip()
    if stripped.startswith("#"):
        return stripped.lstrip("#").strip()
    bold = _BOLD_LABEL_RE.search(stripped)
    if bold:
        return bold.group(1).strip()
    if stripped.endswith(":") and len(stripped) <= 120:
        return stripped[:-1].strip()
    return ""


def split_table_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def is_table_separator(cells: list[str]) -> bool:
    return bool(cells) and all(
        _TABLE_SEPARATOR_RE.fullmatch(cell.replace(" ", "")) for cell in cells
    )


def values_from_table_cell(cell: str) -> list[str]:
    """Split cells such as ``value1`, `value2`` without splitting URL commas."""
    inline_values = _INLINE_CODE_RE.findall(cell)
    if inline_values:
        return [clean_value(value) for value in inline_values if clean_value(value)]
    value = clean_value(cell)
    return [value] if value else []


def iter_table_candidates(
    header: list[str], rows: list[list[str]], context: str
) -> Iterator[Candidate]:
    normalized_headers = [
        re.sub(r"[^a-z0-9]+", " ", cell.casefold()).strip() for cell in header
    ]
    type_column = (
        normalized_headers.index("type") if "type" in normalized_headers else None
    )
    indicator_columns: list[tuple[int, str]] = []

    for index, heading in enumerate(header):
        normalized = normalized_headers[index]
        explicit_type = type_from_label(heading)
        if normalized == "indicator":
            indicator_columns.append((index, ""))
        elif explicit_type:
            indicator_columns.append((index, explicit_type))
        elif normalized == "repo" and type_from_label(context) == "github_repository":
            indicator_columns.append((index, "github_repository"))
        elif normalized == "key" and "registry" in context.casefold():
            indicator_columns.append((index, "registry_key"))

    for row in rows:
        for column, header_type in indicator_columns:
            if column >= len(row):
                continue
            explicit_type = header_type
            if type_column is not None and type_column < len(row):
                explicit_type = row[type_column]
            for value in values_from_table_cell(row[column]):
                yield Candidate(value, context, explicit_type)


def iter_candidates(text: str) -> Iterator[Candidate]:
    """Yield IOC candidates from text fences, Markdown tables, and inline code."""
    lines = text.splitlines()
    context = ""
    index = 0
    in_fence = False
    fence_language = ""
    fence_context = ""

    while index < len(lines):
        line = lines[index]
        stripped = line.strip()

        if stripped.startswith("```"):
            if in_fence:
                in_fence = False
                fence_language = ""
            else:
                in_fence = True
                fence_language = stripped[3:].strip().casefold()
                fence_context = context
            index += 1
            continue

        if in_fence:
            if fence_language in IOC_FENCE_LANGUAGES and stripped:
                yield Candidate(stripped, fence_context)
            index += 1
            continue

        if (
            stripped.startswith("|")
            and index + 1 < len(lines)
            and lines[index + 1].strip().startswith("|")
        ):
            header = split_table_row(line)
            separator = split_table_row(lines[index + 1])
            if is_table_separator(separator):
                rows: list[list[str]] = []
                index += 2
                while index < len(lines) and lines[index].strip().startswith("|"):
                    rows.append(split_table_row(lines[index]))
                    index += 1
                yield from iter_table_candidates(header, rows, context)
                continue

        label = extract_label(line)
        if label:
            context = label

        for inline_value in _INLINE_CODE_RE.findall(line):
            yield Candidate(inline_value, context)

        index += 1


def find_ioc_readmes(root: Path) -> list[Path]:
    """Find canonical IOCs/**/README.md files below Malware and Phishing."""
    readmes: list[Path] = []
    for category in CATEGORIES:
        category_dir = root / category
        if not category_dir.is_dir():
            raise FileNotFoundError(f"required directory not found: {category_dir}")
        for family_dir in sorted(
            path for path in category_dir.iterdir() if path.is_dir()
        ):
            ioc_dir = family_dir / CANONICAL_IOC_DIR
            if not ioc_dir.is_dir():
                continue
            readmes.extend(
                path
                for path in sorted(ioc_dir.rglob("README.md"))
                if path.is_file() and not path.is_symlink()
            )
    return readmes


def confidence_info(readme: Path, root: Path) -> str:
    """Build Category | Family | optional campaign path from the README path."""
    parts = readme.relative_to(root).parts
    ioc_index = parts.index(CANONICAL_IOC_DIR)
    context_parts = (*parts[:ioc_index], *parts[ioc_index + 1 : -1])
    return " | ".join(context_parts)


def extract_readme(readme: Path) -> list[IOC]:
    """Extract and deduplicate indicators within one README source."""
    text = readme.read_text(encoding="utf-8", errors="replace")
    indicators: list[IOC] = []
    seen: set[tuple[str, str]] = set()

    for candidate in iter_candidates(text):
        indicator = classify_candidate(candidate)
        if indicator is None:
            continue
        key = (indicator.ioc_type, indicator.normalized_value)
        if key in seen:
            continue
        seen.add(key)
        indicators.append(indicator)

    return indicators


def write_csv(readmes: list[Path], root: Path, output: Path) -> int:
    """Write the requested CSV schema and return the number of rows."""
    run_date = datetime.now().astimezone().date().isoformat()
    row_count = 0

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()

        for readme in readmes:
            additional_info = confidence_info(readme, root)
            for indicator in extract_readme(readme):
                writer.writerow(
                    {
                        "IOC_type": indicator.ioc_type,
                        "Value": indicator.value,
                        "Source_feed": SOURCE_FEED,
                        "Confidence_Additional_info": additional_info,
                        "Last_modified_date": run_date,
                    }
                )
                row_count += 1

    return row_count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Repository root containing Malware/ and Phishing/ (default: script directory).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help=f"Output CSV path (default: <root>/{DEFAULT_OUTPUT}).",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    output = args.output.resolve() if args.output else root / DEFAULT_OUTPUT

    try:
        readmes = find_ioc_readmes(root)
        row_count = write_csv(readmes, root, output)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Parsed {len(readmes)} IOC README files.")
    print(f"Wrote {row_count} indicators to {output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
