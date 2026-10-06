#!/usr/bin/env python3
"""Validate seclang-spec repository invariants.

Usage: python3 tools/validate.py        (exit 1 if anything is wrong)

Checks: test files match their schema; every Core spec feature has a test and no test
points at a missing anchor; ADR files and index agree; compat/matrix.md is current.
"""
import json
import re
import sys
from pathlib import Path
from typing import Callable, Iterator

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parent.parent


def _rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def load_test_files(root: Path) -> Iterator[tuple[Path, object]]:
    """Yield (path, parsed) for every test file. Parse failures yield (path, exception)."""
    for path in sorted((root / "tests" / "unit").rglob("*.json")):
        try:
            yield path, json.loads(path.read_text())
        except ValueError as exc:
            yield path, exc
    for path in sorted((root / "tests" / "engine").rglob("*.yaml")):
        try:
            yield path, yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            yield path, exc


def check_tests(root: Path) -> list[str]:
    schemas = {
        tier: jsonschema.Draft202012Validator(json.loads((root / "tests" / "schema" / f"{tier}.schema.json").read_text()))
        for tier in ("unit", "engine")
    }
    errors = []
    for path, data in load_test_files(root):
        rel = _rel(root, path)
        if isinstance(data, Exception):
            errors.append(f"{rel}: cannot parse: {data}")
            continue
        tier = path.relative_to(root / "tests").parts[0]
        for err in sorted(schemas[tier].iter_errors(data), key=lambda e: list(map(str, e.absolute_path))):
            where = "/".join(map(str, err.absolute_path)) or "<root>"
            errors.append(f"{rel}: {where}: {err.message}")
    return errors


HEADING_RE = re.compile(r"^#{2,4}\s+(.+?)\s*$")
STATUS_RE = re.compile(r"^\*\*Status:\*\*\s+(Core|Extended|Deprecated|Engine-specific)\s*$")


def slug(heading: str) -> str:
    """GitHub-style heading anchor."""
    cleaned = re.sub(r"[^a-z0-9 -]", "", heading.lower())
    return cleaned.strip().replace(" ", "-")


def spec_features(root: Path) -> dict[str, str]:
    """Map 'NN-file.md#anchor' -> status for every heading followed by a **Status:** line."""
    features = {}
    for path in sorted((root / "spec").glob("*.md")):
        heading = None
        for line in path.read_text().splitlines():
            if m := HEADING_RE.match(line):
                heading = slug(m.group(1))
            elif (m := STATUS_RE.match(line)) and heading:
                features[f"{path.name}#{heading}"] = m.group(1)
                heading = None
            elif line.strip():
                heading = None  # status must directly follow its heading
    return features


def test_spec_refs(root: Path) -> dict[str, list[str]]:
    """Map spec anchor -> test files that reference it."""
    refs: dict[str, list[str]] = {}
    for path, data in load_test_files(root):
        if isinstance(data, Exception):
            continue
        rel = _rel(root, path)
        found = []
        if isinstance(data, list):
            found = [c.get("spec") for c in data if isinstance(c, dict)]
        elif isinstance(data, dict):
            found = [data.get("spec")] + [t.get("spec") for t in data.get("tests", []) if isinstance(t, dict)]
        for ref in found:
            if ref:
                refs.setdefault(ref, []).append(rel)
    return refs


def check_coverage(root: Path) -> list[str]:
    features = spec_features(root)
    refs = test_spec_refs(root)
    errors = []
    for ref, files in sorted(refs.items()):
        if ref not in features:
            for f in sorted(set(files)):
                errors.append(f"{f}: spec anchor {ref} does not exist or has no **Status:** line")
    for anchor, status in sorted(features.items()):
        if status == "Core" and anchor not in refs:
            errors.append(f"spec/{anchor}: Core feature has no test")
    return errors


ADR_FILE_RE = re.compile(r"^(\d{4})-[a-z0-9]+(?:-[a-z0-9]+)*\.md$")
ADR_TITLE_RE = re.compile(r"^# ADR-(\d{4}): \S")
ADR_FIELD_RE = re.compile(r"^- \*\*(Status|Date|Deciders|Category):\*\* (.+?)\s*$")
ADR_INDEX_RE = re.compile(r"^\| \[(\d{4})\]\(([^)]+)\) \|")
ADR_TEST_PATH_RE = re.compile(r"`(tests/[^`\s]+)`")
ADR_FIELDS = ("Status", "Date", "Deciders", "Category")
ADR_STATUSES = {"proposed", "accepted", "superseded", "rejected"}
ADR_CATEGORIES = {"Divergence", "Clarification", "Deprecation", "Extension"}


def check_adrs(root: Path) -> list[str]:
    adr_dir = root / "adr"
    errors = []
    files = sorted(p for p in adr_dir.glob("*.md") if p.name not in ("README.md", "0000-template.md"))
    for path in files:
        rel = _rel(root, path)
        m = ADR_FILE_RE.match(path.name)
        if not m:
            errors.append(f"{rel}: filename must be NNNN-lower-kebab.md")
            continue
        number = m.group(1)
        text = path.read_text()
        lines = text.splitlines()
        tm = ADR_TITLE_RE.match(lines[0] if lines else "")
        if not tm:
            errors.append(f"{rel}: first line must be '# ADR-{number}: <title>'")
        elif tm.group(1) != number:
            errors.append(f"{rel}: filename number {number} but title says ADR-{tm.group(1)}")
        fields = {}
        for line in lines[1:]:
            if line.startswith("## "):
                break
            if fm := ADR_FIELD_RE.match(line):
                fields[fm.group(1)] = fm.group(2)
        for name in ADR_FIELDS:
            if name not in fields:
                errors.append(f"{rel}: missing header field **{name}:**")
        if "Status" in fields and fields["Status"] not in ADR_STATUSES:
            errors.append(f"{rel}: Status '{fields['Status']}' not in {sorted(ADR_STATUSES)}")
        if "Category" in fields and fields["Category"] not in ADR_CATEGORIES:
            errors.append(f"{rel}: Category '{fields['Category']}' not in {sorted(ADR_CATEGORIES)}")
        if "Date" in fields and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", fields["Date"]):
            errors.append(f"{rel}: Date '{fields['Date']}' must be YYYY-MM-DD")
        if fields.get("Category") == "Divergence":
            section = text.split("\n## Tests", 1)
            paths = ADR_TEST_PATH_RE.findall(section[1].split("\n## ", 1)[0]) if len(section) == 2 else []
            if not paths:
                errors.append(f"{rel}: Divergence ADR needs a '## Tests' section listing at least one `tests/...` path")
            for p in paths:
                if not (root / p).is_file():
                    errors.append(f"{rel}: listed test {p} does not exist")
    index_path = adr_dir / "README.md"
    indexed = {}
    if index_path.is_file():
        for line in index_path.read_text().splitlines():
            if im := ADR_INDEX_RE.match(line):
                indexed[im.group(2)] = im.group(1)
    else:
        errors.append("adr/README.md: missing")
    on_disk = {p.name for p in files}
    for name in sorted(on_disk - set(indexed)):
        errors.append(f"adr/{name}: not listed in adr/README.md index")
    for name in sorted(set(indexed) - on_disk):
        errors.append(f"adr/README.md: index row for {name} but no such file")
    return errors


CHECKS: list[Callable[[Path], list[str]]] = [check_tests, check_coverage, check_adrs]


def main(root: Path = ROOT, checks: list[Callable[[Path], list[str]]] | None = None) -> int:
    errors = [e for check in (checks or CHECKS) for e in check(root)]
    for e in errors:
        print(e, file=sys.stderr)
    print(f"{len(errors)} error(s)", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
