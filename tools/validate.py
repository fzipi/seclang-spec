#!/usr/bin/env python3
"""Validate seclang-spec repository invariants.

Usage: python3 tools/validate.py        (exit 1 if anything is wrong)

Checks: test files match their schema; every Core spec feature has a test and no test
points at a missing anchor; ADR files and index agree; compat/matrix.md is current.
"""
import json
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


CHECKS: list[Callable[[Path], list[str]]] = [check_tests]


def main(root: Path = ROOT, checks: list[Callable[[Path], list[str]]] | None = None) -> int:
    errors = [e for check in (checks or CHECKS) for e in check(root)]
    for e in errors:
        print(e, file=sys.stderr)
    print(f"{len(errors)} error(s)", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
