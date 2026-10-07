"""Rows of compat/known-gaps.md for one engine: {test path: behaviour today}."""
from __future__ import annotations

import re
from pathlib import Path

_PATH = re.compile(r"`(tests/[^`]+)`")


def load_gaps(path: Path, engine: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in Path(path).read_text().splitlines():
        if not line.startswith("| `tests/"):
            continue
        cells = line.strip("| ").split(" | ")
        if len(cells) < 3 or engine.lower() not in cells[1].lower():
            continue
        for p in _PATH.findall(cells[0]):
            out[p] = cells[2].strip()
    return out
