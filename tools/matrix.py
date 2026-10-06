"""Render compat/matrix.md from compat/matrix.json.

Usage: python3 tools/matrix.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENGINES = ("v2", "v3", "coraza")


def load(root: Path = ROOT) -> dict:
    return json.loads((root / "compat" / "matrix.json").read_text())


def render(matrix: dict) -> str:
    out = [
        "# Engine compatibility matrix",
        "",
        f"Generated from `compat/matrix.json` by `tools/matrix.py` on {matrix['generated']}. "
        "Do not edit by hand; edit the JSON and rerun the tool.",
        "",
    ]
    for key, label in matrix["engines"].items():
        out.append(f"- **{key}**: {label}")
    for category, rows in matrix["categories"].items():
        for row in rows:
            missing = [e for e in ENGINES if e not in row]
            if missing:
                raise ValueError(f"{category}/{row.get('name', '?')}: missing engine key(s) {missing}")
        has_status = any("status" in row for row in rows)
        in_all = sum(all(row[e] for e in ENGINES) for row in rows)
        header = ["Name", *ENGINES] + (["status"] if has_status else [])
        out += [
            "",
            f"## {category} ({in_all} of {len(rows)} in all engines)",
            "",
            "| " + " | ".join(header) + " |",
            "|---|" + "---|" * (len(header) - 1),
        ]
        for row in sorted(rows, key=lambda r: r["name"].lower()):
            cells = [("yes" if row[e] else "-") for e in ENGINES]
            if has_status:
                cells.append(row.get("status", "-"))
            out.append(f"| `{row['name']}` | " + " | ".join(cells) + " |")
    return "\n".join(out) + "\n"


def main(root: Path = ROOT) -> None:
    (root / "compat" / "matrix.md").write_text(render(load(root)))


if __name__ == "__main__":
    main()
    print("wrote compat/matrix.md", file=sys.stderr)
