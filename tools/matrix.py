"""Render compat/matrix.md from compat/matrix.json.

Usage: python3 tools/matrix.py
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENGINES = ("v2", "v3", "coraza")
# category -> (spec chapter, anchor prefix): a row names the feature whose heading is
# `### name` (ctl options are headed `### ctl:name`, anchor `ctlname`)
SPEC_FILES = {
    "directives": ("04-directives.md", ""),
    "variables": ("05-variables.md", ""),
    "operators": ("06-operators.md", ""),
    "transformations": ("07-transformations.md", ""),
    "actions": ("08-actions.md", ""),
    "ctl": ("08-actions.md", "ctl"),
}


def slug(heading: str) -> str:
    """GitHub-style heading anchor."""
    cleaned = re.sub(r"[^a-z0-9_ -]", "", heading.lower())
    return cleaned.strip().replace(" ", "-")


def load(root: Path = ROOT) -> dict:
    return json.loads((root / "compat" / "matrix.json").read_text())


def spec_anchors(root: Path = ROOT) -> set[str]:
    """Every `file.md#anchor` of a `###` heading in the specification."""
    out = set()
    for path in sorted((root / "spec").glob("*.md")):
        for m in re.finditer(r"^### (.+)$", path.read_text(encoding="utf-8"), re.M):
            out.add(f"{path.name}#{slug(m.group(1))}")
    return out


def render(matrix: dict, anchors: set[str] | None = None) -> str:
    """The markdown; with `anchors`, a name whose specification entry exists links to it
    (a relative link, valid on GitHub; the site makes it absolute)."""
    out = [
        "# Engine compatibility matrix",
        "",
        f"Generated from `compat/matrix.json` by `tools/matrix.py` on {matrix['generated']}. "
        "Do not edit by hand; edit the JSON and rerun the tool. A name links to its specification "
        "entry; on the published site, rows where the engines differ are tinted.",
        "",
    ]
    for key, label in matrix["engines"].items():
        out.append(f"- **{key}**: {label}")
    for category, rows in matrix["categories"].items():
        for i, row in enumerate(rows):
            if "name" not in row:
                raise ValueError(f"{category}[{i}]: row has no 'name'")
            missing = [e for e in ENGINES if e not in row]
            if missing:
                raise ValueError(f"{category}/{row['name']}: missing engine key(s) {missing}")
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
        spec_file, prefix = SPEC_FILES.get(category, (None, ""))
        for row in sorted(rows, key=lambda r: r["name"].lower()):
            name = f"`{row['name']}`"
            if anchors is not None and spec_file:
                anchor = f"{spec_file}#{prefix}{slug(row['name'])}"
                if anchor in anchors:
                    name = f"[{name}](../spec/{anchor})"
            cells = [("yes" if row[e] else "-") for e in ENGINES]
            if has_status:
                st = row.get("status", "-")
                cells.append(f"{st} ({row['exception']})" if row.get("exception") else st)
            out.append(f"| {name} | " + " | ".join(cells) + " |")
    return "\n".join(out) + "\n"


def main(root: Path = ROOT) -> None:
    (root / "compat" / "matrix.md").write_text(render(load(root), spec_anchors(root)))


if __name__ == "__main__":
    main()
    print("wrote compat/matrix.md", file=sys.stderr)
