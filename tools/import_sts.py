"""Import SecRules Test Set JSON into tests/unit with plain JSON escapes and spec anchors.

Usage: uv run python tools/import_sts.py <sts-dir> [--dest tests/unit]
Anchors come from the feature headings of spec/06-operators.md and spec/07-transformations.md.
"""
import codecs
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools import validate  # noqa: E402

FIELDS = ("input", "output", "param")


def unescape(s: str) -> str:
    """The corpus stores escapes as literal backslash sequences that runners decode after parsing."""
    if "\\" not in s:
        return s
    return codecs.decode(s.encode("latin-1", "backslashreplace"), "unicode_escape")


def convert_case(case: dict, anchor: str) -> dict | None:
    if "resource" in case:
        return None
    out = {k: (unescape(v) if k in FIELDS and isinstance(v, str) else v) for k, v in case.items()}
    out["spec"] = anchor
    return out


def main(src: Path, dest: Path, anchors: dict[str, str]) -> dict[str, int]:
    counts = {}
    for tier in ("operators", "transformations"):
        for path in sorted((src / tier).glob("*.json")):
            name = path.stem
            anchor = anchors.get(name) or anchors.get(name.lower())
            if not anchor:
                continue
            cases = [c for c in (convert_case(c, anchor) for c in json.loads(path.read_text())) if c]
            if not cases:
                continue
            (dest / tier).mkdir(parents=True, exist_ok=True)
            (dest / tier / f"{name}.json").write_text(json.dumps(cases, indent=1, ensure_ascii=False) + "\n")
            counts[name] = len(cases)
    return counts


def anchors_from_spec(root: Path) -> dict[str, str]:
    """Heading slug (lowercased name) -> anchor, for operators and transformations."""
    out = {}
    for anchor in validate.spec_features(root):
        file, frag = anchor.split("#")
        if file in ("06-operators.md", "07-transformations.md"):
            out[frag] = anchor
    return out


if __name__ == "__main__":
    src = Path(sys.argv[1])
    dest = Path(sys.argv[sys.argv.index("--dest") + 1]) if "--dest" in sys.argv else validate.ROOT / "tests" / "unit"
    counts = main(src, dest, anchors_from_spec(validate.ROOT))
    print(f"imported {sum(counts.values())} cases into {len(counts)} files", file=sys.stderr)
