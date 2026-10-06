"""Import SecRules Test Set JSON into tests/unit with plain JSON escapes and spec anchors.

Usage: uv run python tools/import_sts.py <sts-dir> [--dest tests/unit]
Anchors come from the feature headings of spec/06-operators.md and spec/07-transformations.md.
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools import validate  # noqa: E402

FIELDS = ("input", "output", "param")
# Files whose content is decided by the spec rather than imported (see the section's
# divergence notes); the importer never overwrites them.
HAND_MAINTAINED = {("transformations", "base64Decode"), ("operators", "pmFromFile")}  # pmFromFile cases need corpus-internal files


_HEX = re.compile(r"\\\\x([0-9a-fA-F]{2})")
_UNI = re.compile(r"\\\\u([0-9a-fA-F]{4})")
_SIMPLE = {"\\\\0": "\\0", "\\\\b": "\\b", "\\\\t": "\\t", "\\\\n": "\\n", "\\\\r": "\\r"}


def unescape(s: str) -> str:
    """Decode exactly the escapes the libmodsecurity unit runner decodes after JSON parsing.

    test/unit/unit_test.cc replaces \\xHH, \\uHHHH, \\0, \\b, \\t, \\n, \\r; everything else
    (regex escapes such as \\d, and \\\\) is left as written.
    """
    if "\\" not in s:
        return s
    s = _HEX.sub(lambda m: chr(int(m.group(1), 16)), s)
    s = _UNI.sub(lambda m: chr(int(m.group(1), 16)), s)
    for k, v in _SIMPLE.items():
        s = s.replace(k, v)
    return s


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
            if not anchor or (tier, name) in HAND_MAINTAINED:
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
    for anchor, status in validate.spec_features(root).items():
        file, frag = anchor.split("#")
        if file in ("06-operators.md", "07-transformations.md") and status in ("Core", "Extended"):
            out[frag] = anchor
    return out


if __name__ == "__main__":
    src = Path(sys.argv[1])
    dest = Path(sys.argv[sys.argv.index("--dest") + 1]) if "--dest" in sys.argv else validate.ROOT / "tests" / "unit"
    counts = main(src, dest, anchors_from_spec(validate.ROOT))
    print(f"imported {sum(counts.values())} cases into {len(counts)} files", file=sys.stderr)
