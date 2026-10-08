"""Extract every engine profile's configuration for the Lean parser (formal/ParseMain.lean).

Usage: uv run python tools/engine_rules.py > formal/.lake/engine-rules.json
Output: a JSON list of {path, rules, files, expect_error}; expect_error is true when any
stage of the profile asserts expect_error.
"""
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools import validate  # noqa: E402


def extract(root: Path) -> list[dict]:
    out = []
    for path in sorted((root / "tests" / "engine").rglob("*.yaml")):
        d = yaml.safe_load(path.read_text())
        expect = any(s["stage"]["output"].get("expect_error", False) for t in d["tests"] for s in t["stages"])
        out.append({
            "path": path.relative_to(root).as_posix(),
            "rules": d["rules"],
            "files": d.get("files") or {},
            "expect_error": bool(expect),
        })
    return out


if __name__ == "__main__":
    json.dump(extract(validate.ROOT), sys.stdout, indent=1, ensure_ascii=False)
    print()
