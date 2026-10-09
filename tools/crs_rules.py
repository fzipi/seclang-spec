"""Package an OWASP CRS checkout for the Lean parser (formal/ParseMain.lean): the acceptance run.

Usage: uv run python tools/crs_rules.py /path/to/coreruleset > formal/.lake/crs.json
       (cd formal && lake exe seclang-parse .lake/crs.json)
Output: one profile per configuration file (crs-setup.conf.example, then rules/*.conf in
order) plus one profile ALL with every file concatenated, so cross-file invariants such as
unique ids are checked too; rules/*.data are the auxiliary files of every profile. Every
profile must be accepted: CRS is written within the Core grammar.
"""
import json
import sys
from pathlib import Path


def extract(crs: Path) -> list[dict]:
    confs = [crs / "crs-setup.conf.example"] + sorted((crs / "rules").glob("*.conf"))
    files = {p.name: p.read_text(encoding="utf-8") for p in sorted((crs / "rules").glob("*.data"))}
    texts = [(p.name, p.read_text(encoding="utf-8")) for p in confs if p.exists()]
    profile = lambda name, rules: {"path": name, "rules": rules, "files": files, "expect_error": False, "tests": []}
    return [profile(n, t) for n, t in texts] + [profile("ALL", "\n".join(t for _, t in texts))]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: crs_rules.py CRS_DIR")
    json.dump(extract(Path(sys.argv[1])), sys.stdout, ensure_ascii=False)
    print()
