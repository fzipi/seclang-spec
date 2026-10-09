"""Run the differential requests generated against Coraza through libmodsecurity v3.

Usage: MODSECURITY_LIB=… uv run python adapters/libmodsecurity/differential.py GENERATED.json --out V3.json
Input: the JSON written by `adapters/coraza/cmd/differential` (inputs plus what Coraza did).
Output: the same profiles with what libmodsecurity did, in the shape `seclang-eval` reads,
so the Lean model can be checked against v3 on the same requests; on stdout, every request
on which the two engines disagree (at least one of them then diverges from the specification,
and `seclang-eval` on both files says which). Profiles with a libmodsecurity row in
compat/known-gaps.md are skipped. Exit 1 when the engines disagree.
"""
import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import data  # noqa: E402
import engine_tier  # noqa: E402
import gaps  # noqa: E402
from mscapi import ModSecurity  # noqa: E402


def outcome(observed: engine_tier.Observed, ids: list[int]) -> dict:
    """An Observed as the output object of a stage, over the profile's rule ids."""
    out = {"triggered_rules": [i for i in ids if i in observed.triggered],
           "non_triggered_rules": [i for i in ids if i not in observed.triggered]}
    if observed.interruption is None:
        out["no_interruption"] = True
    else:
        out["interruption"] = {"rule_id": observed.interruption.rule_id, "action": observed.interruption.action}
    return out


def disagreement(a: dict, b: dict) -> str:
    """Why two stage outputs differ, or '' when they agree (status codes are not compared)."""
    if sorted(a.get("triggered_rules") or []) != sorted(b.get("triggered_rules") or []):
        return f"triggered {sorted(a.get('triggered_rules') or [])} vs {sorted(b.get('triggered_rules') or [])}"
    ia, ib = a.get("interruption"), b.get("interruption")
    if (ia is None) != (ib is None):
        return f"interruption {ia} vs {ib}"
    if ia and (ia.get("rule_id"), ia.get("action")) != (ib.get("rule_id"), ib.get("action")):
        return f"interruption {ia} vs {ib}"
    return ""


def phase4_gap(rules: str, stage: dict) -> bool:
    """compat/known-gaps.md, phase4-without-inspection.yaml: libmodsecurity evaluates no phase 4
    rule when the response body is not inspected, so such a stage is not replayed when the
    profile has phase 4 or 5 rules."""
    if not re.search(r"phase:[45]\b", rules):
        return False
    r = stage.get("response") or {}
    ct = (r.get("headers") or {}).get("Content-Type", "").split(";")[0].strip()
    access_on = re.search(r"SecResponseBodyAccess\s+On", rules, re.I) is not None
    types = " ".join(re.findall(r"SecResponseBodyMimeType ([^\n]+)", rules)).split()
    return not access_on or ct not in types


def stage_of(d: dict) -> data.Stage:
    i = d["input"]
    inp = data.Input(method=i.get("method", "GET"), uri=i.get("uri", "/"), headers=dict(i.get("headers") or {}),
                     data=i.get("data", "") or "", remote_addr=i.get("remote_addr", "127.0.0.1"))
    r = d.get("response")
    resp = data.Response(status=r.get("status", 200), headers=dict(r.get("headers") or {}), data=r.get("data", "")) if r else None
    return data.Stage(inp, resp, data.Output())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("generated", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    root = data.repo_root()
    known = gaps.load_gaps(root / "compat" / "known-gaps.md", "libmodsecurity")
    ms = ModSecurity()
    profiles = json.loads(a.generated.read_text(encoding="utf-8"))
    out, disagreements, stages, skipped = [], [], 0, 0
    for p in profiles:
        if known.get(p["path"].split("#")[0]):
            skipped += 1
            continue
        profile = data.Profile(path=p["path"], requires=[], files=p.get("files") or {}, rules=p["rules"], tests=[])
        with tempfile.TemporaryDirectory() as tmp:
            try:
                rules, debug = engine_tier.build_rules(ms, profile, Path(tmp))
            except Exception as e:  # noqa: BLE001
                print(f"{p['path']}: cannot load: {e}")
                skipped += 1
                continue
            tests = []
            for t in p["tests"]:
                st = t["stages"][0]["stage"]
                if phase4_gap(p["rules"], st):
                    continue
                coraza = st["output"]
                ids = sorted((coraza.get("triggered_rules") or []) + (coraza.get("non_triggered_rules") or []))
                observed = engine_tier.run_stage(ms, rules, debug, stage_of(st))
                mine = outcome(observed, ids)
                stages += 1
                why = disagreement(coraza, mine)
                if why:
                    disagreements.append((p["path"], t["test_title"], why, st["input"]))
                tests.append({"test_title": t["test_title"], "stages": [{"stage": {"input": st["input"], "response": st.get("response"), "output": mine}}]})
            rules.close()
        out.append({"path": p["path"].replace("#differential", "#differential-v3"), "rules": p["rules"], "files": p.get("files") or {},
                    "expect_error": False, "tests": tests})
    a.out.write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
    for path, title, why, inp in disagreements:
        print(f"{path} [{title}]: Coraza vs libmodsecurity {why}\n  input: {json.dumps(inp, ensure_ascii=False)}")
    print(f"{stages} stages, {len(disagreements)} engine disagreements, {skipped} profiles skipped")
    return 1 if disagreements else 0


if __name__ == "__main__":
    sys.exit(main())
