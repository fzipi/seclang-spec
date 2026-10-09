import unittest

from tools import formal_results

CHECK = """base64Decode.json: 4 passed, 0 failed
detectSQLi.json: skipped (not formalized)
rx-pcre-extra.json: 0 passed, 0 failed, 2 skipped
  skipped: @rx "<\\\\?(?!xml)": regex outside the Core subset
within.json: 7 passed, 0 failed
"""
EVAL = """tests/engine/body/xml-no-xxe.yaml: unsupported (variable XML)
tests/engine/actions/setvar.yaml [five forms]: ok
184 stages, 0 mismatches, 4 unsupported profiles
"""
LEAN = '''/-- ADR-0017: a rule without `phase` runs in phase 2. -/
theorem phase_default (r : Rule) : chainPhase r = 2 := by
  simp
#guard true
#guard false == false
/-- Two
lines. -/
theorem other : True := trivial
'''


class ParseTests(unittest.TestCase):
    def test_check_summary(self):
        s = formal_results.parse_check(CHECK)
        self.assertEqual((s.files, s.passed, s.failed, s.skipped_cases), (3, 11, 0, 2))
        self.assertEqual(s.skipped_files, ["detectSQLi.json"])

    def test_eval_summary(self):
        s = formal_results.parse_eval(EVAL)
        self.assertEqual((s.stages, s.mismatches), (184, 0))
        self.assertEqual(s.unsupported, [("tests/engine/body/xml-no-xxe.yaml", "variable XML")])

    def test_lean_scan(self):
        self.assertEqual(formal_results.count_guards(LEAN), 2)
        self.assertEqual(formal_results.theorems(LEAN), [
            ("phase_default", "ADR-0017: a rule without `phase` runs in phase 2."),
            ("other", "Two lines."),
        ])

    def test_render_is_markdown_table(self):
        md = formal_results.render(
            transformations=formal_results.parse_check(CHECK), operators=formal_results.parse_check(CHECK),
            parse="104 profiles, 0 mismatches", eval_=formal_results.parse_eval(EVAL), crs=("4252", "29 profiles, 0 mismatches"),
            guards=[("Regex.lean", 30)], thms=[("phase_default", "ADR-0017: x.")])
        self.assertTrue(md.startswith("# Formal model results\n"))
        self.assertIn("| `tests/engine/body/xml-no-xxe.yaml` | variable XML |", md)
        self.assertIn("| `phase_default` | ADR-0017: x. |", md)
        self.assertIn("4252", md)
