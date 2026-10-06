import json
import shutil
import tempfile
import unittest
from pathlib import Path

from tools import validate

REAL_ROOT = Path(__file__).resolve().parent.parent

GOOD_UNIT = [{"type": "tfn", "name": "lowercase", "input": "A", "output": "a", "ret": 1,
              "spec": "07-transformations.md#lowercase"}]

GOOD_ENGINE = """\
meta:
  name: sample
  description: sample profile
spec: 04-directives.md#secruleengine
rules: |
  SecRuleEngine On
tests:
  - test_title: t
    stages:
      - stage:
          input:
            uri: /
          output:
            no_interruption: true
"""


def make_repo(tmp: Path) -> Path:
    for d in ("tests/unit", "tests/engine", "spec", "adr", "compat"):
        (tmp / d).mkdir(parents=True)
    shutil.copytree(REAL_ROOT / "tests" / "schema", tmp / "tests" / "schema")
    return tmp


class SchemaCheckTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_repo(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def test_valid_files_produce_no_errors(self):
        (self.root / "tests/unit/t.json").write_text(json.dumps(GOOD_UNIT))
        (self.root / "tests/engine/e.yaml").write_text(GOOD_ENGINE)
        self.assertEqual(validate.check_tests(self.root), [])

    def test_unit_schema_violation_is_reported_with_path(self):
        bad = [{"type": "op", "name": "rx", "input": "x", "ret": 1}]  # op without param
        (self.root / "tests/unit/bad.json").write_text(json.dumps(bad))
        errors = validate.check_tests(self.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("tests/unit/bad.json", errors[0])
        self.assertIn("param", errors[0])

    def test_engine_unknown_field_is_reported(self):
        (self.root / "tests/engine/e.yaml").write_text(GOOD_ENGINE.replace("no_interruption", "no_interuption"))
        errors = validate.check_tests(self.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("no_interuption", errors[0])

    def test_engine_file_that_is_a_list_is_a_schema_error_not_a_crash(self):
        (self.root / "tests/engine/list.yaml").write_text("- a\n- b\n")
        errors = validate.check_tests(self.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("tests/engine/list.yaml", errors[0])

    def test_unparseable_yaml_is_reported(self):
        (self.root / "tests/engine/broken.yaml").write_text("meta: [unclosed\n")
        errors = validate.check_tests(self.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("broken.yaml", errors[0])

    def test_main_returns_1_on_errors_and_0_otherwise(self):
        self.assertEqual(validate.main(self.root, checks=[validate.check_tests]), 0)
        (self.root / "tests/unit/bad.json").write_text("[]")
        self.assertEqual(validate.main(self.root, checks=[validate.check_tests]), 1)


if __name__ == "__main__":
    unittest.main()


SPEC_FEATURE = """\
# Transformations

### lowercase

**Status:** Core

Lowercases ASCII letters.

### uppercase

**Status:** Extended

### `rx`

**Status:** Core
"""


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_repo(Path(self._tmp.name))
        (self.root / "spec/07-transformations.md").write_text(SPEC_FEATURE)
        (self.root / "spec/04-directives.md").write_text("# Directives\n\n### SecRuleEngine\n\n**Status:** Core\n")
        (self.root / "tests/unit/t.json").write_text(json.dumps(GOOD_UNIT))
        (self.root / "tests/engine/e.yaml").write_text(GOOD_ENGINE)

    def tearDown(self):
        self._tmp.cleanup()

    def test_slug_matches_github(self):
        self.assertEqual(validate.slug("SecRuleEngine"), "secruleengine")
        self.assertEqual(validate.slug("Name matching"), "name-matching")
        self.assertEqual(validate.slug("`rx`"), "rx")
        self.assertEqual(validate.slug("ctl: ruleRemoveById"), "ctl-ruleremovebyid")

    def test_spec_features_are_file_qualified_with_status(self):
        feats = validate.spec_features(self.root)
        self.assertEqual(feats["07-transformations.md#lowercase"], "Core")
        self.assertEqual(feats["07-transformations.md#uppercase"], "Extended")
        self.assertEqual(feats["07-transformations.md#rx"], "Core")
        self.assertEqual(feats["04-directives.md#secruleengine"], "Core")
        self.assertNotIn("07-transformations.md#transformations", feats)  # no status line

    def test_same_heading_in_two_files_does_not_collide(self):
        (self.root / "spec/06-operators.md").write_text("# Operators\n\n### `rx`\n\n**Status:** Core\n")
        feats = validate.spec_features(self.root)
        self.assertIn("06-operators.md#rx", feats)
        self.assertIn("07-transformations.md#rx", feats)

    def test_core_feature_without_test_is_reported(self):
        errors = validate.check_coverage(self.root)
        self.assertTrue(any("07-transformations.md#rx" in e and "no test" in e for e in errors))
        self.assertFalse(any("uppercase" in e for e in errors))  # Extended is not required

    def test_dangling_ref_is_reported(self):
        bad = [dict(GOOD_UNIT[0], spec="07-transformations.md#nope")]
        (self.root / "tests/unit/bad.json").write_text(json.dumps(bad))
        errors = validate.check_coverage(self.root)
        self.assertTrue(any("tests/unit/bad.json" in e and "#nope" in e for e in errors))

    def test_ref_to_heading_without_status_is_dangling(self):
        bad = [dict(GOOD_UNIT[0], spec="07-transformations.md#transformations")]
        (self.root / "tests/unit/bad.json").write_text(json.dumps(bad))
        errors = validate.check_coverage(self.root)
        self.assertTrue(any("#transformations" in e for e in errors))

    def test_fully_covered_repo_has_no_errors(self):
        (self.root / "spec/07-transformations.md").write_text(SPEC_FEATURE.replace("### `rx`\n\n**Status:** Core\n", ""))
        self.assertEqual(validate.check_coverage(self.root), [])


ADR_OK = """\
# ADR-0001: Example decision

- **Status:** proposed
- **Date:** 2026-10-06
- **Deciders:** @someone
- **Category:** Clarification

## Context

Why.

## Decision

What.
"""

ADR_DIVERGENCE = ADR_OK.replace("0001", "0002").replace("Clarification", "Divergence") + """
## Tests

- `tests/engine/e.yaml`
"""

INDEX_OK = """\
# ADRs

| ADR | Title | Category | Status |
|---|---|---|---|
| [0001](0001-example-decision.md) | Example decision | Clarification | proposed |
"""


class AdrTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_repo(Path(self._tmp.name))
        (self.root / "adr/0000-template.md").write_text("# ADR-NNNN: template\n")
        (self.root / "adr/0001-example-decision.md").write_text(ADR_OK)
        (self.root / "adr/README.md").write_text(INDEX_OK)
        (self.root / "tests/engine/e.yaml").write_text(GOOD_ENGINE)

    def tearDown(self):
        self._tmp.cleanup()

    def test_valid_adr_and_index(self):
        self.assertEqual(validate.check_adrs(self.root), [])

    def test_bad_filename(self):
        (self.root / "adr/0003_Bad_Name.md").write_text(ADR_OK.replace("0001", "0003"))
        errors = validate.check_adrs(self.root)
        self.assertTrue(any("0003_Bad_Name.md" in e and "filename" in e for e in errors))

    def test_title_number_mismatch(self):
        (self.root / "adr/0001-example-decision.md").write_text(ADR_OK.replace("ADR-0001", "ADR-0007"))
        errors = validate.check_adrs(self.root)
        self.assertTrue(any("0001" in e and "0007" in e for e in errors))

    def test_unknown_category_and_status(self):
        (self.root / "adr/0001-example-decision.md").write_text(
            ADR_OK.replace("Clarification", "Perf").replace("proposed", "draft"))
        errors = validate.check_adrs(self.root)
        self.assertTrue(any("Category" in e and "Perf" in e for e in errors))
        self.assertTrue(any("Status" in e and "draft" in e for e in errors))

    def test_missing_field(self):
        (self.root / "adr/0001-example-decision.md").write_text(ADR_OK.replace("- **Date:** 2026-10-06\n", ""))
        errors = validate.check_adrs(self.root)
        self.assertTrue(any("Date" in e for e in errors))

    def test_divergence_requires_existing_test(self):
        (self.root / "adr/0002-second.md").write_text(ADR_DIVERGENCE)
        (self.root / "adr/README.md").write_text(INDEX_OK + "| [0002](0002-second.md) | Second | Divergence | proposed |\n")
        self.assertEqual(validate.check_adrs(self.root), [])
        (self.root / "adr/0002-second.md").write_text(ADR_DIVERGENCE.replace("e.yaml", "missing.yaml"))
        errors = validate.check_adrs(self.root)
        self.assertTrue(any("missing.yaml" in e for e in errors))
        (self.root / "adr/0002-second.md").write_text(ADR_DIVERGENCE.split("## Tests")[0])
        errors = validate.check_adrs(self.root)
        self.assertTrue(any("0002-second.md" in e and "Tests" in e for e in errors))

    def test_file_missing_from_index_and_index_row_without_file(self):
        (self.root / "adr/0002-second.md").write_text(ADR_OK.replace("0001", "0002"))
        errors = validate.check_adrs(self.root)
        self.assertTrue(any("0002-second.md" in e and "index" in e for e in errors))
        (self.root / "adr/README.md").write_text(INDEX_OK + "| [0009](0009-ghost.md) | Ghost | Clarification | proposed |\n")
        errors = validate.check_adrs(self.root)
        self.assertTrue(any("0009-ghost.md" in e for e in errors))


from tools import matrix as matrix_mod
from tools.test_matrix import SAMPLE as MATRIX_SAMPLE


class MatrixCheckTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_repo(Path(self._tmp.name))
        (self.root / "compat/matrix.json").write_text(json.dumps(MATRIX_SAMPLE))

    def tearDown(self):
        self._tmp.cleanup()

    def test_fresh_markdown_passes(self):
        matrix_mod.main(self.root)
        self.assertEqual(validate.check_matrix(self.root), [])

    def test_stale_markdown_is_reported(self):
        (self.root / "compat/matrix.md").write_text("# old\n")
        errors = validate.check_matrix(self.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("tools/matrix.py", errors[0])

    def test_missing_markdown_is_reported(self):
        errors = validate.check_matrix(self.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("compat/matrix.md", errors[0])

    def test_broken_json_row_is_reported_not_raised(self):
        broken = json.loads(json.dumps(MATRIX_SAMPLE))
        del broken["categories"]["operators"][0]["v2"]
        (self.root / "compat/matrix.json").write_text(json.dumps(broken))
        errors = validate.check_matrix(self.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("rx", errors[0])


class ReviewFixTests(unittest.TestCase):
    """Findings from the Phase 1 whole-branch review."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_repo(Path(self._tmp.name))
        (self.root / "spec/07-transformations.md").write_text(SPEC_FEATURE.replace("### `rx`\n\n**Status:** Core\n", ""))
        (self.root / "spec/04-directives.md").write_text("# Directives\n\n### SecRuleEngine\n\n**Status:** Core\n")
        (self.root / "tests/unit/t.json").write_text(json.dumps(GOOD_UNIT))
        (self.root / "tests/engine/e.yaml").write_text(GOOD_ENGINE)

    def tearDown(self):
        self._tmp.cleanup()

    def test_duplicate_heading_in_one_file_is_reported(self):
        (self.root / "spec/07-transformations.md").write_text(SPEC_FEATURE + "\n### lowercase\n\n**Status:** Extended\n")
        errors = validate.check_coverage(self.root)
        self.assertTrue(any("07-transformations.md#lowercase" in e and "duplicate" in e for e in errors))

    def test_unexpected_file_in_test_tree_is_reported(self):
        (self.root / "tests/engine/profile.yml").write_text(GOOD_ENGINE)
        (self.root / "tests/unit/notes.txt").write_text("hi")
        errors = validate.check_tests(self.root)
        self.assertTrue(any("tests/engine/profile.yml" in e and "*.yaml" in e for e in errors))
        self.assertTrue(any("tests/unit/notes.txt" in e and "*.json" in e for e in errors))

    def test_requires_must_resolve_to_extended_feature(self):
        ok = GOOD_ENGINE.replace("rules: |", "requires: [07-transformations.md#uppercase]\nrules: |")
        (self.root / "tests/engine/e.yaml").write_text(ok)
        self.assertEqual(validate.check_coverage(self.root), [])
        core = GOOD_ENGINE.replace("rules: |", "requires: [07-transformations.md#lowercase]\nrules: |")
        (self.root / "tests/engine/e.yaml").write_text(core)
        errors = validate.check_coverage(self.root)
        self.assertTrue(any("requires" in e and "#lowercase" in e and "Core" in e for e in errors))
        missing = GOOD_ENGINE.replace("rules: |", "requires: [07-transformations.md#nope]\nrules: |")
        (self.root / "tests/engine/e.yaml").write_text(missing)
        errors = validate.check_coverage(self.root)
        self.assertTrue(any("requires" in e and "#nope" in e for e in errors))


MATRIX_WITH_STATUS = {
    "generated": "2026-10-06",
    "engines": {"v2": "a", "v3": "b", "coraza": "c"},
    "categories": {"directives": [
        {"name": "SecRuleEngine", "v2": True, "v3": True, "coraza": True, "status": "Core"},
        {"name": "SecDataset", "v2": False, "v3": False, "coraza": True, "status": "Engine-specific"},
    ]},
}

SPEC_DIRECTIVES = """\
# Directives

### SecRuleEngine

**Status:** Core

### SecDataset

**Status:** Engine-specific
"""


class MatrixStatusTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_repo(Path(self._tmp.name))
        (self.root / "compat/matrix.json").write_text(json.dumps(MATRIX_WITH_STATUS))
        (self.root / "spec/04-directives.md").write_text(SPEC_DIRECTIVES)

    def tearDown(self):
        self._tmp.cleanup()

    def test_consistent_matrix_and_spec_pass(self):
        self.assertEqual(validate.check_matrix_status(self.root), [])

    def test_status_mismatch_is_reported(self):
        (self.root / "spec/04-directives.md").write_text(SPEC_DIRECTIVES.replace("**Status:** Core", "**Status:** Extended"))
        errors = validate.check_matrix_status(self.root)
        self.assertTrue(any("SecRuleEngine" in e and "Core" in e and "Extended" in e for e in errors))

    def test_core_row_missing_in_an_engine_is_reported(self):
        m = json.loads(json.dumps(MATRIX_WITH_STATUS))
        m["categories"]["directives"][0]["coraza"] = False
        (self.root / "compat/matrix.json").write_text(json.dumps(m))
        errors = validate.check_matrix_status(self.root)
        self.assertTrue(any("SecRuleEngine" in e and "coraza" in e for e in errors))

    def test_spec_feature_without_matrix_row_and_row_without_feature(self):
        (self.root / "spec/04-directives.md").write_text(SPEC_DIRECTIVES + "\n### SecFoo\n\n**Status:** Core\n")
        errors = validate.check_matrix_status(self.root)
        self.assertTrue(any("secfoo" in e.lower() and "matrix" in e for e in errors))
        m = json.loads(json.dumps(MATRIX_WITH_STATUS))
        m["categories"]["directives"].append({"name": "SecBar", "v2": True, "v3": True, "coraza": True, "status": "Core"})
        (self.root / "compat/matrix.json").write_text(json.dumps(m))
        (self.root / "spec/04-directives.md").write_text(SPEC_DIRECTIVES)
        errors = validate.check_matrix_status(self.root)
        self.assertTrue(any("SecBar" in e and "spec" in e for e in errors))

    def test_rows_without_status_are_ignored(self):
        m = json.loads(json.dumps(MATRIX_WITH_STATUS))
        m["categories"]["operators"] = [{"name": "rx", "v2": True, "v3": True, "coraza": True}]
        (self.root / "compat/matrix.json").write_text(json.dumps(m))
        self.assertEqual(validate.check_matrix_status(self.root), [])
