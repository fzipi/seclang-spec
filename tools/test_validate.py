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
