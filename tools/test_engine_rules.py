import json
import tempfile
import unittest
from pathlib import Path

from tools import engine_rules

PROFILE = """meta:
  name: x
  description: y
rules: |
  SecRuleEngine On
  Include a.conf
files:
  a.conf: |
    SecRule ARGS "@streq 1" "id:1,phase:1,pass"
tests:
  - test_title: t
    stages:
      - stage:
          input: {}
          output:
            expect_error: true
"""


class ExtractTests(unittest.TestCase):
    def test_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tests" / "engine" / "d").mkdir(parents=True)
            (root / "tests" / "engine" / "d" / "p.yaml").write_text(PROFILE)
            out = engine_rules.extract(root)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["path"], "tests/engine/d/p.yaml")
        self.assertEqual(out[0]["rules"], "SecRuleEngine On\nInclude a.conf\n")
        self.assertEqual(out[0]["files"], {"a.conf": 'SecRule ARGS "@streq 1" "id:1,phase:1,pass"\n'})
        self.assertTrue(out[0]["expect_error"])
        self.assertIs(out[0]["tests"][0]["stages"][0]["stage"]["output"]["expect_error"], True)
        json.dumps(out)
