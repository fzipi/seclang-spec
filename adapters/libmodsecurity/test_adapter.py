"""The adapter's own tests: parsers and loaders always; engine smoke tests when MODSECURITY_LIB is set."""
import os
import tempfile
import unittest
from pathlib import Path

import data
import gaps
import mscapi

needs_engine = unittest.skipUnless(os.environ.get(mscapi.ENV), f"{mscapi.ENV} not set")


class DataTests(unittest.TestCase):
    def test_repo_root_has_tests(self):
        self.assertTrue((data.repo_root() / "tests" / "engine").is_dir())

    def test_latin1_round_trip(self):
        self.assertEqual(data.latin1("aÿ\u0000"), b"a\xff\x00")
        self.assertEqual(data.byte_string(b"a\xff\x00"), "aÿ\u0000")

    def test_load_profiles_defaults(self):
        profiles = data.load_profiles(data.repo_root())
        self.assertGreater(len(profiles), 50)
        p = next(x for x in profiles if x.path == "tests/engine/directives/logging-directives-load.yaml")
        st = p.tests[0].stages[0]
        self.assertEqual(st.input.method, "GET")
        self.assertEqual(st.input.uri, "/?a=1")
        self.assertEqual(st.output.interruption.rule_id, 5200)
        self.assertEqual(st.output.interruption.action, "deny")
        self.assertIsNone(st.response)

    def test_load_unit_cases_param_presence(self):
        files = data.load_unit_cases(data.repo_root())
        rx = files["tests/unit/operators/rx.json"]
        self.assertEqual(rx[0].param, "test")
        self.assertEqual(rx[1].param, "")
        self.assertIsNone(files["tests/unit/operators/detectSQLi.json"][0].param)
        self.assertEqual(rx[0].re_groups, [])


class GapsTests(unittest.TestCase):
    TABLE = """# x
| Test | Engine | Behaviour today | Decided in |
|---|---|---|---|
| `tests/engine/a.yaml` | Coraza | one | ADR-1 |
| `tests/engine/b.yaml`, `tests/engine/c.yaml` | libmodsecurity v3, Coraza | two | ADR-2 |
| `tests/unit/d.json` | ModSecurity v2 | three | ADR-3 |
"""

    def test_rows_for_engine(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "k.md"
            p.write_text(self.TABLE)
            self.assertEqual(gaps.load_gaps(p, "libmodsecurity v3"),
                             {"tests/engine/b.yaml": "two", "tests/engine/c.yaml": "two"})
            self.assertEqual(set(gaps.load_gaps(p, "coraza")),
                             {"tests/engine/a.yaml", "tests/engine/b.yaml", "tests/engine/c.yaml"})


@needs_engine
class BindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ms = mscapi.ModSecurity()

    def test_version(self):
        self.assertIn("ModSecurity v3", self.ms.version())

    def test_load_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "r.conf"
            p.write_text("SecRule ARGS\n")
            with self.assertRaises(mscapi.LoadError):
                self.ms.rules_from_file(str(p))

    def test_deny_intervention_and_log(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "r.conf"
            p.write_text('SecRuleEngine On\nSecRule ARGS:a "@streq 1" "id:7,phase:1,deny,status:418,log,msg:\'hit\'"\n')
            rules = self.ms.rules_from_file(str(p))
            tx = self.ms.transaction(rules)
            tx.connection("127.0.0.1", 12345, "127.0.0.1", 80)
            tx.uri("/?a=1", "GET", "1.1")
            tx.request_header("Host", "localhost")
            tx.process_request_headers()
            it = tx.intervention()
            tx.process_logging()
            tx.close()
            rules.close()
            self.assertEqual(it["status"], 418)
            self.assertIn(b'[id "7"]', it["log"])
            self.assertIsNone(it["url"])


if __name__ == "__main__":
    unittest.main()
