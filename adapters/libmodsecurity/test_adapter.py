"""The adapter's own tests: parsers and loaders always; engine smoke tests when MODSECURITY_LIB is set."""
import os
import tempfile
import unittest
from pathlib import Path

import data
import engine_tier
import gaps
import mscapi
from data import Interruption, Output

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


L = b"[1.2] [/?a=1] [4] "


def dbg(*texts):
    return b"\n".join(L + t for t in texts) + b"\n"


class DebugLogTests(unittest.TestCase):
    def test_match_and_non_match(self):
        t, d = engine_tier.parse_debug_log(dbg(
            b'(Rule: 1) Executing operator "StrEq" with param "1" against ARGS:a.', b"Rule returned 1.",
            b'(Rule: 2) Executing operator "StrEq" with param "9" against ARGS:a.', b"Rule returned 0."))
        self.assertEqual(t, {1})
        self.assertIsNone(d)

    def test_unconditional_rule(self):
        t, _ = engine_tier.parse_debug_log(dbg(b"(Rule: 3) Executing unconditional rule..."))
        self.assertEqual(t, {3})

    def test_chain_member_fails(self):
        t, _ = engine_tier.parse_debug_log(dbg(
            b'(Rule: 4) Executing operator "StrEq" with param "1" against ARGS:a.', b"Rule returned 1.",
            b"Executing chained rule.",
            b'(Rule: 0) Executing operator "StrEq" with param "2" against ARGS:b.', b"Rule returned 0.",
            b'(Rule: 5) Executing operator "StrEq" with param "1" against ARGS:a.', b"Rule returned 1."))
        self.assertEqual(t, {5})

    def test_chain_matches(self):
        t, _ = engine_tier.parse_debug_log(dbg(
            b'(Rule: 4) Executing operator "StrEq" with param "1" against ARGS:a.', b"Rule returned 1.",
            b"Executing chained rule.",
            b'(Rule: 0) Executing operator "StrEq" with param "2" against ARGS:b.', b"Rule returned 1."))
        self.assertEqual(t, {4})

    def test_deny_attribution(self):
        t, d = engine_tier.parse_debug_log(dbg(
            b'(Rule: 20) Executing operator "StrEq" with param "1" against ARGS:a.', b"Rule returned 1.",
            b"Running (disruptive)     action: deny."))
        self.assertEqual((t, d), ({20}, (20, "deny")))

    def test_redirect_typo(self):
        _, d = engine_tier.parse_debug_log(dbg(
            b'(Rule: 30) Executing operator "StrEq" with param "1" against ARGS:a.', b"Rule returned 1.",
            b"Running (disruptive)     action: redirert."))
        self.assertEqual(d, (30, "redirect"))

    def test_pass_is_not_disruptive(self):
        _, d = engine_tier.parse_debug_log(dbg(
            b'(Rule: 1) Executing operator "StrEq" with param "1" against ARGS:a.', b"Rule returned 1.",
            b"Running (disruptive)     action: pass."))
        self.assertIsNone(d)

    def test_uri_with_brackets(self):
        line = b"[1.2] [/x] [9] y] [4] z\n" + b"[1.2] [/?a=1] [4] (Rule: 8) Executing unconditional rule...\n"
        t, _ = engine_tier.parse_debug_log(line)
        self.assertEqual(t, {8})


class CheckStageTests(unittest.TestCase):
    def test_messages(self):
        o = engine_tier.Observed({1}, Interruption(1, "deny", 403), "ModSecurity: Warning x")
        self.assertEqual(engine_tier.check_stage(o, Output(triggered_rules=[1], interruption=Interruption(1, "deny", 403), log_contains="Warning")), [])
        msgs = engine_tier.check_stage(o, Output(triggered_rules=[2], non_triggered_rules=[1], no_interruption=True, no_log_contains="Warning"))
        self.assertEqual(len(msgs), 4)
        msgs = engine_tier.check_stage(engine_tier.Observed(set(), None, ""), Output(interruption=Interruption(1, "deny", 0)))
        self.assertEqual(len(msgs), 1)


@needs_engine
class EngineSmokeTests(unittest.TestCase):
    def test_stage_round_trip(self):
        ms = mscapi.ModSecurity()
        profile = data.Profile("x", [], {"inc.conf": 'SecRule ARGS:a "@streq 1" "id:2,phase:1,pass,nolog"\n'},
                               'SecRuleEngine On\nInclude inc.conf\nSecRule ARGS:a "@streq 1" "id:1,phase:2,deny,status:418,log,msg:\'hit\'"\n'
                               'SecRule ARGS:a "@streq 9" "id:3,phase:1,pass"\n', [])
        with tempfile.TemporaryDirectory() as d:
            rules, debug = engine_tier.build_rules(ms, profile, Path(d))
            st = data.Stage(data.Input(uri="/?a=1"), None, Output())
            o = engine_tier.run_stage(ms, rules, debug, st)
            o2 = engine_tier.run_stage(ms, rules, debug, data.Stage(data.Input(uri="/?a=9"), None, Output()))
            rules.close()
        self.assertEqual(o.triggered, {1, 2})
        self.assertEqual(o.interruption, Interruption(1, "deny", 418))
        self.assertIn("hit", o.log)
        self.assertEqual(o2.triggered, {3})
        self.assertIsNone(o2.interruption)


if __name__ == "__main__":
    unittest.main()
