import json
import tempfile
import unittest
from pathlib import Path

from tools import import_sts


class WireModelTests(unittest.TestCase):
    """to_wire_bytes models libmodsecurity's test/unit/unit_test.cc json2bin()."""

    def test_hex_and_u_escapes_become_single_bytes(self):
        self.assertEqual(import_sts.to_wire_bytes("a\\x41\\u0042"), "aAB")
        self.assertEqual(import_sts.to_wire_bytes("\\u00e9"), "é")
        self.assertEqual(import_sts.to_wire_bytes("\\u1100"), "\u0000")  # low 8 bits only

    def test_runner_regex_matches_any_two_alphanumerics(self):
        # json2bin's regex is \\x([a-z0-9A-Z]{2}) and sscanf("%3x") parses the leading hex digits:
        # \xag -> byte 0x0a, \xga -> no hex digits -> byte 0x00 in this model.
        self.assertEqual(import_sts.to_wire_bytes("\\xag"), "\n")
        self.assertEqual(import_sts.to_wire_bytes("\\xga"), "\u0000")

    def test_other_escapes_are_literal(self):
        # \0 \b \t \n \r have been commented out in the runner since 2016: a Windows path stays a path.
        self.assertEqual(import_sts.to_wire_bytes("\\foo\\bar\\baz"), "\\foo\\bar\\baz")
        self.assertEqual(import_sts.to_wire_bytes("a\\nb"), "a\\nb")

    def test_non_ascii_characters_become_utf8_bytes(self):
        # The corpus is mojibake: a UTF-8 JSON parser hands the engine the UTF-8 bytes of each code point.
        self.assertEqual(import_sts.to_wire_bytes("Ã§"), "Ã\u0083Â§")
        self.assertEqual(import_sts.to_wire_bytes("진"), "ì§\u0084")


class ConvertTests(unittest.TestCase):
    def test_model_applies_to_input_and_output_only(self):
        case = {"type": "op", "name": "rx", "param": "a\\x41", "input": "\\x41", "output": "\\x42", "ret": 1}
        out = import_sts.convert_case(case, "06-operators.md#rx")
        self.assertEqual(out["param"], "a\\x41")  # params are never decoded by the runner
        self.assertEqual(out["input"], "A")
        self.assertEqual(out["output"], "B")
        self.assertEqual(out["spec"], "06-operators.md#rx")

    def test_param_wide_characters_become_bytes(self):
        out = import_sts.convert_case({"type": "op", "name": "rx", "param": "€", "input": "x", "ret": 0}, "a#b")
        self.assertEqual(out["param"], "â\u0082¬")

    def test_transformation_ret_means_output_differs_from_input(self):
        # tests/README.md: ret is 1 when the transformation changed its input. The corpus
        # carries the engine's return code instead, which v2 hardcodes to 1 for some.
        unchanged = import_sts.convert_case({"type": "tfn", "name": "hexEncode", "input": "", "output": "", "ret": 1}, "a#b")
        self.assertEqual(unchanged["ret"], 0)
        changed = import_sts.convert_case({"type": "tfn", "name": "lowercase", "input": "A", "output": "a", "ret": 0}, "a#b")
        self.assertEqual(changed["ret"], 1)
        op = import_sts.convert_case({"type": "op", "name": "rx", "param": "a", "input": "a", "ret": 1}, "a#b")
        self.assertEqual(op["ret"], 1)

    def test_resource_cases_dropped_and_re_groups_kept(self):
        self.assertIsNone(import_sts.convert_case({"type": "op", "name": "pmFromFile", "param": "x", "input": "y", "ret": 1, "resource": "f"}, "a#b"))
        out = import_sts.convert_case({"type": "op", "name": "rx", "param": "(a)", "input": "a", "ret": 1, "re_groups": ["a", "a"]}, "a#b")
        self.assertEqual(out["re_groups"], ["a", "a"])

    def test_excluded_cases_are_dropped(self):
        self.assertIsNone(import_sts.convert_case({"type": "op", "name": "validateByteRange", "param": "", "input": "x", "ret": 1}, "a#b"))
        self.assertIsNone(import_sts.convert_case({"type": "op", "name": "validateByteRange", "param": "xxx", "input": "x", "ret": 1}, "a#b"))
        self.assertIsNone(import_sts.convert_case({"type": "op", "name": "ipMatch", "param": "10.0.0.0/100", "input": "10.10.10.11", "ret": 0}, "a#b"))
        self.assertIsNone(import_sts.convert_case({"type": "op", "name": "unconditionalMatch", "param": "TestCase", "input": "", "ret": 1}, "a#b"))

    def test_anchors_from_spec_skips_deprecated_and_engine_specific(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "spec").mkdir()
            (root / "spec" / "06-operators.md").write_text(
                "# Ops\n\n### rx\n\n**Status:** Core\n\n### noMatch\n\n**Status:** Extended\n\n### gsbLookup\n\n**Status:** Deprecated\n\n### rxGlobal\n\n**Status:** Engine-specific\n")
            self.assertEqual(set(import_sts.anchors_from_spec(root)), {"rx", "nomatch"})

    def test_case_name_is_the_file_stem(self):
        # The corpus names cmdLine.json cases "cmd_line"; the engines know the transformation as cmdLine.
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"; dest = Path(tmp) / "dest"
            (src / "operators").mkdir(parents=True); (src / "transformations").mkdir()
            (src / "transformations" / "cmdLine.json").write_text(json.dumps([{"type": "tfn", "name": "cmd_line", "input": "A", "output": "a", "ret": 1}]))
            import_sts.main(src, dest, {"cmdline": "07-transformations.md#cmdline"})
            self.assertEqual(json.loads((dest / "transformations" / "cmdLine.json").read_text())[0]["name"], "cmdLine")

    def test_hand_maintained_files_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"; dest = Path(tmp) / "dest"
            (src / "operators").mkdir(parents=True); (src / "transformations").mkdir()
            (src / "transformations" / "base64Decode.json").write_text(json.dumps([{"type": "tfn", "name": "base64Decode", "input": "", "output": "", "ret": 0}]))
            counts = import_sts.main(src, dest, {"base64decode": "07-transformations.md#base64decode"})
            self.assertEqual(counts, {})
            self.assertFalse((dest / "transformations" / "base64Decode.json").exists())

    def test_main_writes_only_anchored_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"; dest = Path(tmp) / "dest"
            (src / "operators").mkdir(parents=True); (src / "transformations").mkdir()
            (src / "operators" / "rx.json").write_text(json.dumps([{"type": "op", "name": "rx", "param": "a", "input": "a", "ret": 1}]))
            (src / "operators" / "gsbLookup.json").write_text(json.dumps([{"type": "op", "name": "gsbLookup", "param": "a", "input": "a", "ret": 0}]))
            (src / "transformations" / "lowercase.json").write_text(json.dumps([{"type": "tfn", "name": "lowercase", "input": "A", "output": "a", "ret": 1}]))
            counts = import_sts.main(src, dest, {"rx": "06-operators.md#rx", "lowercase": "07-transformations.md#lowercase"})
            self.assertEqual(counts, {"rx": 1, "lowercase": 1})
            self.assertTrue((dest / "operators" / "rx.json").is_file())
            self.assertFalse((dest / "operators" / "gsbLookup.json").exists())
            self.assertEqual(json.loads((dest / "transformations" / "lowercase.json").read_text())[0]["spec"], "07-transformations.md#lowercase")


if __name__ == "__main__":
    unittest.main()
