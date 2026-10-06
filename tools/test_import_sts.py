import json
import tempfile
import unittest
from pathlib import Path

from tools import import_sts


class ConvertTests(unittest.TestCase):
    def test_unescapes_literal_backslash_sequences(self):
        case = {"type": "tfn", "name": "base64Decode", "input": "VGVzdABDYXNl", "output": "Test\\u0000Case", "ret": 1}
        out = import_sts.convert_case(case, "07-transformations.md#base64decode")
        self.assertEqual(out["output"], "Test\u0000Case")
        self.assertEqual(out["spec"], "07-transformations.md#base64decode")

    def test_plain_strings_unchanged_and_param_unescaped(self):
        case = {"type": "op", "name": "rx", "param": "a\\\\d", "input": "a1", "ret": 1}
        out = import_sts.convert_case(case, "06-operators.md#rx")
        self.assertEqual(out["param"], "a\\d")
        self.assertEqual(out["input"], "a1")

    def test_resource_cases_dropped_and_re_groups_kept(self):
        self.assertIsNone(import_sts.convert_case({"type": "op", "name": "pmFromFile", "param": "x", "input": "y", "ret": 1, "resource": "f"}, "a#b"))
        out = import_sts.convert_case({"type": "op", "name": "rx", "param": "(a)", "input": "a", "ret": 1, "re_groups": ["a", "a"]}, "a#b")
        self.assertEqual(out["re_groups"], ["a", "a"])

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
