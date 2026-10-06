import json
import tempfile
import unittest
from pathlib import Path

from tools import matrix

SAMPLE = {
    "generated": "2026-10-06",
    "engines": {"v2": "ModSecurity v2", "v3": "libmodsecurity v3", "coraza": "Coraza"},
    "categories": {
        "operators": [
            {"name": "rx", "v2": True, "v3": True, "coraza": True},
            {"name": "restpath", "v2": False, "v3": False, "coraza": True},
        ]
    },
}


class RenderTests(unittest.TestCase):
    def test_header_and_rows(self):
        md = matrix.render(SAMPLE)
        self.assertIn("## operators (1 of 2 in all engines)", md)
        self.assertIn("| `restpath` | - | - | yes |", md)
        self.assertIn("| `rx` | yes | yes | yes |", md)
        self.assertIn("Do not edit by hand", md)

    def test_rows_sorted_case_insensitively(self):
        md = matrix.render(SAMPLE)
        self.assertLess(md.index("`restpath`"), md.index("`rx`"))

    def test_missing_engine_key_names_row(self):
        broken = json.loads(json.dumps(SAMPLE))
        del broken["categories"]["operators"][1]["coraza"]
        with self.assertRaises(ValueError) as cm:
            matrix.render(broken)
        self.assertIn("restpath", str(cm.exception))
        self.assertIn("coraza", str(cm.exception))

    def test_main_writes_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "compat").mkdir()
            (root / "compat" / "matrix.json").write_text(json.dumps(SAMPLE))
            matrix.main(root)
            self.assertEqual((root / "compat" / "matrix.md").read_text(), matrix.render(SAMPLE))


if __name__ == "__main__":
    unittest.main()


class StatusColumnTests(unittest.TestCase):
    def test_status_column_rendered_when_any_row_has_it(self):
        sample = json.loads(json.dumps(SAMPLE))
        sample["categories"]["operators"][0]["status"] = "Core"
        md = matrix.render(sample)
        self.assertIn("| Name | v2 | v3 | coraza | status |", md)
        self.assertIn("| `rx` | yes | yes | yes | Core |", md)
        self.assertIn("| `restpath` | - | - | yes | - |", md)

    def test_no_status_column_when_absent(self):
        self.assertNotIn("| status |", matrix.render(SAMPLE))
