import json
import tempfile
import unittest
from pathlib import Path

from tools import crs_rules


class ExtractTests(unittest.TestCase):
    def test_profiles_per_file_and_combined(self):
        with tempfile.TemporaryDirectory() as tmp:
            crs = Path(tmp)
            (crs / "rules").mkdir()
            (crs / "crs-setup.conf.example").write_text("SecRuleEngine On\n")
            (crs / "rules" / "REQUEST-901-X.conf").write_text('SecRule ARGS "@pmFromFile words.data" "id:901100,phase:1,pass"\n')
            (crs / "rules" / "RESPONSE-950-Y.conf").write_text('SecRule ARGS "@streq 1" "id:950100,phase:1,pass"\n')
            (crs / "rules" / "words.data").write_text("# comment\nforbidden\n")
            out = crs_rules.extract(crs)
        self.assertEqual([p["path"] for p in out], ["crs-setup.conf.example", "REQUEST-901-X.conf", "RESPONSE-950-Y.conf", "ALL"])
        self.assertEqual(out[1]["rules"], 'SecRule ARGS "@pmFromFile words.data" "id:901100,phase:1,pass"\n')
        self.assertEqual(out[1]["files"], {"words.data": "# comment\nforbidden\n"})
        self.assertEqual(out[3]["rules"], "SecRuleEngine On\n\n" + out[1]["rules"] + "\n" + out[2]["rules"])
        for p in out:
            self.assertFalse(p["expect_error"])
            self.assertEqual(p["tests"], [])
        json.dumps(out)
