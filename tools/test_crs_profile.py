import tempfile
import unittest
from pathlib import Path

import yaml

from tools import crs_profile

CONF = """# comment
SecRule ARGS "@rx a" \\
    "id:1,phase:1,pass,chain"
    SecRule ARGS "@detectXSS"

SecRule ARGS|XML:/* "@rx b" "id:2,phase:2,pass"
SecRuleUpdateTargetById 1 "!ARGS:x"
SecRuleUpdateTargetById 2 "!ARGS:y"
SecRule TX:a "@eq 1" "id:3,phase:1,pass,chain"
    SecRule TX:b "@eq 1"
SecRule ARGS "@rx c" "id:4,phase:1,pass"
"""


class AssembleTests(unittest.TestCase):
    def test_blocks_and_chains(self):
        bs = crs_profile.blocks(CONF)
        self.assertEqual(len(bs), 8)
        self.assertEqual([len(g) for g in crs_profile.chains(bs)], [2, 1, 1, 1, 2, 1])

    def test_assemble(self):
        with tempfile.TemporaryDirectory() as tmp:
            crs = Path(tmp)
            (crs / "rules").mkdir()
            (crs / "crs-setup.conf.example").write_text("SecAction \"id:900,phase:1,pass,nolog,setvar:tx.v=1\"\n")
            (crs / "rules" / "REQUEST-1.conf").write_text(CONF)
            (crs / "rules" / "w.data").write_text("x\n")
            text, dropped = crs_profile.assemble(crs)
        self.assertEqual(dropped, 2)  # the libinjection chain, starter and member
        p = yaml.safe_load(text)
        rules = p["rules"]
        self.assertIn("SecRuleEngine On", rules)
        self.assertNotIn("detectXSS", rules)
        self.assertNotIn("SecRuleUpdateTargetById 1 ", rules)  # names a dropped id
        self.assertIn("SecRuleUpdateTargetById 2 ", rules)
        self.assertIn('SecRule ARGS "@rx b"', rules)  # XML:/* stripped from the list
        self.assertIn('    SecRule TX:b "@eq 1"\n\nSecRule ARGS "@rx c"', rules)  # blank line after the member
        self.assertEqual(p["files"], {"w.data": "x\n"})
        self.assertEqual(p["tests"], [])
