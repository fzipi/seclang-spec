import unittest

import differential
from engine_tier import Observed
from data import Interruption


class OutcomeTests(unittest.TestCase):
    def test_outcome_partitions_ids(self):
        o = differential.outcome(Observed({2, 9}, None, ""), [1, 2, 3])
        self.assertEqual(o, {"triggered_rules": [2], "non_triggered_rules": [1, 3], "no_interruption": True})

    def test_outcome_interruption(self):
        o = differential.outcome(Observed({1}, Interruption(1, "deny", 403), ""), [1])
        self.assertEqual(o["interruption"], {"rule_id": 1, "action": "deny"})
        self.assertNotIn("no_interruption", o)

    def test_disagreement(self):
        a = {"triggered_rules": [1, 2], "no_interruption": True}
        self.assertEqual(differential.disagreement(a, {"triggered_rules": [2, 1], "no_interruption": True}), "")
        self.assertTrue(differential.disagreement(a, {"triggered_rules": [1], "no_interruption": True}).startswith("triggered"))
        self.assertTrue(differential.disagreement(a, {"triggered_rules": [1, 2], "interruption": {"rule_id": 1, "action": "deny"}}).startswith("interruption"))
        b = {"triggered_rules": [1, 2], "interruption": {"rule_id": 1, "action": "deny", "status": 403}}
        self.assertEqual(differential.disagreement(b, {"triggered_rules": [1, 2], "interruption": {"rule_id": 1, "action": "deny"}}), "")
