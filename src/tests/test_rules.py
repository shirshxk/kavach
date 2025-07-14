import unittest
from scapy.all import IP
from src.core.rule_engine import RuleEngine
import os

class TestRuleEngine(unittest.TestCase):
    def setUp(self):
        self.engine = RuleEngine(rules_file="src/core/configs/test_rules.json")
        self.sample_rule = {"src": "192.168.1.100", "action": "BLOCK"}
        self.engine.rules = []  # Start with clean state

    def tearDown(self):
        if os.path.exists("src/core/configs/test_rules.json"):
            os.remove("src/core/configs/test_rules.json")

    def test_add_rule(self):
        self.engine.add_rule(self.sample_rule)
        self.assertIn(self.sample_rule, self.engine.rules)

    def test_remove_existing_rule(self):
        self.engine.add_rule(self.sample_rule)
        self.engine.remove_rule(self.sample_rule)
        self.assertNotIn(self.sample_rule, self.engine.rules)

    def test_check_packet_allow_by_default(self):
        pkt = IP(src="10.0.0.1", dst="192.168.1.1")
        result = self.engine.check_packet(pkt)
        self.assertEqual(result, "ALLOW")

    def test_check_packet_block_when_matched(self):
        self.engine.add_rule(self.sample_rule)
        pkt = IP(src="192.168.1.100", dst="192.168.1.1")
        result = self.engine.check_packet(pkt)
        self.assertEqual(result, "BLOCK")

    def test_check_packet_rate_limiting(self):
        self.engine.add_rule(self.sample_rule)
        for _ in range(25):  # trigger rate limiting
            self.engine.check_packet(IP(src="192.168.1.100", dst="192.168.1.1"))
        result = self.engine.check_packet(IP(src="192.168.1.100", dst="192.168.1.1"))
        self.assertEqual(result, "BLOCK")  # due to rate limiting

if __name__ == "__main__":
    unittest.main()
