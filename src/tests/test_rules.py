import unittest
from src.core.rule_engine import RuleEngine

class TestRuleEngine(unittest.TestCase):
    def setUp(self):
        """
        Initialize a fresh instance of the RuleEngine for each test case,
        ensuring no residual state from previous tests.
        """
        self.engine = RuleEngine()
        self.sample_rule = {"src": "192.168.1.100", "action": "BLOCK"}

    def tearDown(self):
        """
        Clean up after tests if required (e.g., clearing saved rules).
        """
        self.engine.rules = []
        self.engine.save_rules()

    def test_add_rule(self):
        """
        Test adding a single rule and ensure it's included in the rules.
        """
        self.engine.add_rule(self.sample_rule)
        self.assertIn(self.sample_rule, self.engine.rules)

    
    def test_remove_rule(self):
        """
        Test removing a rule and ensure it's no longer present.
        """
        self.engine.add_rule(self.sample_rule)
        self.engine.remove_rule(self.sample_rule)
        self.assertNotIn(self.sample_rule, self.engine.rules)

    def test_remove_nonexistent_rule(self):
        """
        Test that removing a non-existent rule does not cause errors
        and leaves the rules unchanged.
        """
        initial_count = len(self.engine.rules)
        self.engine.remove_rule(self.sample_rule)
        self.assertEqual(len(self.engine.rules), initial_count)

    def test_check_packet_allow(self):
        """
        Test that a packet with no matching rule is allowed.
        """
        packet = {"src": "10.0.0.1"}  # Adjust to match expected packet structure
        result = self.engine.check_packet(packet)
        self.assertEqual(result, "ALLOW")  # Default action for unmatched packets

    def test_check_packet_block(self):
        """
        Test that a packet matching a 'BLOCK' rule is blocked.
        """
        # Arrange: Add the block rule to the RuleEngine
        block_rule = {"src": "192.168.1.100", "action": "BLOCK"}
        self.engine.add_rule(block_rule)

        # Act: Check a packet that matches the block rule
        test_packet = {"src": "192.168.1.100"}
        print(f"Testing with packet: {test_packet}")
        result = self.engine.check_packet(test_packet)
        print(f"Check packet result: {result}")

        # Assert: Verify that the result is 'BLOCK'
        self.assertEqual(result, "BLOCK", "The packet should be blocked based on the rule.")


    def test_empty_rules_allow(self):
        """
        Test that the engine defaults to allowing packets when no rules exist.
        """
        packet = {"src": "10.0.0.2"}  # Arbitrary packet data
        result = self.engine.check_packet(packet)
        self.assertEqual(result, "ALLOW")

if __name__ == "__main__":
    unittest.main()
