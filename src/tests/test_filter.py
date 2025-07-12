from unittest.mock import MagicMock, patch
import unittest
from src.core.rule_engine import RuleEngine
from src.core.packet_filter import PacketFilter

class TestPacketFilter(unittest.TestCase):
    def setUp(self):
        # Mock RuleEngine and PacketFilter
        self.mock_rule_engine = MagicMock(spec=RuleEngine)
        self.filter = PacketFilter(self.mock_rule_engine)
        self.sample_packet = {"summary": lambda: "Test Packet", "ip": {"src": "192.168.1.100"}}

    # Test packet allow
@patch("src.core.rule_engine.RuleEngine.check_packet")
def test_filter_packet_allow(self, mock_check_packet):
    mock_check_packet.return_value = "ALLOW"  # Return 'ALLOW' action
    result = self.filter.filter_packet(self.sample_packet)
    self.assertEqual(result, "ALLOW")  # Expect 'ALLOW'

# Test packet block
@patch("src.core.rule_engine.RuleEngine.check_packet")
def test_filter_packet_block(self, mock_check_packet):
    mock_check_packet.return_value = "BLOCK"  # Return 'BLOCK' action
    result = self.filter.filter_packet(self.sample_packet)
    self.assertEqual(result, "BLOCK")  # Expect 'BLOCK'

# Test rule removal
def test_remove_rule(self):
    self.engine.add_rule(self.sample_rule)
    self.engine.remove_rule(self.sample_rule)
    self.assertNotIn(self.sample_rule, self.engine.rules)  # Expect rule removed

if __name__ == "__main__":
    unittest.main()
