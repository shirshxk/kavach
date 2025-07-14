import unittest
from unittest.mock import MagicMock
from scapy.all import IP, TCP
from src.core.packet_filter import PacketFilter
from src.core.rule_engine import RuleEngine

class TestPacketFilter(unittest.TestCase):
    def setUp(self):
        self.rule_engine = RuleEngine()
        self.rule_engine.rules = []  # Clean start
        self.packet_filter = PacketFilter(self.rule_engine, mode="view")

    def test_allow_packet(self):
        packet = IP(src="10.0.0.1", dst="192.168.1.1") / TCP()
        self.rule_engine.check_packet = MagicMock(return_value="ALLOW")
        result = self.packet_filter.filter_packet(packet)
        self.assertTrue(result)

    def test_block_packet(self):
        packet = IP(src="192.168.1.100", dst="192.168.1.1") / TCP()
        self.rule_engine.check_packet = MagicMock(return_value="BLOCK")
        result = self.packet_filter.filter_packet(packet)
        self.assertFalse(result)

    def test_rate_limit_warning_output(self):
        packet = IP(src="192.168.1.100", dst="192.168.1.1") / TCP()
        self.rule_engine.check_packet = MagicMock(return_value="BLOCK_RATE_LIMIT")
        result = self.packet_filter.filter_packet(packet)
        self.assertFalse(result)

if __name__ == "__main__":
    unittest.main()
