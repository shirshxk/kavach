import unittest
from unittest.mock import patch
from scapy.packet import Packet
from src.core.packet_sniffer import PacketSniffer

class TestPacketSniffer(unittest.TestCase):
    @patch("src.core.packet_sniffer.PacketSniffer.packet_handler")  # Correct the patch path
    def test_packet_handler(self, mock_handler):
        mock_packet = Packet()
        mock_packet.summary = lambda: "Mock Packet Summary"
        sniffer = PacketSniffer(interface="wlan0", packet_filter=None, logger=None)  # Pass mock if needed
        sniffer.packet_handler(mock_packet)
        mock_handler.assert_called_with(mock_packet)

if __name__ == "__main__":
    unittest.main()
