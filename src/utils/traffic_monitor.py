# src/utils/traffic_monitor.py
import time
from scapy.all import sniff
from .helpers import Helper

class TrafficMonitor:
    def __init__(self, interface):
        self.interface = interface
        self.packet_count = 0
        self.total_data = 0

    def packet_handler(self, packet):
        """Handles each captured packet and updates stats."""
        self.packet_count += 1
        self.total_data += len(packet)

    def start_monitoring(self, duration=10):
        """Starts monitoring traffic for a specific duration."""
        sniff(iface=self.interface, prn=self.packet_handler, timeout=duration)

# Function to integrate Traffic Monitor with the main program
def get_traffic_statistics(interface=None, duration=10):
    if interface is None:
        interface = Helper.detect_interface()
    monitor = TrafficMonitor(interface)
    monitor.start_monitoring(duration)
    return {
        "interface": interface,
        "packets": monitor.packet_count,
        "data": monitor.total_data
    }