from scapy.all import sniff

class PacketSniffer:
    def __init__(self, interface, packet_filter, logger):
        self.interface = interface
        self.packet_filter = packet_filter
        self.logger = logger

    def packet_handler(self, packet):
        self.packet_filter.filter_packet(packet)

    def start(self):
        """
        Start sniffing on the specified network interface.
        """
        print(f"Starting packet sniffer on {self.interface}...")
        sniff(iface=self.interface, prn=self.packet_handler, store=False)
