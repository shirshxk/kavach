from scapy.all import sniff

class PacketSniffer:
    def __init__(self, interface, packet_filter, logger):
        self.interface = interface
        self.packet_filter = packet_filter
        self.logger = logger
        self.stop_sniffing = False 

    def packet_handler(self, packet):
        self.packet_filter.filter_packet(packet)

    def start(self):
        def _should_stop(_):
            return self.stop_sniffing

        print(f"Starting packet sniffer on {self.interface}...")
        sniff(iface=self.interface, prn=self.packet_handler, store=False, stop_filter=_should_stop)
