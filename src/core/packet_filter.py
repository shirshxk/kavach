from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP
from colorama import Fore, Style, init

init(autoreset=True)

class PacketFilter:
    def __init__(self, rule_engine, mode="view"):
        self.rule_engine = rule_engine
        self.mode = mode
        self.printed_header = False  # flag to only print once

    def filter_packet(self, packet):
        from scapy.all import IP, TCP, UDP, ARP
        from datetime import datetime
        from colorama import Fore, Style

        # silently ignore packets we don't know how to handle
        if not (IP in packet or ARP in packet):
            return True

        # Print table header once
        if not self.printed_header:
            print(
                f"{Style.BRIGHT + Fore.CYAN}Time      "
                f"{Fore.MAGENTA}Proto   "
                f"{Fore.WHITE}Source{' ' * 17}"
                f"{Fore.WHITE}Destination{' ' * 12}"
                f"{Fore.GREEN}Action{Style.RESET_ALL}"
            )
            print(Fore.WHITE + "-" * 75 + Style.RESET_ALL)
            self.printed_header = True

        # Default values
        timestamp = datetime.now().strftime('%H:%M:%S')
        proto = "UNKNOWN"
        src = dst = "N/A"

        # Extract protocol and addresses
        if IP in packet:
            proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "IP"
            sport = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else ""
            dport = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else ""
            src = f"{packet[IP].src}:{sport}"
            dst = f"{packet[IP].dst}:{dport}"
        elif ARP in packet:
            proto = "ARP"
            src = packet[ARP].psrc
            dst = packet[ARP].pdst

        # Colors
        proto_color = {
            "TCP": Fore.CYAN,
            "UDP": Fore.YELLOW,
            "IP": Fore.LIGHTBLUE_EX,
            "ARP": Fore.MAGENTA,
            "UNKNOWN": Fore.WHITE
        }.get(proto, Fore.WHITE)

        time_col = Fore.LIGHTBLUE_EX
        src_col = Fore.LIGHTWHITE_EX
        dst_col = Fore.LIGHTWHITE_EX

        # Determine action
        is_allowed = self.rule_engine.check_packet(packet) == "ALLOW"
        action = "ALLOW" if is_allowed else "BLOCK"
        action_color = Fore.GREEN if is_allowed else Fore.RED

        # Only show:
        # → ALL traffic in 'view' mode (but BLOCK only if firewall is active)
        # → ONLY blocked traffic in 'block' mode
        if self.mode == "view":
            # Check if iptables is actually running
            ipt_running = self._check_nfqueue()
            real_action = action if ipt_running else "ALLOW"
            real_color = action_color if ipt_running else Fore.GREEN

            print(
                f"{time_col}{timestamp:<9} "
                f"{proto_color}{proto:<7} "
                f"{src_col}{src:<22} "
                f"{dst_col}{dst:<22} "
                f"{real_color}{real_action}"
            )

        elif self.mode == "block" and not is_allowed:
            print(
                f"{time_col}{timestamp:<9} "
                f"{proto_color}{proto:<7} "
                f"{src_col}{src:<22} "
                f"{dst_col}{dst:<22} "
                f"{action_color}{action}"
            )

        return is_allowed

    # Add this helper method inside the PacketFilter class:
    def _check_nfqueue(self):
        import subprocess
        try:
            output = subprocess.check_output(["sudo", "iptables", "-L", "INPUT", "-n"]).decode()
            return "NFQUEUE" in output
        except:
            return False
