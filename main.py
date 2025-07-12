#!/usr/bin/env -S PYTHONWARNINGS=ignore python3
import argparse
import logging
import subprocess
import psutil
from src.core.packet_sniffer import PacketSniffer
from src.core.rule_engine import RuleEngine
from src.core.packet_filter import PacketFilter
from src.core.logger import Logger
from src.utils.traffic_monitor import get_traffic_statistics
from src.utils.helpers import Helper
from src.utils.ip_utils import IpUtils
from src.tests.test_firewall import run_all_tests
from colorama import Fore, Style
import argparse

class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        print(f"{Fore.RED}[❌] {message}{Style.RESET_ALL}\n")
        self.print_help()
        self.exit(2)

    def print_help(self):
        print(f"""
    {Fore.CYAN + Style.BRIGHT}Kavach Firewall CLI{Style.RESET_ALL}
    {Fore.WHITE}Usage:{Style.RESET_ALL}
    sudo ./main.py [option] [value]

    {Fore.GREEN}Available Commands:{Style.RESET_ALL}
    {Fore.YELLOW}-s{Style.RESET_ALL}                Start the firewall (block mode)
    {Fore.YELLOW}-v{Style.RESET_ALL}                View live traffic (no blocking)
    {Fore.YELLOW}-a IP,ACTION{Style.RESET_ALL}      Add rule (e.g. 192.168.1.10,BLOCK)
    {Fore.YELLOW}-r IP,ACTION{Style.RESET_ALL}      Remove IP rule (e.g. 8.8.8.8,BLOCK)
    {Fore.YELLOW}-r PORT{Style.RESET_ALL}           Remove port block rule (e.g. 22)
    {Fore.YELLOW}-p PORTS{Style.RESET_ALL}          Block ports (e.g. 22,80,443)
    {Fore.YELLOW}-l{Style.RESET_ALL}                List all rules
    {Fore.YELLOW}-m{Style.RESET_ALL}                Show traffic stats
    {Fore.YELLOW}-u{Style.RESET_ALL}                Run unit tests
    {Fore.YELLOW}-i{Style.RESET_ALL}                Show version info
    {Fore.YELLOW}-d{Style.RESET_ALL}                Delete all rules quickly


    {Fore.MAGENTA}Examples:{Style.RESET_ALL}
    ➤ Block Google DNS           : {Fore.CYAN}-a 8.8.8.8,BLOCK{Style.RESET_ALL}
    ➤ Unblock Port 22            : {Fore.CYAN}-r 22{Style.RESET_ALL}
    ➤ Start Firewall Blocking    : {Fore.CYAN}-s{Style.RESET_ALL}
    ➤ Live View Only             : {Fore.CYAN}-v{Style.RESET_ALL}
    """)

def ensure_iptables():
    try:
        output = subprocess.check_output(["sudo", "iptables", "-L", "INPUT", "-n"])
        if "NFQUEUE" not in output.decode():
            print("[*] Inserting iptables rule to forward packets to NFQUEUE...")
            subprocess.run(["sudo", "iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "1"])
        else:
            print("[✓] NFQUEUE rule already active.")
    except Exception as e:
        print(f"[!] Failed to check or insert iptables rule: {e}")

def cleanup_iptables():
    print("[*] Cleaning up iptables rule...")
    subprocess.call(["iptables", "-D", "INPUT", "-j", "NFQUEUE", "--queue-num", "1"])

def initialize_firewall():
    print("Initializing Firewall...")
    logger = Logger("logs/firewall.log")
    logger.log("Firewall initialized", level="INFO")

    rule_engine = RuleEngine()
    try:
        if not rule_engine.rules:
            rule_engine.load_rules()
            logger.log("Rules loaded successfully", level="INFO")
    except Exception as e:
        logger.log(f"Error loading rules: {e}", level="ERROR")

    packet_filter = PacketFilter(rule_engine)
    return packet_filter, logger

def add_ip_rule(ip, subnet):
    if IpUtils.is_valid_ip(ip):
        if IpUtils.is_ip_in_subnet(ip, subnet):
            print(f"IP {ip} is valid and belongs to the subnet {subnet}.")
        else:
            print(f"IP {ip} does not belong to the subnet {subnet}. Rule not added.")
    else:
        print(f"Invalid IP address: {ip}. Rule not added.")

def start_sniffer(packet_filter, logger):
    print("Starting Packet Sniffer...")
    sniffer = PacketSniffer(
        interface=Helper.detect_interface(),
        packet_filter=packet_filter,
        logger=logger
    )
    sniffer.start()

def main():
    parser = CustomArgumentParser(description="Kavach Firewall CLI")
    parser.add_argument("-i", "--version", action="store_true", help="Show version and exit")
    parser.add_argument("-s", "--start", action="store_true", help="Start full firewall with packet blocking via NetfilterQueue")
    parser.add_argument("-v", "--view-live", action="store_true", help="Live monitor firewall packets without blocking")
    parser.add_argument("-a", "--add-rule", type=str, help="Add a firewall rule (format: IP,ACTION)")
    parser.add_argument("-r", "--remove-rule", type=str, help="Remove a firewall rule (format: IP,ACTION)")
    parser.add_argument("-l", "--list-rules", action="store_true", help="List all firewall rules")
    parser.add_argument("-m", "--monitor-traffic", action="store_true", help="Monitor network traffic")
    parser.add_argument("-u", "--run-tests", action="store_true", help="Run unit tests for the firewall")
    parser.add_argument("-p", "--block-ports", type=str, help="Block traffic on specific ports (comma-separated, e.g., 22,80,443)")
    parser.add_argument("-d", "--reset-rules", action="store_true", help="Delete all current rules")

    args = parser.parse_args()
    if args.version:
        print(f"{Fore.CYAN}Kavach Firewall v1.0.0{Style.RESET_ALL}")
        return
    mode = "block" if args.start else "view" if args.view_live else None

    packet_filter, logger = initialize_firewall()
    if mode:
        packet_filter.mode = mode

    if args.start:
        try:
            from netfilterqueue import NetfilterQueue
            from scapy.all import IP
            ensure_iptables()
            print("[*] Enabling firewall hard-blocking via NetfilterQueue...")

            def process_packet(pkt):
                scapy_pkt = IP(pkt.get_payload())
                allowed = packet_filter.filter_packet(scapy_pkt)
                pkt.accept() if allowed else pkt.drop()

            nfqueue = NetfilterQueue()
            nfqueue.bind(1, process_packet)
            nfqueue.run()
        except ImportError:
            print("[ERROR] Required modules not installed. Run: pip install NetfilterQueue scapy")
        except KeyboardInterrupt:
            print("\n[!] Firewall hard-block mode stopped by user.")
            try: nfqueue.unbind()
            except: pass
            cleanup_iptables()

    elif args.add_rule:
        try:
            ip, action = Helper.parse_rule_arg(args.add_rule)
            if not IpUtils.is_valid_ip(ip):
                raise ValueError("Invalid IP address")
            rule = {"src": ip, "action": action}
            packet_filter.rule_engine.add_rule(rule)
            logger.log(f"Rule added: {rule}", level="INFO")
            print(f"✅ Rule added: {rule}")
        except Exception as e:
            print(f"[!] Failed to add rule: {e}")
            print("📝 Correct Format: -a 192.168.1.1,ALLOW")

    elif args.remove_rule:
        try:
            try:
                # Try treating input as port(s)
                ports = Helper.parse_ports(args.remove_rule)
                for port in ports:
                    rule = {"port": port, "action": "BLOCK"}
                    if rule in packet_filter.rule_engine.rules:
                        packet_filter.rule_engine.remove_rule(rule)
                        logger.log(f"Port block rule removed: {rule}", level="INFO")
                        print(f"✅ Removed block rule on port: {port}")
                    else:
                        print(f"[!] No such port block rule found for port: {port}")
            except ValueError:
                # Otherwise, treat as IP rule
                ip, action = Helper.parse_rule_arg(args.remove_rule)
                if not IpUtils.is_valid_ip(ip):
                    raise ValueError("Invalid IP address")
                rule = {"src": ip, "action": action}
                if rule in packet_filter.rule_engine.rules:
                    packet_filter.rule_engine.remove_rule(rule)
                    logger.log(f"Rule removed: {rule}", level="INFO")
                    print(f"✅ Rule removed: {rule}")
                else:
                    print(f"[!] No such IP rule found: {rule}")

        except Exception as e:
            print(f"[!] Failed to remove rule: {e}")
            print("📝 Correct Format:")
            print("    ➤ Remove IP rule   : -r 192.168.1.1,BLOCK")
            print("    ➤ Remove Port rule : -r 22 or -r 22,443,8080")

    elif args.monitor_traffic:
        stats = get_traffic_statistics(Helper.detect_interface())
        print("Network Traffic Statistics:")
        print(f"Total Packets Captured: {stats['packets']}")
        print(f"Total Data Transferred: {stats['data']} bytes")

    elif args.run_tests:
        print("Running unit tests...")
        run_all_tests()

    elif args.view_live:
        start_sniffer(packet_filter, logger)
    
    elif args.reset_rules:
        packet_filter.rule_engine.rules = []
        packet_filter.rule_engine.save_rules()
        print(f"{Fore.YELLOW}⚠️ All firewall rules cleared.{Style.RESET_ALL}")
        logger.log("All rules reset by user", level="WARNING")

    elif args.list_rules:
        rules = packet_filter.rule_engine.rules
        if not rules:
            print("🚫 No rules currently set.")
        else:
            print("\n📋 Current Firewall Rules:")
            for rule in rules:
                print(f"🔸 {rule}")

    elif args.block_ports:
        try:
            ports = Helper.parse_ports(args.block_ports)
            for port in ports:
                rule = {"port": port, "action": "BLOCK"}
                packet_filter.rule_engine.add_rule(rule)
                logger.log(f"Port block rule added: {rule}", level="INFO")
                print(f"✅ Blocked traffic on port: {port}")
        except Exception as e:
            print(f"[!] Failed to block port(s): {e}")
            print("📝 Correct Format: -p 22,80,443")

    else:
        print("\n[⚙️] No option provided. Use --help to see available commands.\n")
        parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except PermissionError:
        print("\n[❌] Permission denied! Try running with sudo/admin rights.\n")
    except KeyboardInterrupt:
        print("\n[🛑] Firewall stopped by user.")
    except Exception as e:
        print(f"\n[⚠️] Unexpected error: {e}\n")
