import json  
from scapy.layers.inet import IP, TCP, UDP
import time
from collections import defaultdict, deque
import os

class RuleEngine:
    def __init__(self, rules_file=None):
        if rules_file is None:
            base_path = os.path.dirname(os.path.abspath(__file__))
            rules_file = os.path.join(base_path, "configs", "default_rules.json")
        self.rules_file = rules_file
        self.rules = []  # Initialize rules as a list
        self.load_rules()
        self.rate_limit_window = 5  # seconds
        self.rate_limit_threshold = 20  # packets
        self.packet_history = defaultdict(lambda: deque())

    def load_rules(self):
        try:
            with open(self.rules_file, "r") as file:
                data = json.load(file)
                
                # If rules are inside a dictionary, extract them
                if isinstance(data, dict):
                    self.rules = data.get("rules", [])
                elif isinstance(data, list):
                    self.rules = data  # If it's already a list, use it directly
        except FileNotFoundError:
            print("Rules file not found. Starting with no rules.")
        except json.JSONDecodeError:
            print("Error parsing rules file. Ensure it's a valid JSON file.")

    def save_rules(self):
        try:
            with open(self.rules_file, "w") as file:
                json.dump({"rules": self.rules}, file, indent=4)  # Wrap the rules in a dictionary
            print(f"Rules saved to {self.rules_file}.")
        except Exception as e:
            print(f"Error saving rules: {e}")

    def add_rule(self, rule):
        self.rules.append(rule)  # This should work if self.rules is a list
        print(f"Added rule: {rule}")
        self.save_rules()  # Ensure rule is saved

    def remove_rule(self, rule):
        if rule in self.rules:
            self.rules.remove(rule)
            self.save_rules()
            print(f"Removed rule: {rule}")
        else:
            print("Rule not found.")

    def check_packet(self, packet):
        """
        Checks if the given packet matches any rule.
        Returns "BLOCK" if a rule matches and says to block,
        or if rate limiting is triggered. Otherwise returns "ALLOW".
        """
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src

            # ✅ Always apply rate limiting first
            if self.is_rate_limited(src_ip):
                return "BLOCK"

        for rule in self.rules:
            # IP match
            if IP in packet:
                ip_layer = packet[IP]
                if rule.get("src") and ip_layer.src != rule["src"]:
                    continue
                if rule.get("dst") and ip_layer.dst != rule["dst"]:
                    continue
            else:
                if "src" in rule or "dst" in rule:
                    continue

            # Protocol match
            if rule.get("protocol"):
                proto = rule["protocol"].lower()
                if proto == "tcp" and not packet.haslayer(TCP):
                    continue
                elif proto == "udp" and not packet.haslayer(UDP):
                    continue
                elif proto == "ip" and not packet.haslayer(IP):
                    continue

            # Port match
            if TCP in packet or UDP in packet:
                pkt_sport = packet[TCP].sport if TCP in packet else packet[UDP].sport
                pkt_dport = packet[TCP].dport if TCP in packet else packet[UDP].dport

                if "port" in rule:
                    if pkt_sport != rule["port"] and pkt_dport != rule["port"]:
                        continue

                if "sport" in rule and pkt_sport != rule["sport"]:
                    continue
                if "dport" in rule and pkt_dport != rule["dport"]:
                    continue

            # All conditions matched
            return rule.get("action", "ALLOW").upper()

        # No rule matched
        return "ALLOW"


    def is_rate_limited(self, src_ip):
        now = time.time()
        history = self.packet_history[src_ip]

        # Remove old entries
        while history and now - history[0] > self.rate_limit_window:
            history.popleft()

        # Check if threshold exceeded
        if len(history) >= self.rate_limit_threshold:
            print(f"[⚠️] Rate limit exceeded for {src_ip}. Blocking packet.")
            return True

        # Otherwise record this packet
        history.append(now)
        return False

    
    def test_check_packet_allow(self):
        packet = {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1"}  # Adjust structure
        result = self.engine.check_packet(packet)
        self.assertEqual(result, "ALLOW")  # No rule matches this packet

    def test_check_packet_block(self):
        self.engine.add_rule({"src_ip": "192.168.1.100", "action": "BLOCK"})
        packet = {"src_ip": "192.168.1.100", "dst_ip": "192.168.1.1"}
        result = self.engine.check_packet(packet)
        self.assertEqual(result, "BLOCK")  # Blocked by the rule

