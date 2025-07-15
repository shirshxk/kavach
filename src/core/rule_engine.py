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
        self.rules = []
        self.load_rules()
        self.rate_limit_window = 5
        self.rate_limit_threshold = 20
        self.packet_history = defaultdict(lambda: deque())

    def load_rules(self):
        try:
            with open(self.rules_file, "r") as file:
                data = json.load(file)
                if isinstance(data, dict):
                    self.rules = data.get("rules", [])
                elif isinstance(data, list):
                    self.rules = data
        except FileNotFoundError:
            print("Rules file not found. Starting with no rules.")
        except json.JSONDecodeError:
            print("Error parsing rules file. Ensure it's a valid JSON file.")

    def save_rules(self):
        try:
            os.makedirs(os.path.dirname(self.rules_file), exist_ok=True)
            with open(self.rules_file, "w") as file:
                json.dump({"rules": self.rules}, file, indent=4)
            print(f"Rules saved to {self.rules_file}.")
        except Exception as e:
            print(f"Error saving rules: {e}")

    def add_rule(self, rule):
        self.rules.append(rule)
        print(f"Added rule: {rule}")
        self.save_rules()

    def remove_rule(self, rule):
        if rule in self.rules:
            self.rules.remove(rule)
            self.save_rules()
            print(f"Removed rule: {rule}")
            return True
        else:
            print("Rule not found.")
            return False

    def check_packet(self, packet):
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            if self.is_rate_limited(src_ip):
                return "BLOCK"

        for rule in self.rules:
            if IP in packet:
                ip_layer = packet[IP]
                if rule.get("src") and ip_layer.src != rule["src"]:
                    continue
                if rule.get("dst") and ip_layer.dst != rule["dst"]:
                    continue
            else:
                if "src" in rule or "dst" in rule:
                    continue

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

            return rule.get("action", "ALLOW").upper()

        return "ALLOW"

    def is_rate_limited(self, src_ip):
        now = time.time()
        history = self.packet_history[src_ip]
        while history and now - history[0] > self.rate_limit_window:
            history.popleft()
        if len(history) >= self.rate_limit_threshold:
            print(f"[⚠️] Rate limit exceeded for {src_ip}. Blocking packet.")
            return True
        history.append(now)
        return False
