import json  
from scapy.layers.inet import IP, TCP, UDP

class RuleEngine:
    def __init__(self, rules_file="src/core/configs/default_rules.json"):
        self.rules_file = rules_file
        self.rules = []  # Initialize rules as a list
        self.load_rules()

    def load_rules(self):
        try:
            with open(self.rules_file, "r") as file:
                data = json.load(file)
                
                # If rules are inside a dictionary, extract them
                if isinstance(data, dict):
                    self.rules = data.get("rules", [])
                elif isinstance(data, list):
                    self.rules = data  # If it's already a list, use it directly

            print("Rules loaded successfully.")
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
        print(f"Current rules before removal: {self.rules}")  # Debugging line
        if rule in self.rules:
            self.rules.remove(rule)
            print(f"Removed rule: {rule}")
            self.save_rules()  # Ensure rule is saved after removal
        else:
            print("Rule not found.")
    

    def check_packet(self, packet):
        """
        Checks if the given packet matches any rule.
        Returns "BLOCK" if a rule matches and says to block,
        otherwise returns "ALLOW".
        """
        if not self.rules:
            return "ALLOW"

        for rule in self.rules:
            # Check for IP layer
            if IP in packet:
                ip_layer = packet[IP]

                if rule.get("src") and ip_layer.src != rule["src"]:
                    continue
                if rule.get("dst") and ip_layer.dst != rule["dst"]:
                    continue

            else:
                # If rule needs IP fields but packet has no IP layer, skip
                if "src" in rule or "dst" in rule:
                    continue

            # Check protocol
            if rule.get("protocol"):
                proto = rule["protocol"].lower()
                if proto == "tcp" and not packet.haslayer(TCP):
                    continue
                elif proto == "udp" and not packet.haslayer(UDP):
                    continue
                elif proto == "ip" and not packet.haslayer(IP):
                    continue

            # If all checks pass, return action
            return rule.get("action", "ALLOW").upper()

        return "ALLOW"  # No rule matched means allow by default

    
    def test_check_packet_allow(self):
        packet = {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1"}  # Adjust structure
        result = self.engine.check_packet(packet)
        self.assertEqual(result, "ALLOW")  # No rule matches this packet

    def test_check_packet_block(self):
        self.engine.add_rule({"src_ip": "192.168.1.100", "action": "BLOCK"})
        packet = {"src_ip": "192.168.1.100", "dst_ip": "192.168.1.1"}
        result = self.engine.check_packet(packet)
        self.assertEqual(result, "BLOCK")  # Blocked by the rule

