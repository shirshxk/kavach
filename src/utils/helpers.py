import os
import psutil

class Helper:
    @staticmethod
    def detect_interface():
        interfaces = psutil.net_if_addrs()
        for iface in interfaces:
            if iface != "lo" and not iface.startswith("docker") and not iface.startswith("veth"):
                return iface
        return "lo"

    @staticmethod
    def read_file(file_path):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"{file_path} does not exist.")
        with open(file_path, "r") as file:
            return file.read()

    @staticmethod
    def write_file(file_path, content):
        with open(file_path, "w") as file:
            file.write(content)

    @staticmethod
    def validate_action(action):
        action = action.strip().upper()
        if action not in ["ALLOW", "BLOCK"]:
            raise ValueError("Action must be 'ALLOW' or 'BLOCK'.")
        return action

    @staticmethod
    def parse_rule_arg(arg):
        """Parses a CLI rule argument in the format 'IP,ACTION'."""
        if "," not in arg:
            raise ValueError("Missing comma in rule. Expected format: IP,ACTION")
        parts = [p.strip() for p in arg.split(",")]
        if len(parts) != 2:
            raise ValueError("Incorrect rule format. Expected format: IP,ACTION")
        ip = parts[0]
        action = Helper.validate_action(parts[1])
        return ip, action

    @staticmethod
    def parse_ports(port_str):
        ports = [int(p.strip()) for p in port_str.split(",")]
        for port in ports:
            if not (1 <= port <= 65535):
                raise ValueError(f"Invalid port: {port}")
        return ports
    
    @staticmethod
    def is_rate_limited(self, ip):
        now = time.time()
        timestamps = self.packet_history[ip]

        while timestamps and now - timestamps[0] > self.rate_limit_window:
            timestamps.popleft()

        timestamps.append(now)

        if len(timestamps) > self.rate_limit_threshold:
            return True
        return False

