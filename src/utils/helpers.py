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

    def read_file(file_path):
        """Reads a file and returns its content."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"{file_path} does not exist.")
        with open(file_path, "r") as file:
            return file.read()

    def write_file(file_path, content):
        """Writes content to a file."""
        with open(file_path, "w") as file:
            file.write(content)

    def validate_action(action):
        """Validates if the action is 'ALLOW' or 'BLOCK'."""
        if action not in ["ALLOW", "BLOCK"]:
            raise ValueError("Action must be 'ALLOW' or 'BLOCK'.")
        return True
