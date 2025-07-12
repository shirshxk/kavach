# src/utils/ip_utils.py
import ipaddress

class IpUtils:
    @staticmethod
    def is_valid_ip(ip):
        """Checks if a given string is a valid IP address."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_ip_in_subnet(ip, subnet):
        """Checks if an IP address belongs to a given subnet."""
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            return False

    @staticmethod
    def get_subnet_ips(subnet):
        """Returns all IPs in a subnet."""
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            raise ValueError("Invalid subnet provided.")
