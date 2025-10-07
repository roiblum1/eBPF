import socket
import ipaddress

class IPInterface:
    @staticmethod
    def convert_ip_str(ip_in_bytes):
        """Convert IP bytes to string with reversed octets"""
        ip_address = ipaddress.ip_address(ip_in_bytes)
        reversed_ip = ".".join(str(ip_address).split(".")[::-1])
        return reversed_ip

    @staticmethod
    def opposite_ip(ip_address: str) -> str:
        """Reverse IP address octets"""
        reversed_ip = ".".join(str(ip_address).split(".")[::-1])
        return reversed_ip

    @staticmethod
    def int_to_ip(ip_int):
        """Convert integer to IP address string"""
        return socket.inet_ntoa(ip_int.to_bytes(4, 'big'))
