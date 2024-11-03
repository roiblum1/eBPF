import socket 
import ipaddress

class IPInterface:
    def converte_ip_str(ip_in_bytes):
        """
        Converts a bytes object representing an IP address into a string.

        :param ip_in_bytes: A bytes object containing the IP address in network byte order.
        :type ip_in_bytes: bytes
        :return: A string representation of the IP address.
        :rtype: str
        """
        if isinstance(ip_in_bytes, int):
            ip_in_bytes = ip_in_bytes.to_bytes(4, byteorder='big')
            return str(ipaddress.ip_address(ip_in_bytes))
        return str(ipaddress.ip_address(ip_in_bytes))