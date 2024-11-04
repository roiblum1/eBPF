import socket 
import ipaddress

class IPInterface:
    def convert_ip_str(ip_in_bytes):
        ip_address = ipaddress.ip_address(ip_in_bytes)
        reversed_ip = ".".join(str(ip_address).split(".")[::-1])
        return reversed_ip
    
    def opposite_ip(ip_address:str) -> str:
        reversed_ip = ".".join(str(ip_address).split(".")[::-1])
        return reversed_ip        
    
    def int_to_ip(ip_int):
        return socket.inet_ntoa(ip_int.to_bytes(4, 'big'))
