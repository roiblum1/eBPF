from pydantic import BaseModel, field_validator
from typing import Optional
import socket

class PacketInformation(BaseModel):
    src_ip: str
    dest_ip: str
    tot_len: int
    ttl: int
    protocol: str
    data_length: Optional[int] = 0 
    data: str
    @field_validator('src_ip','dest_ip')
    def convert_ip_to_string(cls, v):
        return bytes_to_ip(v)

def bytes_to_ip(ip_in_bytes):
    """
    Converts a bytes object representing an IP address into a string.

    :param ip_in_bytes: A bytes object containing the IP address in network byte order.
    :type ip_in_bytes: bytes
    :return: A string representation of the IP address.
    :rtype: str
    """
    if(type(ip_in_bytes) == str):
        return ip_in_bytes
    ip_addr = socket.inet_ntoa(ip_in_bytes)
    return ip_addr