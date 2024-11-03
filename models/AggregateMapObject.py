from pydantic import BaseModel, computed_field, field_validator
from typing import Optional
import matplotlib.pyplot as plt
import numpy as np
import socket

class PacketMapKey(BaseModel):
    src_ip: str
    dst_ip: str
    @field_validator('src_ip','dst_ip')
    def convert_ip_to_string(cls, v):
        return bytes_to_ip(v)
    
class PacketAggregate(BaseModel):
    total_packet_count: int
    total_packet_length: int
    total_ttl: int
    @computed_field
    @property
    def avg_ttl(self) -> float:
        if(self.total_packet_count > 0):
            return self.total_packet_length / self.total_packet_count
        else:
            return 0

class PacketAggregateMap(BaseModel):
    key: PacketMapKey 
    value: PacketAggregate

def visualizeAggregateMap(packet_aggregate_map: list[PacketAggregateMap]): 
    keys = []
    for map in packet_aggregate_map:
        keys.append(map.key.src_ip + " -> " + map.key.dst_ip)
            
    metrics = {
        'Total Packet Count': [map.value.total_packet_count for map in packet_aggregate_map],
        'Total Packet Length': [map.value.total_packet_length for map in packet_aggregate_map],
        'Average TTL': [map.value.avg_ttl for map in packet_aggregate_map]
    }
        
    x = np.arange(len(keys))  
    width = 0.25  
    multiplier = 0

    fig, ax = plt.subplots(layout='constrained')

    for attribute, measurement in metrics.items():
        offset = width * multiplier
        rects = ax.bar(x + offset, measurement, width, label=attribute)
        ax.bar_label(rects, padding=3)
        multiplier += 1

    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel('Length (mm)')
    ax.set_title('Penguin attributes by species')
    ax.set_xticks(x + width, keys)
    ax.legend(loc='upper left', ncols=3)
    ax.set_ylim(0, 50000)

    plt.ion()
    plt.show(block=True)

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