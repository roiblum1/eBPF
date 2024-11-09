from pydantic import BaseModel, computed_field, field_validator
from typing import Optional
import matplotlib.pyplot as plt
import numpy as np
from Helpers.IPconvert import IPInterface

class PacketMapKey(BaseModel):
    src_ip: str
    dst_ip: str
    @field_validator('src_ip','dst_ip', mode="before")
    def convert_ip_to_string(cls, v):
        return IPInterface.convert_ip_str(v)
    
    def reverse_ips(self) -> None:
        self.src_ip, self.dst_ip = IPInterface.opposite_ip(self.dst_ip), IPInterface.opposite_ip(self.src_ip)
class PacketAggregate(BaseModel):
    total_packet_count: int
    total_packet_length: int
    total_ttl: int
    @computed_field
    def avg_ttl(self) -> float:
        if self.total_packet_count > 0:
            return self.total_ttl / self.total_packet_count
        else:
            return 0

class PacketAggregateMap(BaseModel):
    key: PacketMapKey 
    value: PacketAggregate

def visualizeAggregateMap(packet_aggregate_map: list[PacketAggregateMap]): 
    top_10_maps = sorted(packet_aggregate_map, key=lambda x: x.value.total_packet_count, reverse=True)[:5]
    packet_aggregate_map = top_10_maps
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

    ax.set_ylabel('Length (mm)')
    ax.set_title('Top 10 Keys Packet Metrics')
    ax.set_xticks(x + width, keys)
    ax.legend(loc='upper left', ncols=3)
    ax.set_ylim(0, max(map.value.total_packet_length for map in top_10_maps) * 1.1)

    plt.ion()
    plt.show(block=True)
