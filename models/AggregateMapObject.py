from pydantic import BaseModel, computed_field, field_validator
from typing import Optional
import matplotlib.pyplot as plt
import numpy as np
from Helpers.IPconverte import IPInterface

class PacketMapKey(BaseModel):
    src_ip: str
    dst_ip: str
    @field_validator('src_ip','dst_ip', mode="before")
    def convert_ip_to_string(cls, v):
        return IPInterface.converte_ip_str(v)
    
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

    ax.set_ylabel('Length (mm)')
    ax.set_title('Penguin attributes by species')
    ax.set_xticks(x + width, keys)
    ax.legend(loc='upper left', ncols=3)
    ax.set_ylim(0, 50000)

    plt.ion()
    plt.show(block=True)
