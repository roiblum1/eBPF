from pydantic import BaseModel, computed_field
import matplotlib.pyplot as plt
import numpy as np
import datetime
from typing import List

class GlobalMap(BaseModel):
    total_packet_count: int
    total_packet_length: int
    total_ttl: int
    timestamp: int  #

    @computed_field
    @property
    def avg_ttl(self) -> float:
        if self.total_packet_count > 0:
            return self.total_ttl / self.total_packet_count
        else:
            return 0

def visualize_global_map(global_maps: List[GlobalMap]):
    if not global_maps:
        print("No data available to visualize.")
        return

    # Extract times and metrics from global_maps
    times = [datetime.datetime.fromtimestamp(gm.timestamp / 1e9) for gm in global_maps]
    total_packet_counts = [gm.total_packet_count for gm in global_maps]
    total_packet_lengths = [gm.total_packet_length for gm in global_maps]
    average_ttls = [gm.avg_ttl for gm in global_maps]

    # Plot Total Packet Count over time
    plt.figure(figsize=(12, 6))
    plt.plot(times, total_packet_counts, marker='o', label='Total Packet Count')
    plt.xlabel('Time')
    plt.ylabel('Total Packet Count')
    plt.title('Total Packet Count Over Time')
    plt.grid(True)
    plt.legend()
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

    # Plot Total Packet Length over time
    plt.figure(figsize=(12, 6))
    plt.plot(times, total_packet_lengths, marker='o', color='orange', label='Total Packet Length')
    plt.xlabel('Time')
    plt.ylabel('Total Packet Length')
    plt.title('Total Packet Length Over Time')
    plt.grid(True)
    plt.legend()
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

    # Plot Average TTL over time
    plt.figure(figsize=(12, 6))
    plt.plot(times, average_ttls, marker='o', color='green', label='Average TTL')
    plt.xlabel('Time')
    plt.ylabel('Average TTL')
    plt.title('Average TTL Over Time')
    plt.grid(True)
    plt.legend()
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

    # Combined Plot with Subplots
    fig, axs = plt.subplots(3, 1, figsize=(14, 18), sharex=True)

    axs[0].plot(times, total_packet_counts, marker='o', label='Total Packet Count')
    axs[0].set_ylabel('Total Packet Count')
    axs[0].legend()
    axs[0].grid(True)

    axs[1].plot(times, total_packet_lengths, marker='o', color='orange', label='Total Packet Length')
    axs[1].set_ylabel('Total Packet Length')
    axs[1].legend()
    axs[1].grid(True)

    axs[2].plot(times, average_ttls, marker='o', color='green', label='Average TTL')
    axs[2].set_xlabel('Time')
    axs[2].set_ylabel('Average TTL')
    axs[2].legend()
    axs[2].grid(True)

    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()
