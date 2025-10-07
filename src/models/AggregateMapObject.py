from pydantic import BaseModel, computed_field, field_validator
from typing import Optional, List
import matplotlib.pyplot as plt
import numpy as np

from src.helpers.IPconvert import IPInterface

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

def visualizeAggregateMap(packet_aggregate_map: List[PacketAggregateMap]):
    """
    Visualize aggregate packet statistics with improved dashboard-style layout
    """
    if not packet_aggregate_map:
        print("No aggregate data to visualize")
        return

    # Get top 10 flows by packet count
    top_flows = sorted(packet_aggregate_map, key=lambda x: x.value.total_packet_count, reverse=True)[:10]

    # Create figure with subplots
    fig = plt.figure(figsize=(16, 10))
    fig.suptitle('Network Traffic Analysis - Aggregate Statistics', fontsize=16, fontweight='bold')

    # Create grid layout
    gs = fig.add_gridspec(3, 2, hspace=0.3, wspace=0.3)

    # --- Top Left: Packet Count Bar Chart ---
    ax1 = fig.add_subplot(gs[0, 0])
    flow_labels = [f"{m.key.src_ip[:15]}→{m.key.dst_ip[:15]}" for m in top_flows]
    packet_counts = [m.value.total_packet_count for m in top_flows]
    colors = plt.cm.viridis(np.linspace(0.3, 0.9, len(flow_labels)))

    bars1 = ax1.barh(flow_labels, packet_counts, color=colors)
    ax1.set_xlabel('Packet Count', fontweight='bold')
    ax1.set_title('Top 10 Flows by Packet Count', fontweight='bold')
    ax1.grid(axis='x', alpha=0.3)

    # Add value labels on bars
    for i, (bar, val) in enumerate(zip(bars1, packet_counts)):
        ax1.text(val, bar.get_y() + bar.get_height()/2, f' {val:,}',
                va='center', fontsize=9, fontweight='bold')

    # --- Top Right: Traffic Volume (Bytes) ---
    ax2 = fig.add_subplot(gs[0, 1])
    packet_lengths = [m.value.total_packet_length for m in top_flows]
    packet_lengths_kb = [x / 1024 for x in packet_lengths]  # Convert to KB

    bars2 = ax2.barh(flow_labels, packet_lengths_kb, color=colors)
    ax2.set_xlabel('Total Traffic (KB)', fontweight='bold')
    ax2.set_title('Top 10 Flows by Traffic Volume', fontweight='bold')
    ax2.grid(axis='x', alpha=0.3)

    for i, (bar, val) in enumerate(zip(bars2, packet_lengths_kb)):
        ax2.text(val, bar.get_y() + bar.get_height()/2, f' {val:.1f} KB',
                va='center', fontsize=9, fontweight='bold')

    # --- Middle Left: Average TTL ---
    ax3 = fig.add_subplot(gs[1, 0])
    avg_ttls = [m.value.avg_ttl for m in top_flows]

    bars3 = ax3.barh(flow_labels, avg_ttls, color='coral')
    ax3.set_xlabel('Average TTL', fontweight='bold')
    ax3.set_title('Average TTL by Flow', fontweight='bold')
    ax3.grid(axis='x', alpha=0.3)
    ax3.set_xlim(0, 255)

    for i, (bar, val) in enumerate(zip(bars3, avg_ttls)):
        ax3.text(val, bar.get_y() + bar.get_height()/2, f' {val:.1f}',
                va='center', fontsize=9, fontweight='bold')

    # --- Middle Right: Packet Size Distribution ---
    ax4 = fig.add_subplot(gs[1, 1])
    avg_packet_sizes = [m.value.total_packet_length / m.value.total_packet_count
                        for m in top_flows]

    bars4 = ax4.barh(flow_labels, avg_packet_sizes, color='lightgreen')
    ax4.set_xlabel('Average Packet Size (Bytes)', fontweight='bold')
    ax4.set_title('Average Packet Size by Flow', fontweight='bold')
    ax4.grid(axis='x', alpha=0.3)

    for i, (bar, val) in enumerate(zip(bars4, avg_packet_sizes)):
        ax4.text(val, bar.get_y() + bar.get_height()/2, f' {val:.0f} B',
                va='center', fontsize=9, fontweight='bold')

    # --- Bottom: Traffic Distribution Pie Chart ---
    ax5 = fig.add_subplot(gs[2, :])

    # Show top 5 + "Others"
    top5 = top_flows[:5]
    top5_counts = [m.value.total_packet_count for m in top5]
    others_count = sum([m.value.total_packet_count for m in packet_aggregate_map]) - sum(top5_counts)

    pie_labels = [f"{m.key.src_ip[:12]}→{m.key.dst_ip[:12]}" for m in top5]
    if others_count > 0:
        pie_labels.append('Others')
        top5_counts.append(others_count)

    colors_pie = plt.cm.Set3(np.linspace(0, 1, len(pie_labels)))
    wedges, texts, autotexts = ax5.pie(top5_counts, labels=pie_labels, autopct='%1.1f%%',
                                         colors=colors_pie, startangle=90, textprops={'fontsize': 10})

    ax5.set_title('Traffic Distribution (by Packet Count)', fontweight='bold', pad=20)

    # Make percentage text bold
    for autotext in autotexts:
        autotext.set_color('white')
        autotext.set_fontweight('bold')
        autotext.set_fontsize(11)

    # Add summary statistics text
    total_packets = sum([m.value.total_packet_count for m in packet_aggregate_map])
    total_bytes = sum([m.value.total_packet_length for m in packet_aggregate_map])
    total_flows = len(packet_aggregate_map)

    summary = f"Total Flows: {total_flows} | Total Packets: {total_packets:,} | Total Traffic: {total_bytes/1024/1024:.2f} MB"
    fig.text(0.5, 0.02, summary, ha='center', fontsize=12, fontweight='bold',
             bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

    plt.show(block=True)
