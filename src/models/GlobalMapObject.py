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
    """
    Visualize global traffic statistics - optimized for clarity
    """
    if not global_maps:
        print("No data available to visualize.")
        return

    # Use latest snapshot for current stats
    latest = global_maps[-1]

    # Extract time series data
    times = [datetime.datetime.fromtimestamp(gm.timestamp / 1e9) for gm in global_maps]
    total_packet_counts = [gm.total_packet_count for gm in global_maps]
    total_packet_lengths_mb = [gm.total_packet_length / (1024 * 1024) for gm in global_maps]
    average_ttls = [gm.avg_ttl for gm in global_maps]

    # Calculate derived metrics
    avg_packet_size = latest.total_packet_length / latest.total_packet_count if latest.total_packet_count > 0 else 0

    # Create clean dashboard
    fig = plt.figure(figsize=(16, 9))
    fig.suptitle('Global Network Traffic Overview', fontsize=18, fontweight='bold', y=0.98)

    # Create grid layout: 2 rows, 3 columns
    gs = fig.add_gridspec(2, 3, hspace=0.35, wspace=0.3, top=0.92, bottom=0.08)

    # --- Row 1: Key Metrics Cards ---

    # Card 1: Total Packets
    ax1 = fig.add_subplot(gs[0, 0])
    ax1.axis('off')
    ax1.text(0.5, 0.7, f"{latest.total_packet_count:,}", ha='center', va='center',
             fontsize=48, fontweight='bold', color='#2E86AB')
    ax1.text(0.5, 0.3, 'Total Packets', ha='center', va='center',
             fontsize=16, fontweight='bold', color='#555')
    ax1.add_patch(plt.Rectangle((0.05, 0.05), 0.9, 0.9, fill=False,
                                 edgecolor='#2E86AB', linewidth=3))

    # Card 2: Total Traffic
    ax2 = fig.add_subplot(gs[0, 1])
    ax2.axis('off')
    traffic_mb = latest.total_packet_length / (1024 * 1024)
    ax2.text(0.5, 0.7, f"{traffic_mb:.2f} MB", ha='center', va='center',
             fontsize=40, fontweight='bold', color='#F77F00')
    ax2.text(0.5, 0.3, 'Total Traffic', ha='center', va='center',
             fontsize=16, fontweight='bold', color='#555')
    ax2.add_patch(plt.Rectangle((0.05, 0.05), 0.9, 0.9, fill=False,
                                 edgecolor='#F77F00', linewidth=3))

    # Card 3: Average TTL
    ax3 = fig.add_subplot(gs[0, 2])
    ax3.axis('off')
    ax3.text(0.5, 0.7, f"{latest.avg_ttl:.1f}", ha='center', va='center',
             fontsize=48, fontweight='bold', color='#06A77D')
    ax3.text(0.5, 0.3, 'Average TTL', ha='center', va='center',
             fontsize=16, fontweight='bold', color='#555')
    ax3.add_patch(plt.Rectangle((0.05, 0.05), 0.9, 0.9, fill=False,
                                 edgecolor='#06A77D', linewidth=3))

    # --- Row 2: Time Series Charts ---

    # Chart 1: Packet Count Over Time
    ax4 = fig.add_subplot(gs[1, 0])
    if len(global_maps) > 1:
        ax4.plot(times, total_packet_counts, marker='o', linewidth=3, markersize=8,
                 color='#2E86AB', label='Packets')
        ax4.fill_between(times, total_packet_counts, alpha=0.2, color='#2E86AB')
    else:
        ax4.bar([0], [total_packet_counts[0]], color='#2E86AB', alpha=0.7)
        ax4.set_xticks([0])
        ax4.set_xticklabels(['Current'])

    ax4.set_ylabel('Packets', fontweight='bold', fontsize=12)
    ax4.set_title('Packet Count Timeline', fontweight='bold', fontsize=13)
    ax4.grid(True, alpha=0.3, linestyle='--')
    ax4.tick_params(axis='x', rotation=45)

    # Chart 2: Traffic Volume Over Time
    ax5 = fig.add_subplot(gs[1, 1])
    if len(global_maps) > 1:
        ax5.plot(times, total_packet_lengths_mb, marker='s', linewidth=3, markersize=8,
                 color='#F77F00', label='Traffic (MB)')
        ax5.fill_between(times, total_packet_lengths_mb, alpha=0.2, color='#F77F00')
    else:
        ax5.bar([0], [total_packet_lengths_mb[0]], color='#F77F00', alpha=0.7)
        ax5.set_xticks([0])
        ax5.set_xticklabels(['Current'])

    ax5.set_ylabel('Traffic (MB)', fontweight='bold', fontsize=12)
    ax5.set_title('Traffic Volume Timeline', fontweight='bold', fontsize=13)
    ax5.grid(True, alpha=0.3, linestyle='--')
    ax5.tick_params(axis='x', rotation=45)

    # Chart 3: Average TTL Over Time
    ax6 = fig.add_subplot(gs[1, 2])
    if len(global_maps) > 1:
        ax6.plot(times, average_ttls, marker='^', linewidth=3, markersize=8,
                 color='#06A77D', label='Avg TTL')
        ax6.fill_between(times, average_ttls, alpha=0.2, color='#06A77D')
    else:
        ax6.bar([0], [average_ttls[0]], color='#06A77D', alpha=0.7)
        ax6.set_xticks([0])
        ax6.set_xticklabels(['Current'])

    ax6.set_ylabel('TTL', fontweight='bold', fontsize=12)
    ax6.set_title('Average TTL Timeline', fontweight='bold', fontsize=13)
    ax6.grid(True, alpha=0.3, linestyle='--')
    ax6.set_ylim(0, 255)
    ax6.tick_params(axis='x', rotation=45)

    # Add footer with additional stats
    duration_seconds = (latest.timestamp - global_maps[0].timestamp) / 1e9
    duration_str = f"{duration_seconds:.1f}s" if duration_seconds < 60 else f"{duration_seconds/60:.1f}m"

    footer_text = f"Avg Packet Size: {avg_packet_size:.0f} bytes  |  Duration: {duration_str}  |  Samples: {len(global_maps)}"
    fig.text(0.5, 0.02, footer_text, ha='center', fontsize=11,
             bbox=dict(boxstyle='round', facecolor='lightgray', alpha=0.5))

    plt.show(block=True)
