from pydantic import BaseModel, computed_field
from typing import Optional
import matplotlib.pyplot as plt
import numpy as np
class GlobalMap(BaseModel):
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
    
    #https://matplotlib.org/stable/gallery/lines_bars_and_markers/barchart.html#sphx-glr-gallery-lines-bars-and-markers-barchart-py
    def visualize(self):
        metrics = {
            'Total Packet Count': (self.total_packet_count),
            'Total Packet Length': (self.total_packet_length),
            'Average TTL': (self.avg_ttl)
        }
        
        width = 0.25  
        multiplier = 0
        fig, ax = plt.subplots(layout='constrained')

        for attribute, measurement in metrics.items():
            offset = width * multiplier
            rects = ax.bar([offset], [measurement], width, label=attribute)
            ax.bar_label(rects, padding=3)
            multiplier += 1

        ax.set_ylabel('Number')
        ax.set_xlabel('Metrics')
        ax.set_title('Global packet statistics')
        ax.legend(loc='upper left', ncols=3)
        ax.set_ylim(0, 250)
        plt.show()
