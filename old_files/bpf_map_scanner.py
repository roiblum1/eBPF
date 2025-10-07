from bpf import read_maps 
from Helpers.FileOperations import FileInterface
from Helpers.file_to_object import FileToObject
import datetime
import numpy as np

def detect_spikes(global_maps, threshold_multiplier=3):
    if len(global_maps) < 2:
        return
    packet_counts = [gm.total_packet_count for gm in global_maps]
    timestamps = [gm.timestamp for gm in global_maps]
    times = [datetime.datetime.fromtimestamp(ts / 1e9) for ts in timestamps]
    packet_counts_per_interval = []
    times_per_interval = []
    for i in range(1, len(packet_counts)):
        if packet_counts[i] >= packet_counts[i - 1]:
            count = packet_counts[i] - packet_counts[i - 1]
        else:
            count = packet_counts[i]
        packet_counts_per_interval.append(count)
        times_per_interval.append(times[i])

    if len(packet_counts_per_interval) < 2:
        return
    mean = np.mean(packet_counts_per_interval)
    std_dev = np.std(packet_counts_per_interval)
    threshold = mean + threshold_multiplier * std_dev
    last_count = packet_counts_per_interval[-1]
    last_time = times_per_interval[-1]

    if last_count > threshold:
        FileInterface.alert_spike(last_time, last_count)
            
def main():
    read_maps()
    detect_spikes(FileToObject.parse_global_map())

if __name__ == "__main__":
  main()
    