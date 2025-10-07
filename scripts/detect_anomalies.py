#!/usr/bin/env python3
"""
Script to detect anomalies in network traffic using statistical analysis
"""
import sys
import signal
import logging
from pathlib import Path
import datetime
import numpy as np

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.collect_data import read_maps
from src.helpers.FileOperations import FileInterface
from src.helpers.file_to_object import FileToObject
from config import SPIKE_THRESHOLD_MULTIPLIER, VERSION

# Setup logging
logger = logging.getLogger(__name__)

# Global flag for graceful shutdown
shutdown_requested = False


def signal_handler(sig, frame):
    """Handle shutdown signals gracefully"""
    global shutdown_requested
    shutdown_requested = True
    logger.info("Shutdown signal received, finishing current operation...")


def detect_spikes(global_maps, threshold_multiplier=SPIKE_THRESHOLD_MULTIPLIER):
    """
    Detect traffic spikes using statistical analysis

    Args:
        global_maps: List of GlobalMap objects
        threshold_multiplier: Number of standard deviations for threshold
    """
    if len(global_maps) < 2:
        logger.info("Not enough data for spike detection (need at least 2 data points)")
        return

    packet_counts = [gm.total_packet_count for gm in global_maps]
    timestamps = [gm.timestamp for gm in global_maps]
    times = [datetime.datetime.fromtimestamp(ts / 1e9) for ts in timestamps]

    # Calculate packet counts per interval
    packet_counts_per_interval = []
    times_per_interval = []
    for i in range(1, len(packet_counts)):
        if shutdown_requested:
            logger.info("Shutdown requested, stopping spike detection")
            return

        if packet_counts[i] >= packet_counts[i - 1]:
            count = packet_counts[i] - packet_counts[i - 1]
        else:
            count = packet_counts[i]
        packet_counts_per_interval.append(count)
        times_per_interval.append(times[i])

    if len(packet_counts_per_interval) < 2:
        logger.info("Not enough intervals for spike detection")
        return

    # Calculate statistics
    mean = np.mean(packet_counts_per_interval)
    std_dev = np.std(packet_counts_per_interval)
    threshold = mean + threshold_multiplier * std_dev
    last_count = packet_counts_per_interval[-1]
    last_time = times_per_interval[-1]

    logger.info("Traffic Statistics:")
    logger.info(f"  Mean packets/interval: {mean:.2f}")
    logger.info(f"  Std deviation: {std_dev:.2f}")
    logger.info(f"  Spike threshold: {threshold:.2f}")
    logger.info(f"  Last interval count: {last_count}")

    if last_count > threshold:
        logger.warning(f"SPIKE DETECTED at {last_time}: {last_count} packets!")
        FileInterface.alert_spike(last_time, last_count)
    else:
        logger.info("No spike detected. Traffic is normal.")


def main():
    """Main entry point"""
    # Setup signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info("=" * 50)
    logger.info(f"eBPF Network Monitor v{VERSION} - Anomaly Detection")
    logger.info("=" * 50)

    try:
        # Collect fresh data
        if not shutdown_requested:
            logger.info("Collecting data from BPF maps...")
            read_maps()

        # Parse global map and detect spikes
        if not shutdown_requested:
            logger.info("Analyzing traffic patterns...")
            try:
                global_maps = FileToObject.parse_global_map()
                detect_spikes(global_maps)
            except FileNotFoundError:
                logger.error("No global map data found. Run collect_data.py first.")
            except Exception as e:
                logger.error(f"Error during analysis: {e}", exc_info=True)

        if shutdown_requested:
            logger.info("Analysis interrupted by shutdown signal")
        else:
            logger.info("Anomaly detection complete")

    except Exception as e:
        logger.error(f"Fatal error during anomaly detection: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logger.info("Exiting gracefully")


if __name__ == "__main__":
    main()
