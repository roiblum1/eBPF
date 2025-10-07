#!/usr/bin/env python3
"""
Main script to collect data from eBPF maps and kernel trace pipe
"""
import json
import sys
import signal
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.models.PacketObject import PacketInformation
from src.models.AggregateMapObject import PacketAggregate, PacketMapKey, PacketAggregateMap
from src.models.GlobalMapObject import GlobalMap
from src.helpers.IPconvert import IPInterface
from src.helpers.FileOperations import FileInterface
from src.helpers.OSFunctions import OSInterface
from src.helpers.parse_to_object import ParseToObject
from config import (
    PACKET_MAP_PATH,
    PACKETS_AGGREGATE_MAP_PATH,
    GLOBAL_AGGREGATE_DATA_PATH,
    MAC_IP_MAP_PATH,
    TRACE_PIPE_PATH,
    MAX_TOTAL_PACKETS,
    SUSPICIOUS_PORTS,
    MAX_IPS_PER_MAC,
    IGNORED_MAC_ADDRESSES,
    VERSION
)

# Setup logging
logger = logging.getLogger(__name__)

# Global flag for graceful shutdown
shutdown_requested = False


def signal_handler(sig, frame):
    """Handle shutdown signals gracefully"""
    global shutdown_requested
    shutdown_requested = True
    logger.info("Shutdown signal received, finishing current operation...")


def read_all_maps_batched():
    """
    Read all BPF maps in a single batched call for better performance

    Returns:
        dict: Dictionary with all map data
    """
    import subprocess

    logger.debug("Reading all BPF maps in batch...")

    maps = {
        'packet': PACKET_MAP_PATH,
        'aggregate': PACKETS_AGGREGATE_MAP_PATH,
        'global': GLOBAL_AGGREGATE_DATA_PATH,
        'mac_ip': MAC_IP_MAP_PATH
    }

    results = {}

    # Batch read all maps
    for map_name, map_path in maps.items():
        try:
            cmd = f"sudo bpftool map dump pinned {map_path} -j"
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.PIPE)
            results[map_name] = output.decode('utf-8')
            logger.debug(f"Successfully read {map_name} map")
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to read {map_name} map: {e}")
            results[map_name] = "[]"
        except Exception as e:
            logger.error(f"Unexpected error reading {map_name} map: {e}")
            results[map_name] = "[]"

    return results


def read_maps():
    """Read and parse all BPF maps"""
    try:
        # Batch read all maps for better performance
        map_data = read_all_maps_batched()

        # Process packet map
        logger.info("Processing packet map...")
        packets_maps = []
        packet_map_dicts = json.loads(map_data['packet'])

        if not packet_map_dicts:
            logger.info("No packet data found (map is empty or eBPF program not running)")

        for i, map_entry in enumerate(packet_map_dicts):
            if shutdown_requested:
                logger.info("Shutdown requested, stopping packet map processing")
                break

            if not isinstance(map_entry, dict):
                logger.warning(f"Entry {i} is {type(map_entry).__name__}, not dict")
                continue
            try:
                packet_map_obj = ParseToObject.parse_packet_map(map_entry)
                if packet_map_obj.dst_port in SUSPICIOUS_PORTS:
                    FileInterface.alert_port_log(packet_map_obj)
                    logger.warning(f"Suspicious port detected: {packet_map_obj.dst_port}")
                packets_maps.append(packet_map_obj)
            except Exception as e:
                logger.debug(f"Failed to parse entry {i}: {e}")
                continue

        if packets_maps:
            FileInterface.write_list_file(packets_maps, "packets_maps.json")
            logger.info(f"Collected {len(packets_maps)} packet entries")

        # Process aggregate map
        logger.info("Processing aggregate map...")
        aggregate_maps = []
        aggregate_map_dict = json.loads(map_data['aggregate'])

        if not aggregate_map_dict:
            logger.info("No aggregate data found (map is empty or eBPF program not running)")

        for i, map_entry in enumerate(aggregate_map_dict):
            if shutdown_requested:
                logger.info("Shutdown requested, stopping aggregate map processing")
                break

            if not isinstance(map_entry, dict):
                logger.warning(f"Invalid aggregate map entry {i}")
                continue
            try:
                packet_aggregate_map = ParseToObject.parse_aggregate_map(map_entry)
                if packet_aggregate_map.value.total_packet_count > MAX_TOTAL_PACKETS:
                    FileInterface.write_alert_log(packet_aggregate_map)
                    logger.warning(f"High packet count detected: {packet_aggregate_map.value.total_packet_count}")
                aggregate_maps.append(packet_aggregate_map)
            except Exception as e:
                logger.debug(f"Failed to parse aggregate entry {i}: {e}")
                continue

        if aggregate_maps:
            FileInterface.write_list_file(aggregate_maps, "aggregate_map.json")
            logger.info(f"Collected {len(aggregate_maps)} aggregate entries")

        # Process global map
        logger.info("Processing global map...")
        global_map_dict = json.loads(map_data['global'])

        if not global_map_dict:
            logger.info("No global data found (map is empty or eBPF program not running)")
            return [], None

        global_map_obj = ParseToObject.parse_global_map(global_map_dict)
        FileInterface.write_list_file([global_map_obj], "global_map.json")
        logger.info("Global statistics collected")

        # Process MAC-IP map
        logger.info("Processing MAC-IP map...")
        mac_address_maps = []
        mac_address_map_dicts = json.loads(map_data['mac_ip'])

        if not mac_address_map_dicts:
            logger.info("No MAC-IP data found (map is empty or eBPF program not running)")

        for i, map_entry in enumerate(mac_address_map_dicts):
            if shutdown_requested:
                logger.info("Shutdown requested, stopping MAC-IP map processing")
                break

            if not isinstance(map_entry, dict):
                logger.warning(f"Invalid MAC-IP map entry {i}")
                continue
            try:
                mac_ip_entry = ParseToObject.parse_mac_ip_map_entry(map_entry)

                # Skip gateway/router MACs (they legitimately have many IPs)
                if mac_ip_entry.key.mac in IGNORED_MAC_ADDRESSES:
                    logger.debug(f"Skipping gateway MAC {mac_ip_entry.key.mac} (in IGNORED_MAC_ADDRESSES)")
                    continue

                # Alert on suspicious MAC-IP associations
                if len(mac_ip_entry.value.ips) > MAX_IPS_PER_MAC:
                    FileInterface.alert_mac_ip_log(mac_ip_entry)
                    logger.warning(f"Potential MAC spoofing detected: MAC {mac_ip_entry.key.mac} has {len(mac_ip_entry.value.ips)} IPs")

                mac_address_maps.append(mac_ip_entry)
            except Exception as e:
                logger.debug(f"Failed to parse MAC-IP entry {i}: {e}")
                continue

        if mac_address_maps:
            FileInterface.write_list_file(mac_address_maps, "mac_ip_map.json")
            logger.info(f"Collected {len(mac_address_maps)} MAC-IP mappings")

        return aggregate_maps, global_map_obj

    except PermissionError:
        logger.error("Permission denied. Try running with sudo.")
        return [], None
    except FileNotFoundError as e:
        logger.error(f"BPF map not found. Make sure eBPF program is loaded. {e}")
        return [], None
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse BPF map output: {e}")
        return [], None
    except Exception as e:
        logger.error(f"Unexpected error reading maps: {e}", exc_info=True)
        return [], None


def main():
    """Main entry point"""
    # Setup signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info("=" * 50)
    logger.info(f"eBPF Network Monitor v{VERSION} - Data Collection")
    logger.info("=" * 50)

    try:
        # Read from BPF maps
        aggregate_maps, global_map = read_maps()

        if not shutdown_requested:
            logger.info(f"Collection complete: {len(aggregate_maps)} aggregate entries")
            logger.info("Data saved to data/logs/")
        else:
            logger.info("Collection interrupted by shutdown signal")

    except Exception as e:
        logger.error(f"Fatal error during collection: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logger.info("Exiting gracefully")


if __name__ == "__main__":
    main()
