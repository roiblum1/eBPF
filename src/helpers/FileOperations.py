import json
import jsonlines
import logging
from pathlib import Path

from src.models.AggregateMapObject import PacketAggregateMap
from src.models.PacketObject import PacketInformation
from src.models.MacIPObject import MacIpKey, MacIpValue, MacIpMapEntry
from config import LOGS_DIR

# Setup logging
logger = logging.getLogger(__name__)

class FileInterface():
    @staticmethod
    def write_list_file(object_list: list, file_name: str) -> None:
        """Write list of objects to JSON lines file"""
        try:
            path = LOGS_DIR / file_name
            letter = 'w'
            if file_name == "global_map.json":
                letter = 'a'
            with jsonlines.open(path, letter) as writer:
                for obj in object_list:
                    writer.write(obj.dict())
                logger.debug(f"Successfully wrote {len(object_list)} entries to {file_name}")
        except Exception as e:
            logger.error(f"Error writing to file {file_name}: {e}")

    @staticmethod
    def write_alert_log(packet_aggregate_map: PacketAggregateMap, file_name: str = "alerts.txt"):
        """Log alerts for high packet count"""
        path = LOGS_DIR / file_name
        with open(path, "a") as file:
            file.write(f"{packet_aggregate_map.key.src_ip} -> {packet_aggregate_map.key.dst_ip} is reaching the max total packet and reach to {packet_aggregate_map.value.total_packet_count}\n")

    @staticmethod
    def alert_port_log(packet_map: PacketInformation, file_name: str = "alerts.txt"):
        """Log alerts for suspicious ports"""
        path = LOGS_DIR / file_name
        with open(path, "a") as file:
            file.write(f"{packet_map.src_ip}:{packet_map.src_port} -> {packet_map.dst_ip}:{packet_map.dst_port} packet is using remote control port!\n")

    @staticmethod
    def alert_mac_ip_log(mac_ip_entry: MacIpMapEntry, file_name: str = "alerts.txt"):
        """Log alerts for MAC address with multiple IPs"""
        path = LOGS_DIR / file_name
        alert_message = f"Alert: MAC address {mac_ip_entry.key.mac} is associated with multiple IPs: {', '.join(mac_ip_entry.value.ips)}"
        with open(path, "a") as f:
            f.write(alert_message + "\n")

    @staticmethod
    def alert_spike(last_time, last_count, file_name: str = "alerts.txt"):
        """Log alerts for traffic spikes"""
        path = LOGS_DIR / file_name
        alert_message = f"Alert: Spike detected at {last_time}: {last_count} packets"
        with open(path, "a") as f:
            f.write(alert_message + "\n")