from typing import Optional

from src.models.PacketObject import PacketInformation
from src.models.AggregateMapObject import PacketAggregate, PacketMapKey, PacketAggregateMap
from src.models.GlobalMapObject import GlobalMap
from src.models.MacIPObject import MacIpKey, MacIpValue, MacIpMapEntry
from src.helpers.IPconvert import IPInterface
class ParseToObject():
    @staticmethod
    def parse_trace(line: str) -> Optional[PacketInformation]:
        start_index = line.find("src_ip:")
        if start_index != -1:
            packet_information = line[start_index:].strip()
            fields = packet_information.split(',')
            packet_information_dict = {}
            for field in fields:
                data = field.split(':', 1)
                if len(data) == 2:
                    attribute = data[0].strip()
                    value = data[1].strip()
                    # Map 'dest_ip' to 'dst_ip' if needed
                    if attribute == 'dest_ip':
                        attribute = 'dst_ip'
                    packet_information_dict[attribute] = value
                else:
                    print(f"Could not parse field '{field}' in packet: {line}")
                    return None
            # Check if all required fields are present
            required_fields = ['src_ip', 'dst_ip', 'tot_len', 'ttl', 'protocol']
            for field in required_fields:
                if field not in packet_information_dict:
                    print(f"Missing field '{field}' in packet: {line}")
                    return None
            return PacketInformation(**packet_information_dict)
        else:
            return None




    @staticmethod
    def parse_packet_map(packet_map: dict) -> PacketInformation:
        """Parse packet map entry from bpftool output"""
        if not isinstance(packet_map, dict):
            raise ValueError(f"Expected dict, got {type(packet_map)}")

        # bpftool -j output has a 'formatted' field with parsed data
        if 'formatted' in packet_map:
            value = packet_map['formatted']['value']
        else:
            value = packet_map.get("value", packet_map)

        # Handle if value is a list (raw byte array from bpftool)
        if isinstance(value, list):
            raise ValueError("Got raw byte array - use 'formatted' field instead")

        return PacketInformation(**value)

    @staticmethod
    def parse_aggregate_map(aggregate_map: dict) -> PacketAggregateMap:
        """Parse aggregate map entry from bpftool output"""
        # bpftool -j output has a 'formatted' field with parsed data
        if 'formatted' in aggregate_map:
            key = aggregate_map['formatted']['key']
            value = aggregate_map['formatted']['value']
        else:
            key = aggregate_map["key"]
            value = aggregate_map["value"]

        packet_map_key = PacketMapKey(**key)
        packet_aggregate = PacketAggregate(**value)
        packet_aggregate_map = PacketAggregateMap(key=packet_map_key, value=packet_aggregate)
        return packet_aggregate_map

    @staticmethod
    def parse_global_map(global_map: dict) -> GlobalMap:
        """Parse global map entry from bpftool output"""
        # Handle list of entries
        if isinstance(global_map, list) and len(global_map) > 0:
            entry = global_map[0]
        else:
            entry = global_map

        # bpftool -j output has a 'formatted' field with parsed data
        if 'formatted' in entry:
            value = entry['formatted']['value']
        else:
            value = entry.get("value", entry)

        global_map_obj = GlobalMap(**value)
        return global_map_obj

    @staticmethod
    def parse_mac_ip_map_entry(mac_ip_map_entry: dict) -> MacIpMapEntry:
        """Parse MAC-IP map entry from bpftool output"""
        # bpftool -j output has a 'formatted' field with parsed data
        if 'formatted' in mac_ip_map_entry:
            key = mac_ip_map_entry['formatted']['key']
            value = mac_ip_map_entry['formatted']['value']
        else:
            key = mac_ip_map_entry["key"]
            value = mac_ip_map_entry["value"]

        mac_ip_key = MacIpKey(mac=key)
        mac_ip_value = MacIpValue(**value)
        mac_ip_map_entry_obj = MacIpMapEntry(key=mac_ip_key, value=mac_ip_value)
        return mac_ip_map_entry_obj