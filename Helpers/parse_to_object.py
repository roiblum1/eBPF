from models.PacketObject import PacketInformation
from models.AggregateMapObject import PacketAggregate, PacketMapKey, PacketAggregateMap
from models.GlobalMapObject import GlobalMap
from models.MacIPObject import MacIpKey, MacIpValue, MacIpMapEntry 
from Helpers.IPconvert import IPInterface
from typing import Optional
class ParseToObject(): 
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
                    packet_information_dict[attribute] = value
                else:
                    print(f"Could not parse field '{field}' in packet: {line}")
                    return None
            return PacketInformation(**packet_information_dict)
        else:
            return None



    def parse_packet_map(packet_map: dict) -> PacketInformation:
        value = packet_map["value"]
        return PacketInformation(**value)

    
    def parse_aggregate_map(aggregate_map: dict) -> PacketAggregateMap:
        key = aggregate_map["key"]
        value = aggregate_map["value"]
        packet_map_key = PacketMapKey(**key)
        packet_aggregate = PacketAggregate(**value)
        packet_aggregate_map = PacketAggregateMap(key=packet_map_key, value=packet_aggregate)
        return packet_aggregate_map
    
    def parse_global_map(global_map:dict)->GlobalMap:
        key = global_map[0]["key"]
        value = global_map[0]["value"]
        global_map_obj = GlobalMap(**value)
        return global_map_obj
    
    def parse_mac_ip_map_entry(mac_ip_map_entry: dict) -> MacIpMapEntry:
        key = mac_ip_map_entry["key"]
        value = mac_ip_map_entry["value"]
        mac_ip_key = MacIpKey(mac=key)
        mac_ip_value = MacIpValue(**value)
        mac_ip_map_entry_obj = MacIpMapEntry(key=mac_ip_key, value=mac_ip_value)
        return mac_ip_map_entry_obj