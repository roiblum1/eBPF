from models.PacketObject import PacketInformation
from models.AggregateMapObject import PacketAggregate, PacketMapKey, PacketAggregateMap
from models.GlobalMapObject import GlobalMap
from Helpers.IPconverte import IPInterface

class ParseToObject(): 
    def parse_trace(line: str) -> PacketInformation:
        start_index = line.find("src_ip:")
        if start_index != -1:
            packet_information = line[start_index:].strip()
            fields = packet_information.split(',')
            packet_information_dict = {}
            for field in fields:
                data = field.split(':')
                if len(data) == 2:
                    attribute = data[0].strip()
                    value = data[1].strip()
                    packet_information_dict[attribute] = value
                else:
                    print(f"Could not parse field '{field}' in packet: {line}")
                    return None
            packet_object = PacketInformation(**packet_information_dict)
            return packet_object
        else:
            return None

    def parse_packet_map(packet_map: dict) -> PacketInformation:
        key = packet_map["key"]
        value = packet_map["value"]
        value["dest_ip"] = IPInterface.converte_ip_str(value["dst_ip"])
        value["data"] = ""
        return PacketInformation(**packet_map["value"])
    
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
        global_map = GlobalMap(**value)
        return global_map 
        