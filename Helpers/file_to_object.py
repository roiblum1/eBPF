from models.AggregateMapObject import PacketAggregateMap, PacketMapKey, PacketAggregate
from models.GlobalMapObject import GlobalMap
import jsonlines

class FileToObject():
    def parse_aggregate_map(file_path:str):
        aggregate_maps = []
        with open(file_path, "r") as file:
            for map in jsonlines.Reader(file):
                packet_map_key = PacketMapKey(**map["key"])
                packet_aggregate = PacketAggregate(**map["value"])
                aggregate_map = PacketAggregateMap(key=packet_map_key, value=packet_aggregate)
                aggregate_maps.append(aggregate_map)
        return aggregate_maps
            
    def parse_global_map(file_path:str):
        with open(file_path, 'r') as file:
            for map in jsonlines.Reader(file):
                global_map = GlobalMap(**map)
            return global_map
print(FileToObject.parse_aggregate_map("logs/aggregate_map.json"))
FileToObject.parse_global_map("logs/global_map.json").visualize()