import jsonlines
from pathlib import Path

from src.models.AggregateMapObject import PacketAggregateMap, PacketMapKey, PacketAggregate
from src.models.GlobalMapObject import GlobalMap
from config import LOGS_DIR

class FileToObject():
    @staticmethod
    def parse_aggregate_map(file_name: str = "aggregate_map.json"):
        """Parse aggregate map from JSON lines file"""
        file_path = LOGS_DIR / file_name
        aggregate_maps = []
        with open(file_path, "r") as file:
            for map in jsonlines.Reader(file):
                packet_map_key = PacketMapKey(**map["key"])
                packet_map_key.reverse_ips()
                packet_aggregate = PacketAggregate(**map["value"])
                aggregate_map = PacketAggregateMap(key=packet_map_key, value=packet_aggregate)
                aggregate_maps.append(aggregate_map)
        return aggregate_maps

    @staticmethod
    def parse_global_map(file_name: str = "global_map.json", max_entries: int = 288):
        """Parse global map from JSON lines file and trim to max_entries"""
        file_path = LOGS_DIR / file_name
        global_maps = []
        with open(file_path, 'r') as file:
            for map_entry in jsonlines.Reader(file):
                global_map = GlobalMap(**map_entry)
                global_maps.append(global_map)
        if len(global_maps) > max_entries:
            global_maps = global_maps[-max_entries:]
            with open(file_path, 'w') as file:
                for global_map in global_maps:
                    file.write(global_map.model_dump_json() + '\n')
        return global_maps
        