import json
from models.AggregateMapObject import PacketAggregateMap
import jsonlines

class FileInterface():
    def write_list_file(object_list: list, file_name: str) -> None:
        try:
            path = rf"/home/nehfaf/dev/logs/{file_name}"
            with jsonlines.open(path, 'a') as writer:
                for obj in object_list:
                    writer.write(obj.dict())
                print(f"Success write the list to the file {file_name}")
        except Exception as e:
            print(f"Error writing to file: {e}")
    
    def write_alert_log(packet_aggregate_map:PacketAggregateMap, file_name:str = "alerts.txt"):
        PATH = rf"/home/nehfaf/dev/logs/{file_name}"
        with open(PATH, "a") as file:
            file.write(f"{packet_aggregate_map.key.src_ip} -> {packet_aggregate_map.key.dst_ip} is reaching the max total packet and reach to {packet_aggregate_map.value.total_packet_count} \n")