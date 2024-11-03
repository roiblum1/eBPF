import json
from models.AggregateMapObject import PacketAggregateMap
class FileInterface():
    def write_list_file(object_list: list, file_name: str) -> None:
        try:
            path = rf"logs/{file_name}"
            with open(path, "a") as f:
                for object in object_list:
                    f.write(json.dumps(object.dict(), indent=4) + "\n")
                print("Write the objects to file successfully.")
        except Exception as e:
            print(f"Error writing to file: {e}")
    
    def write_alert_log(packet_aggregate_map:PacketAggregateMap):
        PATH = rf"logs/alerts.txt"
        with open(PATH, "a") as file:
            file.write(f"{packet_aggregate_map.key.src_ip} -> {packet_aggregate_map.key.dst_ip} is reaching the max total packet and reach to {packet_aggregate_map.value.total_packet_count} \n")