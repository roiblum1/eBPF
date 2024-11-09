import json
from models.AggregateMapObject import PacketAggregateMap
from models.PacketObject import PacketInformation
from models.MacIPObject import MacIpKey, MacIpValue, MacIpMapEntry 
import jsonlines

class FileInterface():
    def write_list_file(object_list: list, file_name: str) -> None:
        try:
            path = rf"/home/nehfaf/dev/logs/{file_name}"
            letter = 'w'
            if(file_name == "global_map.json"):
                letter = 'a'
            with jsonlines.open(path, letter) as writer:
                for obj in object_list:
                    writer.write(obj.dict())
                print(f"Success write the list to the file {file_name}")
        except Exception as e:
            print(f"Error writing to file: {e}")
    
    def write_alert_log(packet_aggregate_map:PacketAggregateMap, file_name:str = "alerts.txt"):
        PATH = rf"/home/nehfaf/dev/logs/{file_name}"
        with open(PATH, "a") as file:
            file.write(f"{packet_aggregate_map.key.src_ip} -> {packet_aggregate_map.key.dst_ip} is reaching the max total packet and reach to {packet_aggregate_map.value.total_packet_count} \n")
            
    def alert_port_log(packet_map: PacketInformation, file_name: str = "alerts.txt"):
        PATH = rf"/home/nehfaf/dev/logs/{file_name}"
        with open(PATH, "a") as file:
            file.write(f"{packet_map.src_ip}:{packet_map.src_port} -> {packet_map.dest_ip}:{packet_map.dst_port} packet is using remote control port ! \n")
    
    def alert_mac_ip_log(mac_ip_entry: MacIpMapEntry):
        alert_message = f"Alert: MAC address {mac_ip_entry.key.mac} is associated with multiple IPs: {', '.join(mac_ip_entry.value.ips)}"
        with open("alerts.txt", "a") as f:
            f.write(alert_message + "\n")
            
    def alert_spike(last_time, last_count):
        alert_message = f"Alert: Spike detected at {last_time}: {last_count} packets"
        with open("alerts.txt", "a") as f:
            f.write(alert_message + "\n")