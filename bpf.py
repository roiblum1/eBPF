#!/usr/bin/env python3
import json
from models.PacketObject import PacketInformation
from models.AggregateMapObject import PacketAggregate, PacketMapKey, PacketAggregateMap, visualizeAggregateMap
from models.GlobalMapObject import GlobalMap
from Helpers.IPconvert import IPInterface
from Helpers.FileOperations import FileInterface
from Helpers.OSFunctions import OSInterface
from Helpers.parse_to_object import ParseToObject

def read_file_tracing():
    print("Started capturing.\nPress ctrl+c to stop...")
    packet_list = []
    try:
      with open("/sys/kernel/debug/tracing/trace_pipe", "r") as trace:
        for line in trace:
            packet_object = ParseToObject.parse_trace(line)
            if (packet_object):
                packet_list.append(packet_object)
    except KeyboardInterrupt:
        print("\nStoppped Capturing")
        return packet_list
'''
packet example 
src_ip:0.0.0.0,dest_ip:0.0.0.0,tot_len:108,ttl:64,protocol:TCP,data:000000004c0f8588
'''
    
def read_maps(): 
    MAX_Total_Packet = 100000
    packet_map_path = r"/sys/fs/bpf/packet_map"
    packets_aggregate_map_path = r"/sys/fs/bpf/packets_aggregate_map"
    global_aggregate_data_path = r"/sys/fs/bpf/global_aggregate_data"
    packet_map = OSInterface.get_map(packet_map_path)
    aggregate_map = OSInterface.get_map(packets_aggregate_map_path)
    global_map = OSInterface.get_map(global_aggregate_data_path)

    print("Packet Map: ")
    packets_maps = []  
    packet_map_dicts = json.loads(packet_map)
    for map in packet_map_dicts:
        packet_map = ParseToObject.parse_packet_map(map)
        packet_map["dest_ip"] = IPInterface.opposite_ip(packet_map["dest_ip"])
        packets_maps.append(packet_map)
    FileInterface.write_list_file(packets_maps, "packets_maps.json")
    
    print("Aggregate Map:")
    aggregate_maps = []
    aggregate_map_dict = json.loads(aggregate_map)
    for map in aggregate_map_dict:
        packet_aggregate_map = ParseToObject.parse_aggregate_map(map)
        if(packet_aggregate_map.value.total_packet_count > MAX_Total_Packet):
            FileInterface.write_alert_log(packet_aggregate_map)
        aggregate_maps.append(packet_aggregate_map)
    FileInterface.write_list_file(aggregate_maps, "aggregate_map.json")
    
    print("Global Map:")
    global_map_dict = json.loads(global_map)
    key = global_map_dict[0]["key"]
    value = global_map_dict[0]["value"]
    global_map = GlobalMap(**value)
    OSInterface.remove_file("logs/global_map.json")
    FileInterface.write_list_file([global_map], "global_map.json") 
    return aggregate_maps, global_map


def main():
    packet_list = read_file_tracing()
    FileInterface.write_list_file(packet_list, "packet_list.json")
    aggregate_maps, global_map = read_maps()
    visualizeAggregateMap(aggregate_maps)
    global_map.visualize()
    
if __name__ == "__main__":
  main()