#!/usr/bin/env python3
import json
import os 
from bcc import BPF
import socket
from models.PacketObject import PacketInformation
from models.AggregateMapObject import PacketAggregate, PacketMapKey, PacketAggregateMap
from models.GlobalMapObject import GlobalMap

def bytes_to_ip(ip_in_bytes: bytes) -> str:
    ip_addr = socket.inet_ntoa(ip_in_bytes)
    return ip_addr
    
def read_file_tracing():
    print("Started capturing.\nPress ctrl+c to stop...")
    packet_list = []
    try:
      with open("/sys/kernel/debug/tracing/trace_pipe", "r") as trace:
        for line in trace:
          start_index = line.find("src_ip:")
          if start_index != -1:
            packet_information = line[start_index:].strip()
            fields = packet_information.split(',')
            packet_information = {}
            for field in fields:
                data = field.split(':')
                if len(data) == 2:
                  attribute = data[0]
                  value = data[1]
                  packet_information[attribute] = value
            packet_object = PacketInformation(**packet_information)
            packet_list.append(packet_object)
    except KeyboardInterrupt:
        print("\nStoppped Capturing")
        return packet_list
'''
packet example 
src_ip:0.0.0.0,dest_ip:0.0.0.0,tot_len:108,ttl:64,protocol:TCP,data:000000004c0f8588
'''
def write_list_file(object_list: list, file_name: str):
    try:
        with open(file_name, "a") as f:
            for object in object_list:
                f.write(json.dumps(object.dict(), indent=4) + "\n")
            print("Write the objects to file successfully.")
    except Exception as e:
        print(f"Error writing to file: {e}")
      
def read_maps(): 
    packet_map_path = r"/sys/fs/bpf/packet_map"
    packets_aggregate_map_path = r"/sys/fs/bpf/packets_aggregate_map"
    global_aggregate_data_path = r"/sys/fs/bpf/global_aggregate_data"

    dummy_program = """
    int dummy(void *ctx) {
        return 0;
    }
    """
    
    bpf = BPF(text=dummy_program)
    packet_map = bpf.get_table("packet_map", packet_map_path)
    aggregate_map = bpf.get_table("packets_aggregate_map", packets_aggregate_map_path)
    global_map = bpf.get_table("global_aggregate_data", global_aggregate_data_path)

    print("Packet Map details ")
    packets_maps = []  
    for k, v in packet_map.items():
        packet_info = PacketInformation(**v)
        packets_maps.append(packet_info)
        print(f"{k}: {v}")
    
    print("Aggregate Map details ")
    for k, v in aggregate_map.items():
        print(f"{k}: {v}")
    
    print("Global Map details ")
    for k, v in global_map.items():
        print(f"{k}: {v}")
            

def main():
    packet_list = read_file_tracing()
    write_list_file(packet_list, "packet_list.json")
    print(packet_list)
    read_maps()
    
if __name__ == "__main__":
  main()