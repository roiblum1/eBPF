#!/usr/bin/env python3
import json
import os 
from typing import Optional
from pydantic import BaseModel, ValidationInfo, field_validator
from bcc import BPF
import socket
from models.PacketObject import PacketInformation
from models.MapKeyObject import PacketMapKey

def bytes_to_ip(ip_in_bytes: bytes) -> str:
    ip_addr = socket.inet_ntoa(ip_in_bytes)
    return ip_addr

class PacketAggregate(BaseModel):
    total_packet_count: int
    total_packet_length: int
    total_ttl: int

    
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
                f.write(json.dumps(object.dict()) + "\n")
            print("Write the objects to file successfully.")
    except Exception as e:
        print(f"Error writing to file: {e}")
      
def read_maps():
    # Define the pin paths for your maps
    PIN_PATH = "/sys/fs/bpf/"  # Update this path based on your setup
    packet_map_path = os.path.join(PIN_PATH, "packet_map")
    packets_aggregate_map_path = os.path.join(PIN_PATH, "packets_aggregate_map")
    global_aggregate_data_path = os.path.join(PIN_PATH, "global_aggregate_data")

    dummy_program = """
    int dummy(void *ctx) {
        return 0;
    }
    """
    bpf = BPF(text=dummy_program)

    # Open the pinned maps using get_table
    packet_map = bpf.get_table("packet_map", packet_map_path)
    packets_aggregate_map = bpf.get_table("packets_aggregate_map", packets_aggregate_map_path)
    global_aggregate_map = bpf.get_table("global_aggregate_data", global_aggregate_data_path)

    print("Packet Map details ")
    for k, v in packet_map.items():
        print(f"{k}: {v}")
    
    print("Aggregate Map details ")
    for k, v in aggregate_map.items():
        print(f"{k}: {v}")
    
    print("Global Map details ")
    for k, v in global_map.items():
        print(f"{k}: {v}")
            

def main():
    packet_list = read_file_tracing()
    write_list_file(packet_list)
    print(packet_list)
    read_maps()
    
if __name__ == "__main__":
  main()