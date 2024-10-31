#!/usr/bin/env python3
import os 
from typing import Optional
from pydantic import BaseModel
from bcc import BPF
import 

class PacketInformation(BaseModel):
    src_ip: str
    dest_ip: str
    tot_len: int
    ttl: int
    protocol: str
    data_length: Optional[int] = 0 
    data: str
    
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

def bytes_to_ip(ip_in_bytes):
    ip_addr = socket.inet_ntoa(ip_in_bytes)
    return ip_addr
def read_maps():
    packet_map = BPF.get_table("packet_map")
    aggregate_map = BPF.get_table("aggregate_map")
    global_map = BPF.get_table("global_map") 
        
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
    print(packet_list)
    read_maps()
    
if __name__ == "__main__":
  main()