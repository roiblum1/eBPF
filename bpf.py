#!/usr/bin/env python3
import json
import os
import subprocess 
from bcc import BPF
import socket
from models.PacketObject import PacketInformation
from models.AggregateMapObject import PacketAggregate, PacketMapKey, PacketAggregateMap
from models.GlobalMapObject import GlobalMap
    
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
def write_list_file(object_list: list, file_name: str) -> None:
    """
    Writes a list of objects to a file in JSON format.

    :param object_list: A list of objects to be written to the file.
    :type object_list: list
    :param file_name: The name of the file to which the objects will be written.
    :type file_name: str
    :return: None
    :rtype: None

    This function takes a list of objects and a file name as input. It then writes each object in the list to the specified file in JSON format, with each object on a new line. If an error occurs during the writing process, an error message will be printed.
    """
    try:
        with open(file_name, "a") as f:
            for object in object_list:
                f.write(json.dumps(object.dict(), indent=4) + "\n")
            print("Write the objects to file successfully.")
    except Exception as e:
        print(f"Error writing to file: {e}")

def get_map(map_path: str):
    command = fr"sudo bpftool map dump pinned {map_path}"
    output = subprocess.check_output(command, shell=True)
    print(output.decode('utf-8'))
    return output.decode('utf-8')
    
    
def read_maps(): 
    packet_map_path = r"/sys/fs/bpf/packet_map"
    packets_aggregate_map_path = r"/sys/fs/bpf/packets_aggregate_map"
    global_aggregate_data_path = r"/sys/fs/bpf/global_aggregate_data"
    packet_map = get_map(packet_map_path)
    aggregate_map = get_map(packets_aggregate_map_path)
    global_map = get_map(global_aggregate_data_path)

    print("Packet Map details ")
    packets_maps = []  
    packet_map_dict = json.loads(packet_map)
    print(PacketMapKey(**packet_map_dict[0]["key"]))
    print(PacketInformation(**packet_map_dict[0]['value']))
        
    
def main():
    packet_list = read_file_tracing()
    write_list_file(packet_list, "packet_list.json")
    print(packet_list)
    read_maps()
    
if __name__ == "__main__":
  main()