#!/usr/bin/env python3
import os 
import subprocess

def read_file():
    with open("/sys/kernel/debug/tracing/trace_pipe", "r") as trace:
      for line in trace:
        start_index = line.find("src_ip:")
        if start_index != -1:
          packet_information = line[start_index:]
          print(packet_information)


'''
packet exmaple 
src_ip:0.0.0.0,dest_ip:0.0.0.0,tot_len:108,ttl:64,protocol:TCP,data:000000004c0f8588
'''
def main():
    read_file()

if __name__ == "__main__":
  main()