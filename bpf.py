#!/usr/bin/env python3
import os 
import subprocess

def start_sniffing():
    
  with open('commands.txt', 'r') as f:
      commands = f.readlines()
      os.chdir(r"/home/nehfaf/dev")
      for command in commands:
        command = command.strip()
        ans = os.system(command)
        if ans == 0:
            print(f"{command} executed.")
        else:
            print(f"{command} failed.")
      
def main():
  print("Start Snifing ...")
  print("To stop enter ctrl+C") 
  start_sniffing()
if __name__ == "__main__":
  main()