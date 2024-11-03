import os
import subprocess

class OSInterface():
    def get_map(map_path: str):
        command = fr"sudo bpftool map dump pinned {map_path}"
        output = subprocess.check_output(command, shell=True)
        return output.decode('utf-8')
    
    def remove_file(file_path:str):
        if os.path.exists(file_path):
            os.remove(file_path)
        else:
            print("File not found")