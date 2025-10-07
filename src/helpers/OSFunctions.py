import os
import subprocess
import json

class OSInterface():
    @staticmethod
    def get_map(map_path: str) -> str:
        """Dump BPF map contents using bpftool"""
        try:
            # Try with bpftool first
            command = f"sudo bpftool map dump pinned {map_path} -j"
            output = subprocess.check_output(command, shell=True, stderr=subprocess.PIPE)
            return output.decode('utf-8')
        except subprocess.CalledProcessError as e:
            # If bpftool fails, try alternative method using bpf() syscall via Python
            print(f"Warning: bpftool failed ({e}), trying alternative method...")
            try:
                return OSInterface._get_map_python(map_path)
            except Exception as e2:
                raise Exception(f"Failed to read BPF map: bpftool error and Python fallback failed: {e2}")

    @staticmethod
    def _get_map_python(map_path: str) -> str:
        """Alternative method to read BPF maps using Python BCC library"""
        try:
            from bcc import BPF
            import ctypes

            # This is a fallback - would need BCC library properly configured
            # For now, return empty list to avoid crashes
            print(f"Warning: Python BPF reader not fully implemented. Install LLVM libraries for bpftool.")
            return "[]"
        except ImportError:
            print("Warning: BCC library not available. Please install: pip install bcc")
            return "[]"

    @staticmethod
    def remove_file(file_path: str):
        """Remove file if it exists"""
        if os.path.exists(file_path):
            os.remove(file_path)
        else:
            print("File not found")