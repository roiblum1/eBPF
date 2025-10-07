# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an eBPF-based network packet monitoring and analysis system that captures TCP packets, aggregates statistics, and provides visualization and anomaly detection capabilities. The project combines kernel-space eBPF programs (C) with user-space Python applications for data processing and visualization.

## Architecture

### Core Components

**Kernel Space (eBPF):**
- [ebpf/main.c](ebpf/main.c) - TC (Traffic Control) ingress hook that captures TCP packets at the network interface level
- Compiles to `main.bpf.o` using eunomia-bpf toolchain (ecc/ecli)
- Uses BPF maps (hash tables) to store packet data, aggregated statistics, global metrics, and MAC-to-IP mappings

**User Space (Python):**
- [scripts/collect_data.py](scripts/collect_data.py) - Main data collection script that reads from BPF maps
- [scripts/detect_anomalies.py](scripts/detect_anomalies.py) - Anomaly detection using statistical spike analysis
- [scripts/visualize.py](scripts/visualize.py) - Tkinter GUI for visualizing aggregate and global statistics

### Data Flow

1. **Packet Capture**: eBPF TC hook intercepts TCP packets at interface level (ifindex 2)
2. **Data Storage**: Packets are stored in 4 pinned BPF maps:
   - `packet_map` - Latest packet details per IP pair
   - `packets_aggregate_map` - Cumulative statistics per IP pair (count, length, TTL)
   - `global_aggregate_data` - Overall traffic statistics with timestamps
   - `mac_ip_map` - MAC address to IP address associations (max 10 IPs per MAC)
3. **User Space Processing**: Python scripts read maps via `/sys/fs/bpf/` and parse JSON output
4. **Analysis & Alerts**: Detects anomalies (packet spikes, suspicious ports, MAC spoofing) and writes to `alerts.txt`

### Directory Structure

- **config.py** - Centralized configuration (paths, thresholds, BPF map locations)
- **ebpf/** - eBPF kernel-space programs
  - `main.c` - TC ingress hook
  - `vmlinux.h` - Kernel type definitions
  - `ecc` / `ecli` - Compiler and loader executables
  - `build.sh` / `load.sh` - Build and load scripts
- **src/** - Python source code organized as a package
  - **models/** - Pydantic data models (PacketObject, AggregateMapObject, GlobalMapObject, MacIPObject)
  - **helpers/** - Utility modules (OSFunctions, IPconvert, FileOperations, parse_to_object, file_to_object)
- **scripts/** - Executable entry point scripts
  - `collect_data.py` - Collect data from BPF maps
  - `detect_anomalies.py` - Statistical anomaly detection
  - `visualize.py` - GUI visualization
- **data/logs/** - Output directory for JSON logs and alerts

## Build & Development Commands

### eBPF Compilation
```bash
# Build eBPF program
cd ebpf
./build.sh

# Load and attach eBPF program (requires root)
sudo ./load.sh
```

### Running the System

```bash
# Collect data from BPF maps
python3 scripts/collect_data.py

# Detect anomalies in traffic
python3 scripts/detect_anomalies.py

# Visualize statistics
python3 scripts/visualize.py

# Monitor kernel trace output (optional, in separate terminal)
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### Development Workflow
1. **eBPF changes**: Edit [ebpf/main.c](ebpf/main.c), then `cd ebpf && ./build.sh && sudo ./load.sh`
2. **Python changes**: Edit files in `src/` or `scripts/`, then re-run the script
3. **Configuration**: Edit [config.py](config.py) to change paths, thresholds, or settings

## Key Technical Details

### eBPF Map Pinning
All maps use `LIBBPF_PIN_BY_NAME` to persist in `/sys/fs/bpf/` so user-space programs can access them after the eBPF program loads.

### IP Address Handling
- eBPF stores IPs in network byte order (big-endian)
- Python helpers in `IPconvert.py` convert between formats
- Use `opposite_ip()` to reverse byte order when needed

### Alert Triggers
- **Port monitoring**: SSH (22), TLS (443), RDP (3389) trigger `alert_port_log`
- **Volume anomalies**: >100k packets per IP pair trigger `write_alert_log`
- **Traffic spikes**: Statistical detection (mean + 3σ) in `detect_spikes()`
- **MAC spoofing**: Single MAC associated with >2 IPs triggers `alert_mac_ip_log`

### Path Configuration
All paths are now centralized in [config.py](config.py). Data is written to `data/logs/` by default. Modify `config.py` to change output locations or BPF map paths.

### Dependencies
Install via: `pip install -r requirements.txt`
- **bcc** - BPF Compiler Collection (for bpftool wrapper)
- **pydantic** - Data validation models
- **matplotlib** - Visualization
- **numpy** - Statistical analysis
- **jsonlines** - Append-mode JSON logging

## Important Constraints

### eBPF Verifier Limitations
- All loops must be bounded (see `IP_LIST_MAX_SIZE = 10`)
- Cannot use unbounded recursion or function pointers
- String operations limited (use `strcpy` not `strncpy`)
- Bounded array access required for verifier proof

### TC Hook Specifics
- Attached to interface index 2 (`ifindex:2`) at `BPF_TC_INGRESS`
- Only TCP packets processed (filtered by `PROTOCOL` macro)
- Must return `TC_ACT_OK` to allow packet continuation

### Testing Considerations
- Requires root/CAP_BPF privileges to load eBPF programs
- Need network traffic on interface 2 to generate data
- Use `bpf_printk()` for kernel-space debugging (appears in trace_pipe)
