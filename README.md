# eBPF Network Monitor

A real-time network packet monitoring and analysis system using eBPF for kernel-space packet capture and Python for user-space data processing, visualization, and anomaly detection.

## Features

- **Real-time TCP packet capture** using eBPF TC (Traffic Control) hooks
- **Statistical aggregation** of network traffic per IP pair
- **Anomaly detection** for traffic spikes, suspicious ports, and MAC spoofing
- **Data visualization** with matplotlib and tkinter
- **Security alerts** logged to file
- **Structured logging** with file and console output
- **Graceful shutdown** handling (Ctrl+C safe)
- **Configuration validation** on startup
- **Performance-optimized** batch BPF map reading

## Requirements

### System Requirements
- Linux kernel 5.8+ with eBPF support (`CONFIG_BPF_SYSCALL=y`)
- Root/sudo privileges for loading eBPF programs
- Python 3.8+

### Dependencies

Install Python dependencies:
```bash
pip install -r requirements.txt
```

Dependencies:
- `pydantic` - Data validation and parsing
- `matplotlib` - Data visualization
- `numpy` - Statistical analysis
- `jsonlines` - JSON logging
- `bcc` - BPF Compiler Collection

System packages (Arch Linux):
```bash
sudo pacman -S bpf llvm
```

## Quick Start

### 1. Build the eBPF Program

```bash
cd ebpf
./build.sh
```

**Expected output:**
```
Building eBPF program...
✓ Build successful! package.json created
```

### 2. Load the eBPF Program

**Terminal 1:**
```bash
cd ebpf
sudo -E ./ecli run package.json
```

**Expected output:**
```
INFO [bpf_loader_lib::skeleton::poller] Running ebpf program...
```

**Leave this terminal running!** Press Ctrl+C to stop.

### 3. Generate Network Traffic

**Terminal 2:**
```bash
# Generate some TCP traffic for the eBPF program to capture
curl https://google.com
curl https://github.com
curl https://archlinux.org
```

### 4. Collect and Analyze Data

**Terminal 3** (wait 30 seconds after step 2):
```bash
cd /path/to/eBPF
sudo python3 scripts/collect_data.py
```

**Expected output:**
```
eBPF Network Monitor - Data Collection
==================================================
Packet Map:
Success write the list to the file packets_maps.json
  Collected 8 packet entries
Aggregate Map:
Success write the list to the file aggregate_map.json
  Collected 8 aggregate entries
Global Map:
Success write the list to the file global_map.json
  Global statistics collected
MAC-IP Map:
Success write the list to the file mac_ip_map.json
  Collected 1 MAC-IP mappings

Collected 8 aggregate entries
Data saved to data/logs/
```

### 5. Detect Anomalies

```bash
sudo python3 scripts/detect_anomalies.py
```

Analyzes traffic patterns and detects statistical anomalies (spikes, suspicious ports, MAC spoofing).

### 6. Visualize Data

```bash
python3 scripts/visualize.py
```

Opens a GUI with options to:
- View aggregate traffic statistics (top flows)
- View global traffic over time

## Project Structure

```
eBPF/
├── README.md                  # Project documentation
├── CLAUDE.md                  # Developer reference (for AI assistants)
├── config.py                  # Centralized configuration
├── requirements.txt           # Python dependencies
├── setup.sh                   # Setup script
│
├── ebpf/                      # eBPF kernel-space programs
│   ├── main.c                 # TC ingress hook
│   ├── vmlinux.h              # Kernel type definitions
│   ├── ecc, ecli              # Compiler & loader (eunomia-bpf)
│   ├── build.sh               # Build script
│   └── load.sh                # Load script
│
├── src/                       # Python source package
│   ├── models/                # Pydantic data models
│   │   ├── PacketObject.py
│   │   ├── AggregateMapObject.py
│   │   ├── GlobalMapObject.py
│   │   └── MacIPObject.py
│   └── helpers/               # Utility modules
│       ├── OSFunctions.py     # BPF map access via bpftool
│       ├── IPconvert.py       # IP address conversion
│       ├── FileOperations.py  # File I/O and logging
│       ├── parse_to_object.py # Parse BPF output to objects
│       └── file_to_object.py  # Load saved JSON data
│
├── scripts/                   # Main entry point scripts
│   ├── collect_data.py        # Collect data from BPF maps
│   ├── detect_anomalies.py    # Anomaly detection
│   └── visualize.py           # GUI visualization
│
├── data/logs/                 # Output directory (created on first run)
│   ├── packets_maps.json      # Individual packet details
│   ├── aggregate_map.json     # Aggregated statistics per IP pair
│   ├── global_map.json        # Overall traffic statistics
│   ├── mac_ip_map.json        # MAC-to-IP associations
│   ├── alerts.txt             # Security alerts
│   └── monitor.log            # Application logs
│
├── tests/                     # Test scripts
└── old_files/                 # Archived original scripts
```

## Output Files

All output is saved to `data/logs/`:

### packets_maps.json
Latest packet information per IP pair:
```json
{
  "src_ip": "142.250.185.46",
  "dst_ip": "192.168.1.148",
  "src_port": 443,
  "dst_port": 34032,
  "tot_len": 40,
  "ttl": 55,
  "protocol": "TCP"
}
```

### aggregate_map.json
Cumulative statistics per IP pair:
```json
{
  "key": {
    "src_ip": "142.250.185.46",
    "dst_ip": "192.168.1.148"
  },
  "value": {
    "total_packet_count": 15,
    "total_packet_length": 780,
    "total_ttl": 825,
    "avg_ttl": 55.0
  }
}
```

### global_map.json
Overall traffic statistics with timestamp:
```json
{
  "total_packet_count": 120,
  "total_packet_length": 6240,
  "total_ttl": 7680,
  "timestamp": 1699000000000000000,
  "avg_ttl": 64.0
}
```

### alerts.txt
Security alerts:
```
192.168.1.148:56568 -> 142.250.185.46:443 packet is using remote control port!
Alert: Spike detected at 2024-10-07 20:14:23: 1500 packets
```

## Security Alerts

The system automatically detects and logs:

| Alert Type | Trigger | Description |
|-----------|---------|-------------|
| **Suspicious Ports** | SSH (22), TLS (443), RDP (3389) | Monitors remote control protocols |
| **High Traffic** | >100,000 packets per IP pair | Potential DoS or data exfiltration |
| **Traffic Spikes** | Mean + 3σ deviation | Statistical anomaly detection |
| **MAC Spoofing** | >2 IPs per MAC address | Potential ARP spoofing attack |

## Configuration

Edit `config.py` to customize:

```python
# Data paths
LOGS_DIR = PROJECT_ROOT / "data/logs"

# Logging
LOG_FILE = LOGS_DIR / "monitor.log"
LOG_LEVEL = logging.INFO

# Alert thresholds
MAX_TOTAL_PACKETS = 100000
SUSPICIOUS_PORTS = [22, 443, 3389]
MAX_IPS_PER_MAC = 2
SPIKE_THRESHOLD_MULTIPLIER = 3

# Gateway MAC addresses to ignore (avoids false positives)
IGNORED_MAC_ADDRESSES = [
    "68:aa:c4:30:ed:1f",  # Your gateway MAC - update this!
]

# eBPF settings
EBPF_INTERFACE_INDEX = 2  # wlan0
PROTOCOL = "TCP"
```

**Important:** Add your gateway's MAC address to `IGNORED_MAC_ADDRESSES` to avoid false MAC spoofing alerts. Find it with: `ip neigh show` or `arp -a`

Configuration is validated at startup and will exit with error messages if invalid values are detected.

## Logging

All scripts use structured logging with both file and console output:

- **Log File**: `data/logs/monitor.log`
- **Console**: Color-coded messages with timestamps
- **Levels**: INFO (default), WARNING, ERROR, DEBUG

View logs in real-time:
```bash
tail -f data/logs/monitor.log
```

## How It Works

### Data Flow

1. **Packet Capture**: eBPF TC hook intercepts TCP packets at interface level
2. **Kernel Storage**: Packets stored in 4 BPF hash maps (pinned to `/sys/fs/bpf/`)
3. **User-Space Collection**: Python scripts read maps via `bpftool`
4. **Analysis**: Statistical analysis and anomaly detection
5. **Output**: JSON logs and security alerts

### BPF Maps

| Map Name | Purpose |
|----------|---------|
| `packet_map` | Latest packet per IP pair |
| `packets_aggregate_map` | Cumulative stats per IP pair |
| `global_aggregate_data` | Overall traffic statistics |
| `mac_ip_map` | MAC-to-IP associations (max 10 IPs) |

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Permission denied" | Use `sudo` to load eBPF and collect data |
| "No packet data found" | eBPF program not running - start in Terminal 1 |
| "bpftool error" | Run `sudo pacman -S bpf llvm` |
| No packets captured | Generate traffic: `curl https://google.com` |
| Wrong interface | Edit `config.py` - change `EBPF_INTERFACE_INDEX` |
| Log file permission error | Run `sudo chown $USER:$USER data/logs/monitor.log` or delete the log file |
| Gateway MAC false alerts | Add your gateway MAC to `IGNORED_MAC_ADDRESSES` in `config.py` |

## Development

### Modifying eBPF Code

1. Edit `ebpf/main.c`
2. Rebuild: `cd ebpf && ./build.sh`
3. Reload: `sudo ./ecli run package.json`

### Modifying Python Code

1. Edit files in `src/` or `scripts/`
2. Re-run the script (no rebuild needed)

### Testing

```bash
# Test Python modules (no root required)
./tests/test_python.sh

# Test bpftool
./tests/test_bpftool_working.sh
```

## Technical Details

### eBPF Implementation

- **Hook Type**: TC (Traffic Control) ingress
- **Interface**: Configurable (default: index 2 - wlan0)
- **Protocol Filter**: TCP only
- **Map Pinning**: `LIBBPF_PIN_BY_NAME` for user-space access

### IP Address Handling

- eBPF stores IPs in network byte order (big-endian)
- Python helpers convert between formats
- Use `opposite_ip()` to reverse byte order when needed

### Verifier Constraints

- All loops bounded (see `IP_LIST_MAX_SIZE = 10`)
- No unbounded recursion or function pointers
- Limited string operations (use `strcpy` not `strncpy`)

## License

GPL (required for eBPF programs)

## Credits

Built using:
- **eunomia-bpf** toolchain for eBPF compilation
- **libbpf** for BPF program loading
- **bpftool** for BPF map inspection
- **pydantic** for data validation

## Recent Improvements

### Version 1.0.0
- ✅ **Logging framework** - Structured logging with file and console output
- ✅ **Graceful shutdown** - Proper Ctrl+C handling in all scripts
- ✅ **Config validation** - Validates all settings on startup
- ✅ **Performance** - Batched BPF map reading (4 calls → 1)
- ✅ **MAC filtering** - Gateway MAC ignore list to avoid false positives
- ✅ **Visualization redesign** - Professional dashboard-style charts

### Visualization Features
- **Aggregate Map**: 6-panel dashboard with top flows, traffic volume, TTL, packet size, and pie chart
- **Global Map**: Clean 2×3 layout with metric cards and time-series charts
- **Professional styling**: Color-coded charts, value labels, summary statistics

## See Also

- [CLAUDE.md](CLAUDE.md) - Developer reference for AI assistants
