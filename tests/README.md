# Test Scripts

## Available Tests

- **test_python.sh** - Test Python modules without root (no eBPF required)
- **test_bpftool_working.sh** - Verify bpftool is working
- **check_maps.sh** - Check if BPF maps are loaded
- **fix_bpftool.sh** - Fix bpftool LLVM library issues

## Running Tests

### Test Python Code (No Root Required)
```bash
./test_python.sh
```

### Test bpftool
```bash
./test_bpftool_working.sh
```

### Check BPF Maps
```bash
./check_maps.sh
```

## Old Files

The `old_files/` directory contains the original Python scripts before reorganization:
- `bpf.py` - Original data collection script
- `bpf_map_scanner.py` - Original anomaly detection
- `bpf_visulize.py` - Original visualization

These are kept for reference only. Use the new scripts in `scripts/` instead.
