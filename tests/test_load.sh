#!/bin/bash
# Test script to load eBPF program
# Run this script with: sudo ./test_load.sh

set -e

echo "Testing eBPF Program Load"
echo "=========================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root"
    echo "Usage: sudo ./test_load.sh"
    exit 1
fi

# Change to ebpf directory
cd "$(dirname "$0")/ebpf"

echo "[1/4] Checking if package.json exists..."
if [ ! -f "package.json" ]; then
    echo "Error: package.json not found. Run ./build.sh first."
    exit 1
fi
echo "✓ package.json found"

echo ""
echo "[2/4] Checking network interfaces..."
ip link show | head -10

echo ""
echo "[3/4] Loading eBPF program..."
./ecli run package.json &
ECLI_PID=$!

echo "✓ eBPF program loaded (PID: $ECLI_PID)"

echo ""
echo "[4/4] Checking BPF maps..."
sleep 2
ls -la /sys/fs/bpf/ 2>/dev/null || echo "Maps not yet visible"

echo ""
echo "✓ eBPF program is running!"
echo ""
echo "To monitor traffic:"
echo "  - View trace: cat /sys/kernel/debug/tracing/trace_pipe"
echo "  - List maps: bpftool map list"
echo "  - Dump map: bpftool map dump pinned /sys/fs/bpf/packet_map"
echo ""
echo "Press Ctrl+C to stop..."

# Wait for the program to run
wait $ECLI_PID
