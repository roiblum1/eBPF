#!/bin/bash
# Check if BPF maps are loaded (without bpftool)

echo "Checking BPF Maps..."
echo "===================="
echo ""

if [ ! -d "/sys/fs/bpf" ]; then
    echo "✗ /sys/fs/bpf directory not found"
    echo "  BPF filesystem may not be mounted"
    exit 1
fi

echo "BPF maps in /sys/fs/bpf:"
sudo ls -lh /sys/fs/bpf/ 2>/dev/null || echo "No maps found or permission denied"

echo ""
echo "Expected maps:"
echo "  - packet_map"
echo "  - packets_aggregate_map"
echo "  - global_aggregate_data"
echo "  - mac_ip_map"

echo ""
if sudo ls /sys/fs/bpf/packet_map >/dev/null 2>&1; then
    echo "✓ Maps are loaded!"
    echo ""
    echo "To read them, you need to:"
    echo "  1. Install LLVM: sudo pacman -S llvm"
    echo "  2. Or run: ./fix_bpftool.sh"
else
    echo "✗ Maps not found. Is the eBPF program running?"
    echo ""
    echo "Start it with:"
    echo "  cd ebpf && sudo -E ./ecli run package.json"
fi
