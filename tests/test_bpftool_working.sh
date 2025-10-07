#!/bin/bash
# Test if bpftool is working now

echo "Testing bpftool..."
echo "=================="
echo ""

echo "[1/2] Testing bpftool version:"
sudo bpftool version
echo ""

echo "[2/2] Testing if bpftool can list maps:"
if sudo bpftool map list 2>&1 | grep -q "Error"; then
    echo "⚠️  bpftool works but no maps loaded yet"
    echo ""
    echo "To load the eBPF program:"
    echo "  cd ebpf && sudo -E ./ecli run package.json"
else
    echo "✓ bpftool is working!"
fi

echo ""
echo "Now you can run:"
echo "  python3 scripts/collect_data.py"
chmod +x test_bpftool_working.sh
