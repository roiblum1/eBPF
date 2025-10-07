#!/bin/bash
# Load and attach eBPF program

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "package.json" ]; then
    echo "Error: package.json not found. Run build.sh first."
    exit 1
fi

echo "Loading eBPF program (requires root)..."
sudo ./ecli run package.json

echo "✓ eBPF program loaded successfully!"
echo ""
echo "To view kernel trace output, run:"
echo "  sudo cat /sys/kernel/debug/tracing/trace_pipe"
