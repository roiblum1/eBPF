#!/bin/bash
# Build script for eBPF program

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building eBPF program..."
./ecc main.c

if [ -f "package.json" ]; then
    echo "✓ Build successful! package.json created"
    echo ""
    echo "To load the program, run:"
    echo "  sudo ./ecli run package.json"
else
    echo "✗ Build failed!"
    exit 1
fi
