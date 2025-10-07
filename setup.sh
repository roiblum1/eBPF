#!/bin/bash
# Setup script for eBPF Network Monitor

set -e

echo "eBPF Network Monitor - Setup"
echo "=============================="
echo ""

# Check Python version
echo "[1/4] Checking Python version..."
python3 --version || { echo "Error: Python 3 not found"; exit 1; }

# Install Python dependencies
echo ""
echo "[2/4] Installing Python dependencies..."
pip3 install -r requirements.txt || { echo "Error: Failed to install dependencies"; exit 1; }

# Build eBPF program
echo ""
echo "[3/4] Building eBPF program..."
cd ebpf
./build.sh || { echo "Error: Failed to build eBPF program"; exit 1; }
cd ..

# Create data directories
echo ""
echo "[4/4] Creating data directories..."
mkdir -p data/logs

echo ""
echo "✓ Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Load eBPF program:    cd ebpf && sudo ./load.sh"
echo "  2. Collect data:         python3 scripts/collect_data.py"
echo "  3. Detect anomalies:     python3 scripts/detect_anomalies.py"
echo "  4. Visualize:            python3 scripts/visualize.py"
echo ""
echo "See README.md for more information."
