#!/bin/bash
# Fix bpftool LLVM dependency issue

echo "Fixing bpftool LLVM dependency..."
echo "=================================="
echo ""

# Detect OS
if [ -f /etc/arch-release ]; then
    echo "Detected Arch Linux"
    echo "Installing LLVM libraries..."
    sudo pacman -S --noconfirm llvm llvm-libs

elif [ -f /etc/debian_version ]; then
    echo "Detected Debian/Ubuntu"
    echo "Installing LLVM libraries..."
    sudo apt update
    sudo apt install -y llvm libllvm18

elif [ -f /etc/fedora-release ]; then
    echo "Detected Fedora"
    echo "Installing LLVM libraries..."
    sudo dnf install -y llvm llvm-libs

else
    echo "Unknown distribution. Please install LLVM manually:"
    echo "  - Arch: sudo pacman -S llvm"
    echo "  - Ubuntu/Debian: sudo apt install llvm"
    echo "  - Fedora: sudo dnf install llvm"
    exit 1
fi

echo ""
echo "Testing bpftool..."
if sudo bpftool version 2>/dev/null; then
    echo "✓ bpftool is working!"
else
    echo "✗ bpftool still has issues. You may need to:"
    echo "  1. Update your system: sudo pacman -Syu"
    echo "  2. Reinstall bpftool: sudo pacman -S bpf"
fi

echo ""
echo "You can now run: python3 scripts/collect_data.py"
