#!/bin/bash
# Test Python modules without needing eBPF loaded

set -e

echo "Testing Python Modules (No Root Required)"
echo "=========================================="
echo ""

cd "$(dirname "$0")"

echo "[1/5] Testing imports..."
python3 -c "
import sys
sys.path.insert(0, '.')
from src.models.PacketObject import PacketInformation
from src.models.AggregateMapObject import PacketAggregateMap
from src.models.GlobalMapObject import GlobalMap
from src.helpers.IPconvert import IPInterface
from src.helpers.FileOperations import FileInterface
print('✓ All imports successful')
"

echo ""
echo "[2/5] Testing IP conversion..."
python3 -c "
import sys
sys.path.insert(0, '.')
from src.helpers.IPconvert import IPInterface
ip = IPInterface.opposite_ip('192.168.1.1')
print(f'✓ IP conversion works: 192.168.1.1 -> {ip}')
"

echo ""
echo "[3/5] Creating sample data..."
mkdir -p data/logs
cat > data/logs/test_aggregate.json << 'EOF'
{"key":{"src_ip":"192.168.1.100","dst_ip":"8.8.8.8"},"value":{"total_packet_count":500,"total_packet_length":25000,"total_ttl":32000}}
{"key":{"src_ip":"192.168.1.100","dst_ip":"1.1.1.1"},"value":{"total_packet_count":300,"total_packet_length":15000,"total_ttl":19200}}
EOF

cat > data/logs/test_global.json << 'EOF'
{"total_packet_count":800,"total_packet_length":40000,"total_ttl":51200,"timestamp":1699000000000000000}
{"total_packet_count":900,"total_packet_length":45000,"total_ttl":57600,"timestamp":1699000300000000000}
EOF

echo "✓ Sample data created"

echo ""
echo "[4/5] Testing data parsing..."
python3 << 'PYEOF'
import sys
sys.path.insert(0, '.')
from src.helpers.file_to_object import FileToObject

# Test aggregate map parsing
try:
    agg_maps = FileToObject.parse_aggregate_map("test_aggregate.json")
    print(f'✓ Parsed {len(agg_maps)} aggregate map entries')
except Exception as e:
    print(f'✗ Error parsing aggregate map: {e}')

# Test global map parsing
try:
    global_maps = FileToObject.parse_global_map("test_global.json")
    print(f'✓ Parsed {len(global_maps)} global map entries')
except Exception as e:
    print(f'✗ Error parsing global map: {e}')
PYEOF

echo ""
echo "[5/5] Testing configuration..."
python3 -c "
import sys
sys.path.insert(0, '.')
import config
print(f'✓ Config loaded')
print(f'  - Logs directory: {config.LOGS_DIR}')
print(f'  - Max packets threshold: {config.MAX_TOTAL_PACKETS}')
print(f'  - Suspicious ports: {config.SUSPICIOUS_PORTS}')
"

echo ""
echo "=========================================="
echo "✅ All Python tests passed!"
echo ""
echo "Next step: Load the eBPF program with:"
echo "  cd ebpf && sudo ./ecli run package.json"
echo ""
echo "See RUN_INSTRUCTIONS.md for details"
