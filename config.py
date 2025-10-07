"""
Configuration file for eBPF network monitor
"""
import os
import sys
import logging
from pathlib import Path

# Version
VERSION = "1.0.0"

# Project root directory
PROJECT_ROOT = Path(__file__).parent.absolute()

# Data directories
DATA_DIR = PROJECT_ROOT / "data"
LOGS_DIR = DATA_DIR / "logs"

# Ensure directories exist
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Logging configuration
LOG_FILE = LOGS_DIR / "monitor.log"
LOG_LEVEL = logging.INFO
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Setup logging
def setup_logging():
    """Configure logging for the application"""
    # Create formatters
    formatter = logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT)

    # Console handler (always works)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(LOG_LEVEL)
    console_handler.setFormatter(formatter)

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(LOG_LEVEL)
    root_logger.addHandler(console_handler)

    # File handler (may fail due to permissions, that's OK)
    try:
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setLevel(LOG_LEVEL)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    except (PermissionError, OSError) as e:
        # If we can't write to log file, just log to console
        # This is expected for non-root users with root-owned log files
        root_logger.warning(f"Could not open log file {LOG_FILE}: {e}. Logging to console only.")

    return root_logger

# Initialize logging
logger = setup_logging()

# BPF map paths
BPF_MAP_DIR = "/sys/fs/bpf"
PACKET_MAP_PATH = f"{BPF_MAP_DIR}/packet_map"
PACKETS_AGGREGATE_MAP_PATH = f"{BPF_MAP_DIR}/packets_aggregate_map"
GLOBAL_AGGREGATE_DATA_PATH = f"{BPF_MAP_DIR}/global_aggregate_data"
MAC_IP_MAP_PATH = f"{BPF_MAP_DIR}/mac_ip_map"

# Kernel tracing
TRACE_PIPE_PATH = "/sys/kernel/debug/tracing/trace_pipe"

# Alert thresholds
MAX_TOTAL_PACKETS = 100000
SUSPICIOUS_PORTS = [22, 443, 3389]  # SSH, TLS, RDP
MAX_IPS_PER_MAC = 2
SPIKE_THRESHOLD_MULTIPLIER = 3

# Gateway/Router MAC addresses to ignore in MAC-IP anomaly detection
# Add your gateway MAC address here (format: "aa:bb:cc:dd:ee:ff")
# These MACs will legitimately have many IPs due to routing
IGNORED_MAC_ADDRESSES = [
    "68:aa:c4:30:ed:1f",  # Default gateway - add yours here
]

# eBPF configuration
EBPF_INTERFACE_INDEX = 2
PROTOCOL = "TCP"


# Configuration Validation
def validate_config():
    """
    Validate configuration values at startup

    Raises:
        ValueError: If any configuration value is invalid
    """
    errors = []

    # Validate interface index
    if not (0 < EBPF_INTERFACE_INDEX < 256):
        errors.append(f"Invalid EBPF_INTERFACE_INDEX: {EBPF_INTERFACE_INDEX} (must be 1-255)")

    # Validate protocol
    if PROTOCOL not in ["TCP", "UDP"]:
        errors.append(f"Invalid PROTOCOL: {PROTOCOL} (must be 'TCP' or 'UDP')")

    # Validate thresholds
    if MAX_TOTAL_PACKETS <= 0:
        errors.append(f"Invalid MAX_TOTAL_PACKETS: {MAX_TOTAL_PACKETS} (must be > 0)")

    if MAX_IPS_PER_MAC <= 0:
        errors.append(f"Invalid MAX_IPS_PER_MAC: {MAX_IPS_PER_MAC} (must be > 0)")

    if SPIKE_THRESHOLD_MULTIPLIER <= 0:
        errors.append(f"Invalid SPIKE_THRESHOLD_MULTIPLIER: {SPIKE_THRESHOLD_MULTIPLIER} (must be > 0)")

    # Validate ports
    for port in SUSPICIOUS_PORTS:
        if not (0 < port <= 65535):
            errors.append(f"Invalid port in SUSPICIOUS_PORTS: {port} (must be 1-65535)")

    # Validate paths exist
    if not Path(BPF_MAP_DIR).exists():
        errors.append(f"BPF_MAP_DIR does not exist: {BPF_MAP_DIR} (is BPF filesystem mounted?)")

    if errors:
        error_msg = "Configuration validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
        logger.error(error_msg)
        raise ValueError(error_msg)

    logger.info("Configuration validation passed")

# Validate on import
try:
    validate_config()
    logger.info(f"eBPF Network Monitor v{VERSION} - Configuration loaded")
except ValueError as e:
    logger.critical("Failed to load configuration - exiting")
    sys.exit(1)
