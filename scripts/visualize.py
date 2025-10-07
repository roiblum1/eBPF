#!/usr/bin/env python3
"""
Script to visualize network traffic data
"""
import sys
import signal
import logging
from pathlib import Path
import tkinter as tk

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.models.AggregateMapObject import visualizeAggregateMap
from src.helpers.file_to_object import FileToObject
from src.models.GlobalMapObject import visualize_global_map
from config import VERSION

# Setup logging
logger = logging.getLogger(__name__)

# Global flag for graceful shutdown
shutdown_requested = False


def signal_handler(sig, frame):
    """Handle shutdown signals gracefully"""
    global shutdown_requested
    shutdown_requested = True
    logger.info("Shutdown signal received, closing application...")
    sys.exit(0)


def open_visualize_aggregate():
    """Open aggregate map visualization"""
    try:
        logger.info("Loading aggregate map data...")
        aggregate_maps = FileToObject.parse_aggregate_map()
        if not aggregate_maps:
            logger.warning("No aggregate map data found")
            return
        logger.info(f"Visualizing {len(aggregate_maps)} aggregate entries")
        visualizeAggregateMap(aggregate_maps)
    except FileNotFoundError:
        logger.error("aggregate_map.json not found. Run collect_data.py first.")
    except Exception as e:
        logger.error(f"Error visualizing aggregate map: {e}", exc_info=True)


def open_visualize_global():
    """Open global map visualization"""
    try:
        logger.info("Loading global map data...")
        global_map = FileToObject.parse_global_map()
        if not global_map:
            logger.warning("No global map data found")
            return
        logger.info(f"Visualizing {len(global_map)} global entries")
        visualize_global_map(global_map)
    except FileNotFoundError:
        logger.error("global_map.json not found. Run collect_data.py first.")
    except Exception as e:
        logger.error(f"Error visualizing global map: {e}", exc_info=True)


def main():
    """Main entry point - create GUI"""
    # Setup signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info("=" * 50)
    logger.info(f"eBPF Network Monitor v{VERSION} - Visualization")
    logger.info("=" * 50)

    try:
        root = tk.Tk()
        root.title(f"eBPF Network Monitor v{VERSION} - Visualization")
        root.geometry("400x200")

        # Title label
        title = tk.Label(root, text="Network Traffic Visualization", font=("Arial", 14, "bold"))
        title.pack(pady=20)

        # Button frame
        button_frame = tk.Frame(root)
        button_frame.pack(pady=20)

        # Buttons
        button1 = tk.Button(
            button_frame,
            text="View Aggregate Map",
            command=open_visualize_aggregate,
            width=20,
            height=2
        )
        button1.pack(side=tk.LEFT, padx=10)

        button2 = tk.Button(
            button_frame,
            text="View Global Map",
            command=open_visualize_global,
            width=20,
            height=2
        )
        button2.pack(side=tk.RIGHT, padx=10)

        # Info label
        info = tk.Label(root, text="Make sure to run collect_data.py first", font=("Arial", 9), fg="gray")
        info.pack(pady=10)

        logger.info("GUI initialized, starting main loop")
        root.mainloop()

    except Exception as e:
        logger.error(f"Fatal error in visualization: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logger.info("Exiting gracefully")


if __name__ == "__main__":
    main()
