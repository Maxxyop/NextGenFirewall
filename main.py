#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NextGen Firewall with EDR and HIPS capabilities
Main entry point for the firewall agent
"""

import os
import sys
import time
import signal
import logging
import argparse
import threading
import setproctitle
from pathlib import Path

# Add the project root directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import firewall modules
from modules.dpi import DeepPacketInspector
from modules.edr import LinuxEDR
from modules.hips import HIPS
from modules.management import ManagementClient
from modules.utils import setup_logging, check_privileges, load_config

# Default configuration path
DEFAULT_CONFIG_PATH = 'C:\\Users\\godma\\nextgen_firewall\\modules\\config.yaml'

# Global variables
running = True
threads = []

def signal_handler(sig, frame):
    """Handle termination signals"""
    global running
    print("Received termination signal. Shutting down...")
    running = False
    # Signal all threads to stop
    for thread in threads:
        if hasattr(thread, 'stop') and callable(thread.stop):
            thread.stop()

def main():
    """Main entry point for the firewall agent"""

    # Argument parsing setup
    parser = argparse.ArgumentParser(description='NextGen Firewall with EDR and HIPS')
    parser.add_argument('-c', '--config', default=DEFAULT_CONFIG_PATH,
                        help='Path to the configuration file')
    parser.add_argument('-d', '--daemon', action='store_true',
                        help='Run as a background process')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose logging')
    args = parser.parse_args()  # This initializes 'args'

    # Check for root privileges
    if not check_privileges():
        sys.exit(1)

    # Load configuration
    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"Failed to load configuration: {str(e)}")
        sys.exit(1)

    # Debug: Print out the config loaded
    print("Loaded configuration:")
    print(config)

    # Setup logging using the config.yaml logging section
    try:
        # Fetch log level from config, default to INFO if not set
        log_level_str = config.get('logging', {}).get('level', 'INFO').upper()
        
        # Debug: Print the log level before trying to use it
        print(f"Log level from config: {log_level_str}")

        # Map string to logging module level
        log_level = getattr(logging, log_level_str, logging.INFO)
        
        # Debug: Print the resolved log level (integer value)
        print(f"Resolved log level: {log_level}")

        # Optionally fetch log file path
        log_path = config.get('logging', {}).get('log_file', None)
        
        # Initialize logging
        logger = setup_logging(log_level, log_path)
        logger.info(f"Configuration loaded from {args.config}")
    except Exception as e:
        print(f"Failed to set up logging: {str(e)}")
        sys.exit(1)

    # Set process title for better identification
    setproctitle.setproctitle("nextgen_firewall")

    # Register signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # For Windows, just run in the foreground (no daemon)
    if args.daemon and sys.platform != "win32":
        # Run as a daemon process on non-Windows systems
        pass  # You can add your `daemon` logic for Unix-based systems here
    else:
        # Run in the foreground (Windows or no daemon flag)
        run_firewall(config, logger)

def run_firewall(config, logger):
    """Initialize and run all firewall components"""
    global threads
    try:
        # Initialize the management client
        logger.info("Initializing management client...")
        management_client = ManagementClient(config.get('management', {}))
        threads.append(management_client)

        # Initialize the DPI module
        if config.get('dpi', {}).get('enabled', False):
            logger.info("Initializing Deep Packet Inspection module...")
            dpi = DeepPacketInspector(
                config.get('dpi', {}),
                management_client.queue_alert
            )
            threads.append(dpi)

        # Initialize the EDR module
        if config.get('edr', {}).get('enabled', False):
            logger.info("Initializing Endpoint Detection & Response module...")
            edr = LinuxEDR(
                config.get('edr', {}),
                management_client.queue_alert
            )
            threads.append(edr)

        # Initialize the HIPS module
        if config.get('hips', {}).get('enabled', False):
            logger.info("Initializing Host Intrusion Prevention System...")
            hips = HIPS(
                config.get('hips', {}),
                management_client.queue_alert
            )
            threads.append(hips)

        # Start all threads
        for thread in threads:
            thread.start()
            logger.debug(f"Started thread: {thread.__class__.__name__}")

        logger.info("NextGen Firewall is running")

        # Main loop - keep the program running until signaled to stop
        while running:
            time.sleep(1)
    except Exception as e:
        logger.error(f"Error in firewall operation: {str(e)}")
    finally:
        # Cleanup
        logger.info("Shutting down NextGen Firewall...")
        for thread in threads:
            if hasattr(thread, 'stop') and callable(thread.stop):
                thread.stop()

        # Wait for threads to finish
        for thread in threads:
            if thread.is_alive():
                thread.join(5)  # Wait up to 5 seconds for each thread

        logger.info("NextGen Firewall shutdown complete")

if __name__ == '__main__':
    main()
