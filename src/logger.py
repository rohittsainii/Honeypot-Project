# src/logger.py
import logging
import os
import json
from datetime import datetime

def setup_logger(log_dir="../logs", log_file_name="cowrie.log"):
    # Ensure log directory exists
    os.makedirs(log_dir, exist_ok=True)
    
    # Use a single fixed log file
    log_file = os.path.join(log_dir, log_file_name)

    # Configure logger
    logger = logging.getLogger("cowrie")
    logger.setLevel(logging.INFO)

    # Avoid adding multiple handlers if setup_logger is called multiple times
    if not logger.handlers:
        file_handler = logging.FileHandler(log_file, mode='a')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    # Log startup message
    logger.info(f"[+] Logger initialized at {log_file}")
    return logger


def log_event(logger, event_type, data):
    """
    Save events in structured JSON format.
    """
    json_line = json.dumps({
        "timestamp": datetime.now().isoformat(),
        "event": event_type,
        "data": data
    })
    logger.info(json_line)
