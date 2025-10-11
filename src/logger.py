# src/logger.py
import logging
import os
import json
from datetime import datetime

def setup_logger(log_dir="../logs", log_file_name="cowrie.log"):
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, log_file_name)

    logger = logging.getLogger("cowrie")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        file_handler = logging.FileHandler(log_file, mode='a')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

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
