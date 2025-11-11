# src/logger.py
import os
import json
import threading
from datetime import datetime
import pathlib

class Logger:
    """
    Simple logger that writes one JSON object per line to a single file:
      logs/cowrie.log

    Each line is:
    {"timestamp":"...","event":"auth","data":{...}}

    Thread-safe for multi-threaded server.
    """
    def __init__(self, log_dir: str = None, filename: str = "cowrie.log"):
        # default log_dir is project_root/logs
        if log_dir is None:
            PROJECT_ROOT = pathlib.Path(__file__).parents[1]
            log_dir = str(PROJECT_ROOT / "logs")

        os.makedirs(log_dir, exist_ok=True)
        self.path = os.path.join(log_dir, filename)
        self._lock = threading.Lock()

        # Write a startup marker
        self._write_raw({
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event": "logger_start",
            "data": {"msg": f"logger initialized, output -> {self.path}"}
        })

    def _write_raw(self, obj: dict) -> None:
        line = json.dumps(obj, ensure_ascii=False)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def log_auth(self, username: str, password: str, client_ip: str, method: str = "password") -> None:
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event": "auth",
            "data": {
                "username": username,
                "password": password,
                "client_ip": client_ip,
                "method": method
            }
        }
        self._write_raw(event)

    def log_session_start(self, session_id: str, username: str, client_ip: str) -> None:
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event": "session_start",
            "data": {
                "session_id": session_id,
                "username": username,
                "client_ip": client_ip
            }
        }
        self._write_raw(event)

    def log_session_event(self, session_id: str, event_data: dict) -> None:
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event": "session_event",
            "data": {
                "session_id": session_id,
                **event_data
            }
        }
        self._write_raw(event)
