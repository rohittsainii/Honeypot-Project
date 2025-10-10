from __future__ import annotations
import json
import os
from datetime import datetime
from typing import Dict, Any

class Logger:
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)

    def _path(self, name: str) -> str:
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        return os.path.join(self.log_dir, f"{ts}_{name}.json")

    def log_auth(self, username: str, password: str, client_ip: str, method: str = "password") -> None:
        payload = {
            "type": "auth",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "username": username,
            "password": password,
            "client_ip": client_ip,
            "method": method,
        }
        path = self._path("auth")
        with open(path, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"[logger] auth -> {path}")

    def log_session_start(self, session_id: str, username: str, client_ip: str) -> None:
        payload = {
            "type": "session_start",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "session_id": session_id,
            "username": username,
            "client_ip": client_ip,
        }
        path = self._path("session_start")
        with open(path, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"[logger] session_start -> {path}")

    def log_session_event(self, session_id: str, event: Dict[str, Any]) -> None:
        payload = {
            "type": "session_event",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "session_id": session_id,
            "event": event,
        }
        path = self._path("session_event")
        with open(path, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"[logger] session_event -> {path}")