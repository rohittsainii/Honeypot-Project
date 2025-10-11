# src/server.py
import socket
import threading
import os
import pathlib
import time
import uuid
import paramiko
from typing import Tuple, Optional

from logger import Logger

PROJECT_ROOT = pathlib.Path(__file__).parents[1]
CONFIG_DIR = PROJECT_ROOT / "config"
HOST_KEY_PATH = CONFIG_DIR / "ssh_host_rsa_key" 
LISTEN_ADDR = "0.0.0.0"
LISTEN_PORT = 2222
BACKLOG = 100

os.makedirs(CONFIG_DIR, exist_ok=True)


def ensure_host_key(path: pathlib.Path) -> paramiko.RSAKey:
    """
    Load or generate an RSA host key for Paramiko.
    """
    if path.exists():
        return paramiko.RSAKey(filename=str(path))
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(path))
    return key


class HoneyServerInterface(paramiko.ServerInterface):
    """
    Paramiko ServerInterface that accepts any password, logs attempts,
    and allows session/shell channels.
    """
    def __init__(self, conn_id: str, client_ip: str, logger: Logger):
        self.event = threading.Event()
        self.conn_id = conn_id
        self.client_ip = client_ip
        self.logger = logger
        self.username = None
        self.exec_command = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        client = self.client_ip
        try:
            self.logger.log_auth(username, password, client, method="password")
        except Exception:
            pass
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        try:
            self.logger.log_session_event(self.conn_id, {"exec": command.decode() if isinstance(command, bytes) else str(command)})
        except Exception:
            pass
        self.exec_command = command.decode() if isinstance(command, bytes) else str(command)
        self.event.set()
        return True


class SyncFakeShell:
    """
    Simple synchronous fake shell: reads commands from channel.recv and responds.
    Logs session start and commands via provided Logger instance.
    """
    def __init__(self, username: str, logger: Logger, session_id: Optional[str] = None):
        self.username = username or "unknown"
        self.logger = logger
        self.session_id = session_id or str(uuid.uuid4())
        self.prompt = "$ "
        self.commands = {
            "ls": lambda parts: "README.md\nbin\nhome\nvar\n",
            "pwd": lambda parts: f"/home/{self.username}",
            "whoami": lambda parts: self.username,
            "id": lambda parts: f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username})",
            "uname": lambda parts: "Linux honeypot 5.15.0-xyz",
            "exit": lambda parts: "logout",
            "help": lambda parts: "Available commands: " + ", ".join(sorted(["exit","help","ls","pwd","whoami","id","uname"]))
        }

    def handle_session(self, chan: paramiko.Channel, client_addr: Tuple[str,int]):
        """
        Main loop for the interactive shell.
        """
        try:
            try:
                self.logger.log_session_start(self.session_id, self.username, client_addr[0])
            except Exception:
                pass

            chan.send("Welcome to Ubuntu 22.04 LTS\r\n")
            chan.send(self.prompt)

            buf = b""
            while True:
                data = chan.recv(1024)
                if not data:
                    break
                buf += data
                if b"\n" in buf or b"\r" in buf:
                    text = buf.decode(errors="ignore").strip()
                    buf = b""
                    if not text:
                        chan.send(self.prompt)
                        continue
                    try:
                        self.logger.log_session_event(self.session_id, {"cmd": text})
                    except Exception:
                        pass
                    parts = text.split()
                    base = parts[0]
                    handler = self.commands.get(base, None)
                    out = None
                    if handler:
                        out = handler(parts)
                    else:
                        out = f"bash: {base}: command not found"
                    chan.send(out + "\r\n")
                    if base == "exit":
                        break
                    chan.send(self.prompt)
        except Exception as e:
            try:
                self.logger.log_session_event(self.session_id, {"error": str(e)})
            except Exception:
                pass
        finally:
            try:
                chan.close()
            except Exception:
                pass


def handle_connection(client_socket: socket.socket, client_addr: Tuple[str, int], host_key: paramiko.RSAKey, logger: Logger):
    """
    Per-connection handler executed in a thread.
    """
    conn_id = str(uuid.uuid4())
    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(host_key)

        logger.log_session_start(conn_id, "N/A", client_addr[0])  
        server = HoneyServerInterface(conn_id, client_addr[0], logger)

        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            return

        chan = transport.accept(20)
        if chan is None:
            return

        if server.exec_command:
            try:
                chan.send("Command received. Exiting.\r\n")
                chan.close()
            except Exception:
                pass
            return

        server.event.wait(10)
        if not server.event.is_set():
            try:
                chan.close()
            except Exception:
                pass
            return

        shell = SyncFakeShell(server.username or "guest", logger, session_id=conn_id)
        shell.handle_session(chan, client_addr)

    except Exception as e:
        try:
            logger.log_session_event(conn_id, {"exception": str(e)})
        except Exception:
            pass
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
        try:
            client_socket.close()
        except Exception:
            pass


def start_listening(listen_addr: str = LISTEN_ADDR, listen_port: int = LISTEN_PORT):
    """
    Main TCP accept loop. Spawns a thread per incoming connection.
    """
    logger = Logger(log_dir=str(PROJECT_ROOT / "logs"))
    host_key = ensure_host_key(HOST_KEY_PATH)

    logger.log_session_event("startup", {"msg": f"Creating SSH listener on port {listen_port}"})
    sock = socket.socket(socket.AF_INET6 if ":" in listen_addr else socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((listen_addr, listen_port))
    sock.listen(BACKLOG)
    logger.log_session_event("startup", {"msg": f"Honeypot started on port {listen_port}"})
    print(f"Honeypot listening on {listen_addr}:{listen_port}")

    try:
        while True:
            client, addr = sock.accept()
            t = threading.Thread(target=handle_connection, args=(client, addr, host_key, logger), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("Shutting down")
    finally:
        sock.close()


if __name__ == "__main__":
    start_listening()
