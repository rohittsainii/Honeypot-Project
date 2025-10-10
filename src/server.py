import asyncio
import asyncssh
import os
import yaml
import pathlib
import uuid
from .logger import Logger
from .shell import FakeShell

class HoneySSHServer(asyncssh.SSHServer):
    def __init__(self, logger: Logger):
        self.logger = logger

    def connection_made(self, conn):
        peer = conn.get_extra_info('peername')
        print(f"Incoming connection from {peer}")
        self.peer = peer

    def connection_lost(self, exc):
        print("Connection closed")

    def begin_auth(self, username):
        # tell asyncssh we want to handle password auth
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        # Log the credentials, then allow authentication to succeed (honeypot)
        client_ip = self.peer[0] if hasattr(self, 'peer') and self.peer else 'unknown'
        self.logger.log_auth(username, password, client_ip, method='password')
        return True

class HoneySSHSession(asyncssh.SSHServerSession):
    def __init__(self, logger: Logger, username: str, client_ip: str):
        self._chan = None
        self.logger = logger
        self.username = username
        self.client_ip = client_ip
        self.session_id = str(uuid.uuid4())

    def connection_made(self, chan):
        self._chan = chan

    def session_started(self):
        # start fake shell loop using the channel's stdin/stdout
        shell = FakeShell(self.username, self.logger, session_id=self.session_id)
        # wrap channel for text IO
        reader = self._chan.get_extra_info('chan').get_reader()

    def exec_requested(self, command):
        # attackers sometimes try to run commands directly
        self.logger.log_session_event(self.session_id, {"exec": command})
        return False

    def shell_requested(self):
        # Start an interactive shell task
        self._chan.write("Welcome to Ubuntu 22.04 LTS\\n")
        # Note: asyncssh gives us streams via start_shell
        return True

    def data_received(self, data, datatype):
        # Fallback for earlier versions — but we use start_shell instead
        pass