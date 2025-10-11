import asyncio
import uuid
from typing import Optional

class FakeShell:
    def __init__(self, username: str, logger, session_id: Optional[str] = None):
        self.username = username
        self.session_id = session_id or str(uuid.uuid4())
        self.logger = logger
        self.prompt = "$ "
        self.commands = {
            "ls": self.cmd_ls,
            "pwd": self.cmd_pwd,
            "whoami": self.cmd_whoami,
            "id": self.cmd_id,
            "uname": self.cmd_uname,
            "exit": self.cmd_exit,
            "help": self.cmd_help,
        }

    async def handle_input(self, stdin_reader, stdout_writer, client_ip: str):
        self.logger.log_session_start(self.session_id, self.username, client_ip)
        await stdout_writer.write(self.prompt)
        await stdout_writer.drain()
        while True:
            data = await stdin_reader.read(1024)
            if not data:
                break
            cmd = data.decode(errors="ignore").strip()
            if not cmd:
                await stdout_writer.write(self.prompt)
                await stdout_writer.drain()
                continue
            self.logger.log_session_event(self.session_id, {"cmd": cmd})
            parts = cmd.split()
            base = parts[0]
            handler = self.commands.get(base, self.cmd_unknown)
            output = handler(parts)
            if asyncio.iscoroutine(output):
                output = await output
            if output:
                await stdout_writer.write(output + "\n")
            if base == "exit":
                break
            await stdout_writer.write(self.prompt)
            await stdout_writer.drain()

    def cmd_ls(self, parts):
        return "README.md\nbin\nhome\nvar\n"

    def cmd_pwd(self, parts):
        return "/home/{}".format(self.username)

    def cmd_whoami(self, parts):
        return self.username

    def cmd_id(self, parts):
        return "uid=1000({}) gid=1000({}) groups=1000({})".format(self.username, self.username, self.username)

    def cmd_uname(self, parts):
        return "Linux honeypot 5.15.0-xyz"

    def cmd_exit(self, parts):
        return "logout"

    def cmd_help(self, parts):
        return "Available commands: {}".format(", ".join(sorted(self.commands.keys())))

    def cmd_unknown(self, parts):
        return "bash: {}: command not found".format(parts[0])