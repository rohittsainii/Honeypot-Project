# src/main.py
import asyncio
import asyncssh
from logger import setup_logger, log_event

logger = setup_logger()

class CowrieServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        peer = conn.get_extra_info('peername')
        log_event(logger, "connection_made", {"client": peer})
        print(f"[+] Connection from {peer}")

    def connection_lost(self, exc):
        log_event(logger, "connection_lost", {"error": str(exc) if exc else "None"})
        print("[-] Connection closed")

    def begin_auth(self, username):
        log_event(logger, "auth_attempt", {"username": username})
        return True

async def start_server():
    await asyncssh.listen('', 2222, server_factory=CowrieServer)
    logger.info("[*] Honeypot started on port 2222")
    print("[*] Honeypot listening on port 2222")
    await asyncio.get_event_loop().create_future()

if __name__ == "__main__":
    try:
        asyncio.run(start_server())
    except (OSError, asyncssh.Error) as exc:
        logger.error(f"[!] SSH server failed: {exc}")
        print(f"[!] SSH server failed: {exc}")
