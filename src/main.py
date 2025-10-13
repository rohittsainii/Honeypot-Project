import socket
import threading
import paramiko
from logger import setup_logger, log_event

logger = setup_logger()

HOST_KEY = paramiko.RSAKey.generate(2048)


class CowrieServer(paramiko.ServerInterface):
    def __init__(self, client_addr):
        self.client_addr = client_addr

    def check_auth_password(self, username, password):
        log_event(logger, "auth_attempt", {"username": username, "password": password})
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


def handle_connection(client_sock, client_addr):
    log_event(logger, "connection_made", {"client": client_addr})
    print(f"[+] Connection from {client_addr}")

    try:
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(HOST_KEY)
        server = CowrieServer(client_addr)
        transport.start_server(server=server)

        # Accept channels (sessions)
        while True:
            chan = transport.accept(timeout=20)
            if chan is None:
                break
            chan.send("Welcome to Cowrie honeypot!\n")
            chan.close()

    except Exception as e:
        log_event(logger, "connection_lost", {"client": client_addr, "error": str(e)})
        print(f"[-] Connection closed with {client_addr}: {e}")
    finally:
        transport.close()  
        client_sock.close()


def start_server(host='0.0.0.0', port=2222):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)
    sock.settimeout(1.0) 
    logger.info(f"[*] Honeypot started on port {port}")
    print(f"[*] Honeypot listening on port {port}")

    try:
        while True:
            try:
                client_sock, client_addr = sock.accept()
                t = threading.Thread(target=handle_connection, args=(client_sock, client_addr))
                t.daemon = True
                t.start()
            except socket.timeout:
                continue 
    except KeyboardInterrupt:
        print("\n[!] Shutting down honeypot...")
        logger.info("[!] Honeypot shutdown via Ctrl+C")
    finally:
        sock.close()


if __name__ == "__main__":
    try:
        start_server()
    except Exception as exc:
        logger.error(f"[!] SSH server failed: {exc}")
        print(f"[!] SSH server failed: {exc}")
