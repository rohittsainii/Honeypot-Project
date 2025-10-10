from __future__ import annotations
import asyncio
import asyncssh
import yaml
import os
import pathlib
from .logger import Logger
from .server import HoneySSHServer, HoneySSHSession

CONFIG_PATH = pathlib.Path(__file__).parent.parent / 'config' / 'config.yaml'

async def start_server():
    with open(CONFIG_PATH, 'r') as f:
        cfg = yaml.safe_load(f)
    port = cfg.get('port', 2222)
    host_key = cfg.get('host_key', None)
    log_dir = cfg.get('log_dir', 'logs')
    banner = cfg.get('banner', 'SSH-2.0-OpenSSH_8.9p1')

    logger = Logger(log_dir=log_dir)

    server = HoneySSHServer(logger)

    # load or generate host key
    if host_key and os.path.exists(host_key):
        host_key_path = host_key
    else:
        # asyncssh can generate a key on the fly if None is passed
        host_key_path = None

    print(f"Starting honeypot on 0.0.0.0:{port}")

    await asyncssh.create_server(lambda: server, '', port,
                                 server_host_keys=[host_key_path] if host_key_path else None,
                                 server_version_string=banner,
                                 allow_scp=False)
    # keep running
    await asyncio.Event().wait()

if __name__ == '__main__':
    try:
        asyncio.run(start_server())
    except (OSError, asyncssh.Error) as exc:
        print('Error starting server: ' + str(exc))