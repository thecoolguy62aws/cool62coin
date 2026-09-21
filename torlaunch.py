import os
import subprocess
import time
from pathlib import Path

import config


class TorDaemon:
    def __init__(self, data_dir, socks_port, server_port, tor_bin=None,
                 timeout=120):
        self.data_dir = Path(data_dir)
        self.socks_port = socks_port
        self.server_port = server_port
        self.tor_bin = Path(tor_bin) if tor_bin else config.TOR_BIN
        self.timeout = timeout
        self.hidden_dir = self.data_dir / "hidden_service"
        self.torrc = self.data_dir / "torrc"
        self.process = None
        self.hostname = None
        self.pid_file = self.data_dir / "tor.pid"

    def write_torrc(self):
        os.makedirs(self.data_dir, mode=0o700, exist_ok=True)
        for sub in ("datadir", "hidden_service"):
            path = self.data_dir / sub
            os.makedirs(path, mode=0o700, exist_ok=True)
            os.chmod(path, 0o700)
        self.hidden_dir.mkdir(mode=0o700, exist_ok=True)

        def winpath(path):
            return str(path).replace("\\", "/")

        self.torrc.write_text("\n".join([
            f"SocksPort 127.0.0.1:{self.socks_port}",
            f"DataDirectory {winpath(self.data_dir / 'datadir')}",
            f"HiddenServiceDir {winpath(self.hidden_dir)}",
            f"HiddenServicePort 80 127.0.0.1:{self.server_port}",
            f"Log notice file {winpath(self.data_dir / 'notices.log')}",
        ]))

    def start(self):
        self.write_torrc()
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self.process = subprocess.Popen(
            [str(self.tor_bin), "-f", str(self.torrc)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=flags,
        )
        self.pid_file.write_text(str(self.process.pid))
        hostname_file = self.hidden_dir / "hostname"
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            if hostname_file.exists():
                self.hostname = hostname_file.read_text().strip()
                return self.hostname
            if self.process.poll() is not None:
                break
            time.sleep(0.5)
        self.stop()
        raise TimeoutError("tor failed to publish a hidden service")

    def stop(self):
        if self.process is None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
        self.process = None