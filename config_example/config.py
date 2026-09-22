from pathlib import Path
import platform
import shutil

BASE_DIR = Path(__file__).parent
if platform.system() == "Windows":
    TOR_BIN = BASE_DIR / "tor.exe"
else:
    TOR_BIN = shutil.which("tor") or "/usr/bin/tor"
PEERS_FILE = BASE_DIR / "peers.txt"
GENESIS_FILE = BASE_DIR / "genesis.json"
DATA_DIR = BASE_DIR / "data"

INTERNAL_PORT = 8090
SOCKS_PORT = 9050

DIFFICULTY = 65536
MIN_DIFFICULTY = DIFFICULTY
MAX_DIFFICULTY = 1 << 40
TARGET_BLOCK_TIME = 30
RETARGET_INTERVAL = 5
REWARD = 100.0
SYNC_INTERVAL = 20