import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import requests

from core import Blockchain

HERE = Path(__file__).parent
TOR = r"C:\Users\awspa\portableapps\tor.exe"
PY = sys.executable

N1 = dict(port=8090, socks=9050, data=HERE / "data" / "n1", peers=HERE / "data" / "peers1.txt", chain=HERE / "data" / "chain1.pkl")
N2 = dict(port=8091, socks=9051, data=HERE / "data" / "n2", peers=HERE / "data" / "peers2.txt", chain=HERE / "data" / "chain2.pkl")

os.environ.setdefault("NO_PROXY", "*")


def clean():
    for d in (N1["data"], N2["data"]):
        shutil.rmtree(d, ignore_errors=True)
    for n in (N1, N2):
        n["peers"].unlink(missing_ok=True)
        n["chain"].unlink(missing_ok=True)
        seed = Blockchain(difficulty=1)
        seed.save(n["chain"])


def spawn(node):
    return subprocess.Popen([
        PY, str(HERE / "main.py"),
        "--port", str(node["port"]),
        "--socks", str(node["socks"]),
        "--data", str(node["data"]),
        "--peers", str(node["peers"]),
        "--chain", str(node["chain"]),
        "--tor", TOR,
        "--sync-interval", "5",
    ], cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def wait_onion(node, timeout=180):
    hostfile = Path(node["data"]) / "hidden_service" / "hostname"
    deadline = time.time() + timeout
    while time.time() < deadline:
        if hostfile.exists():
            onion = hostfile.read_text().strip()
            if onion:
                try:
                    api(onion, "/info", node["socks"])
                    return onion
                except Exception:
                    pass
        time.sleep(2)
    raise TimeoutError(f"no reachable onion for {node}")


def api(onion, path, socks_port, body=None, method="GET"):
    url = f"http://{onion}{path}"
    proxies = {"http": f"socks5h://127.0.0.1:{socks_port}", "https": f"socks5h://127.0.0.1:{socks_port}"}
    resp = requests.request(method, url, json=body, proxies=proxies, timeout=30)
    resp.raise_for_status()
    return resp.json()


def call_until(fn, timeout=120, interval=3):
    deadline = time.time() + timeout
    while True:
        try:
            return fn()
        except Exception:
            if time.time() >= deadline:
                raise
        time.sleep(interval)


def sweep_leftover():
    try:
        out = subprocess.run([
            "powershell", "-NoProfile", "-Command",
            "Get-CimInstance Win32_Process -Filter \"Name='tor.exe'\" | Where-Object { $_.CommandLine -like '*blockchain*data*' } | ForEach-Object { $_.ProcessId }"
        ], capture_output=True, text=True, timeout=30)
        for line in out.stdout.splitlines():
            pid = line.strip()
            if pid.isdigit():
                subprocess.run(["taskkill", "/F", "/PID", pid, "/T"], capture_output=True)
    except Exception:
        pass


def main():
    sweep_leftover()
    clean()

    p1 = None
    p2 = None
    miner_proc = None
    try:
        p1 = spawn(N1)
        onion1 = wait_onion(N1)
        print("node1 onion:", onion1)

        N2["peers"].write_text(onion1 + "\n")
        p2 = spawn(N2)
        onion2 = wait_onion(N2)
        print("node2 onion:", onion2)

        info1 = call_until(lambda: api(onion1, "/info", N1["socks"]))
        info2 = call_until(lambda: api(onion2, "/info", N2["socks"]))
        assert info1["height"] == 1 and info2["height"] == 1, (info1, info2)

        def mutual_peers():
            peers1 = api(onion1, "/peers", N1["socks"])["peers"]
            peers2 = api(onion2, "/peers", N2["socks"])["peers"]
            if onion2 in peers1 and onion1 in peers2:
                return peers1, peers2
            raise AssertionError((peers1, peers2))

        peers1, peers2 = call_until(mutual_peers)
        print("peers1:", peers1)
        print("peers2:", peers2)
        print("mutual peer discovery: True")

        from core import load_private_key, load_key_address, sign_transaction
        from cryptography.hazmat.primitives.asymmetric import ed25519

        miner = load_key_address()
        priv = load_private_key("private_key.pem")
        target = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()

        sig = sign_transaction(priv, miner, target, 10.0, 1)
        tx = {"sender": miner, "receiver": target, "amount": 10.0, "nonce": 1, "signature": sig}
        api(onion1, "/transaction", N1["socks"], body=tx, method="POST")
        print("tx posted to node1")

        def tx_reached():
            pool2 = api(onion2, "/txpool", N2["socks"])["transactions"]
            if any(t["sender"] == miner and t["amount"] == 10.0 for t in pool2):
                return True
            raise AssertionError("tx not in node2 txpool yet")

        propagated = call_until(tx_reached, timeout=90)
        print("tx in node2 txpool:", propagated)

        def work_has_tx():
            w = requests.get("http://127.0.0.1:8090/work", timeout=10).json()
            if not (w.get("success") and w.get("pending")):
                raise AssertionError("no pending work yet")
            if not any(t["sender"] == miner for t in w["transactions"]):
                raise AssertionError("tx not in /work template yet")
            return w

        call_until(work_has_tx, timeout=90)
        print("standalone miner sees the tx via /work")

        miner_proc = subprocess.Popen([
            PY, str(HERE / "miner.py"),
            "--node", "http://127.0.0.1:8090",
            "--interval", "1", "--cpu", "--threads", "2",
        ], cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        print("waiting for standalone miner to produce block #2")

        def converged():
            h1 = api(onion1, "/info", N1["socks"])["height"]
            h2 = api(onion2, "/info", N2["socks"])["height"]
            if h1 == h2 == 2:
                return h1, h2
            raise AssertionError(f"heights not converged: {h1}/{h2}")

        h1, h2 = call_until(converged, timeout=120)
        print("heights node1/node2:", h1, h2)
        assert h1 == h2 == 2

        b1 = api(onion1, f"/balance?address={miner}", N1["socks"])["balance"]
        b2 = api(onion2, f"/balance?address={miner}", N2["socks"])["balance"]
        btarget = api(onion2, f"/balance?address={target}", N2["socks"])["balance"]
        print("balances node1/node2:", b1, b2, "target:", btarget)
        assert b1 == b2 == 190.0, (b1, b2)
        assert btarget == 10.0, btarget

        print("INTEGRATION TEST PASSED")
    finally:
        if miner_proc is not None:
            miner_proc.terminate()
            try:
                miner_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                miner_proc.kill()
        for p in (p1, p2):
            if p is not None:
                p.terminate()
        for p in (p1, p2):
            if p is not None:
                try:
                    p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    p.kill()

        for n in (N1, N2):
            pidfile = Path(n["data"]) / "tor.pid"
            if pidfile.exists():
                pid = pidfile.read_text().strip()
                if pid:
                    subprocess.run(["taskkill", "/F", "/PID", pid, "/T"], capture_output=True)
        sweep_leftover()


if __name__ == "__main__":
    main()