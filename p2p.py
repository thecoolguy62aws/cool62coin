import threading
import time
from pathlib import Path

import requests

import config


class PeerNetwork:
    def __init__(self, blockchain, peers_file, my_onion=None,
                 socks_port=config.SOCKS_PORT, sync_interval=config.SYNC_INTERVAL):
        self.blockchain = blockchain
        self.peers_file = Path(peers_file)
        self.my_onion = my_onion
        self.socks_port = socks_port
        self.sync_interval = sync_interval
        self.peers = set()
        self.seen_txs = set()
        self._lock = threading.Lock()
        self.load_peers()

    def load_peers(self):
        if self.peers_file.exists():
            for line in self.peers_file.read_text().splitlines():
                onion = self._normalize(line)
                if onion:
                    self.peers.add(onion)

    def save_peers(self):
        self.peers_file.write_text("\n".join(sorted(self.peers)) + "\n")

    def _normalize(self, onion):
        onion = str(onion).strip().lower()
        if onion.startswith("http://"):
            onion = onion[len("http://"):]
        if onion.startswith("https://"):
            onion = onion[len("https://"):]
        onion = onion.split("/")[0].split(":")[0]
        return onion

    def add_peer(self, onion):
        onion = self._normalize(onion)
        if onion and onion != self.my_onion and onion.endswith(".onion"):
            with self._lock:
                self.peers.add(onion)
        self.save_peers()

    def peer_list(self):
        with self._lock:
            known = set(self.peers)
        if self.my_onion:
            known.add(self.my_onion)
        return sorted(known)

    def proxies(self):
        proxy = f"socks5h://127.0.0.1:{self.socks_port}"
        return {"http": proxy, "https": proxy}

    def on_peer(self, onion, method, path, body=None, timeout=15):
        url = f"http://{self._normalize(onion)}{path}"
        try:
            response = requests.request(
                method, url, json=body,
                proxies=self.proxies(), timeout=timeout,
            )
            response.raise_for_status()
            return response.json()
        except Exception:
            return None

    def broadcast_tx(self, tx):
        for onion in list(self.peers):
            self.on_peer(onion, "POST", "/transaction", body=tx)

    def broadcast_block(self, block_dict):
        for onion in list(self.peers):
            self.on_peer(onion, "POST", "/block", body=block_dict)

    def on_local_tx(self, tx):
        self.seen_txs.add(self.blockchain.tx_id(tx))
        self.broadcast_tx(tx)

    def sync_once(self):
        for onion in list(self.peers):
            self.sync_peer(onion)

    def sync_peer(self, onion):
        info = self.on_peer(onion, "GET", "/info")
        if not info:
            return

        if info.get("onion"):
            self.add_peer(info["onion"])

        if self.my_onion:
            self.on_peer(onion, "POST", "/peers", body={"peers": [self.my_onion]})

        remote_peers = self.on_peer(onion, "GET", "/peers")
        if remote_peers:
            for peer in remote_peers.get("peers", []):
                self.add_peer(peer)

        remote_chain = self.on_peer(onion, "GET", "/chain")
        if remote_chain:
            blocks = remote_chain.get("blocks", [])
            local_height = self.blockchain.height
            remote_height = len(blocks)
            adopt = False
            if remote_height > local_height:
                adopt = True
            elif remote_height == local_height and remote_height > 1:
                remote_tip = blocks[-1].get("hash")
                local_tip = self.blockchain.last_block.hash
                if remote_tip != local_tip and remote_tip < local_tip:
                    adopt = True
            if adopt:
                if self.blockchain.adopt_chain(blocks):
                    self.broadcast_block(blocks[-1])

        pool = self.on_peer(onion, "GET", "/txpool")
        if pool:
            for tx in pool.get("transactions", []):
                txid = self.blockchain.tx_id(tx)
                if txid in self.seen_txs or self.blockchain.mempool_has(tx):
                    continue
                ok = self.blockchain.add_transaction(
                    tx.get("sender"),
                    tx.get("receiver"),
                    tx.get("amount"),
                    tx.get("signature"),
                    tx.get("nonce", 0),
                )
                if ok:
                    self.seen_txs.add(txid)
                    self.broadcast_tx(tx)

    def run(self):
        while True:
            try:
                self.sync_once()
            except Exception:
                pass
            time.sleep(self.sync_interval)