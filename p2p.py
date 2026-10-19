import logging
import threading
import time
from pathlib import Path

import requests

import config
from core import network_id

CHAIN_PAGE_LIMIT = getattr(config, "CHAIN_PAGE_LIMIT", 500)
logger = logging.getLogger(__name__)


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
        self.peer_state = {}
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
                is_new = onion not in self.peers
                self.peers.add(onion)
            if is_new:
                logger.info("new peer: %s", onion)
        self.save_peers()

    def peer_list(self):
        with self._lock:
            known = set(self.peers)
        if self.my_onion:
            known.add(self.my_onion)
        return sorted(known)

    def _state(self, onion):
        with self._lock:
            if onion not in self.peer_state:
                self.peer_state[onion] = {
                    "last_ok": None, "last_err": None, "reason": None,
                    "last_height": None, "backoff_until": 0.0, "fails": 0,
                }
            return dict(self.peer_state[onion])

    def _note_ok(self, onion, height=None):
        with self._lock:
            state = self.peer_state.setdefault(onion, {})
            state["last_ok"] = time.time()
            state["last_err"] = None
            state["reason"] = None
            state["fails"] = 0
            state["backoff_until"] = 0.0
            if height is not None:
                state["last_height"] = height

    def _note_fail(self, onion, reason, backoff=True):
        with self._lock:
            state = self.peer_state.setdefault(onion, {})
            state["last_err"] = time.time()
            state["reason"] = reason
            state["fails"] += 1
            if backoff:
                backoff_s = min(600, 10 * (2 ** min(state["fails"] - 1, 6)))
            else:
                backoff_s = 0
            state["backoff_until"] = time.time() + backoff_s
            repeat = state.get("_printed_reason") == reason
            if not repeat:
                state["_printed_reason"] = reason
        if repeat:
            return
        if backoff_s:
            logger.warning(
                "sync: peer %s... unreachable (%s); retrying in %ss",
                onion[:12], reason, backoff_s)
        else:
            logger.warning("sync: peer %s... %s", onion[:12], reason)

    def peer_status(self):
        with self._lock:
            return {
                onion: {k: v for k, v in state.items()
                        if k != "_printed_reason"}
                for onion, state in self.peer_state.items()
            }

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

    def _chain_page(self, onion, from_index, limit):
        page = self.on_peer(
            onion, "GET", f"/chain?from_index={from_index}&limit={limit}")
        if not page or not isinstance(page.get("blocks"), list):
            return None
        if "from_index" not in page:
            return {"legacy": True, "blocks": page["blocks"]}
        return page

    def _fetch_range(self, onion, start, end, anchor_hash=None):
        if end <= start:
            return []
        blocks = []
        cursor = start
        while cursor < end:
            limit = min(CHAIN_PAGE_LIMIT, end - cursor)
            page = self._chain_page(onion, cursor, limit)
            if page is None or page.get("legacy"):
                return None
            if page.get("from_index") != cursor:
                return None
            page_blocks = page["blocks"]
            if not page_blocks or len(page_blocks) > limit:
                return None
            if not blocks and anchor_hash is not None:
                first = page_blocks[0]
                if first.get("index") != start or \
                        first.get("previous_hash") != anchor_hash:
                    return None
            blocks.extend(page_blocks)
            nxt = page.get("next_from")
            if nxt is None or nxt <= cursor:
                cursor += len(page_blocks)
            else:
                cursor = nxt
        if len(blocks) != end - start:
            return None
        return blocks

    def _fetch_whole(self, onion):
        page = self.on_peer(onion, "GET", "/chain")
        if not page or not isinstance(page.get("blocks"), list):
            return None
        return page["blocks"]

    def _fetch_candidate(self, onion, remote_height, remote_genesis):
        chain = self.blockchain.chain
        local_height = len(chain)
        local_genesis = chain[0].hash
        local_tip = chain[-1].hash
        if remote_genesis == local_genesis and local_height < remote_height:
            suffix = self._fetch_range(onion, local_height, remote_height,
                                       anchor_hash=local_tip)
            if suffix is not None:
                return [block.to_dict() for block in chain] + suffix
        full = self._fetch_range(onion, 0, remote_height)
        if full is not None:
            return full
        return self._fetch_whole(onion)

    def broadcast_tx(self, tx):
        for onion in list(self.peers):
            self.on_peer(onion, "POST", "/transaction", body=tx)

    def broadcast_block(self, block_dict):
        for onion in list(self.peers):
            self.on_peer(onion, "POST", "/block", body=block_dict)

    def broadcast_chain(self, block_dicts):
        for onion in list(self.peers):
            self.on_peer(onion, "POST", "/chain", body={"blocks": block_dicts})

    def on_local_tx(self, tx):
        self.seen_txs.add(self.blockchain.tx_id(tx))
        self.broadcast_tx(tx)

    def sync_once(self):
        for onion in list(self.peers):
            self.sync_peer(onion)

    def sync_peer(self, onion):
        if time.time() < self._state(onion)["backoff_until"]:
            return
        info = self.on_peer(onion, "GET", "/info")
        if not info:
            self._note_fail(onion, "no /info response")
            return
        self._note_ok(onion, info.get("height"))

        if info.get("onion"):
            self.add_peer(info["onion"])

        remote_id = info.get("network_id")
        if remote_id and remote_id != network_id():
            self._note_fail(onion,
                            "incompatible network config "
                            f"(network_id {remote_id[:12]}... != "
                            f"{network_id()[:12]}...)", backoff=False)
            return

        if self.my_onion:
            self.on_peer(onion, "POST", "/peers", body={"peers": [self.my_onion]})

        remote_peers = self.on_peer(onion, "GET", "/peers")
        if remote_peers:
            for peer in remote_peers.get("peers", []):
                self.add_peer(peer)

        local_height = self.blockchain.height
        local_tip = self.blockchain.last_block.hash
        remote_height = info.get("height")
        remote_tip = info.get("tip")
        remote_genesis = info.get("genesis")

        adopt = False
        reason = None
        if remote_height is None:
            reason = "no height in /info"
        elif remote_height > local_height:
            adopt = True
        elif remote_height == local_height:
            if remote_height > 1 and remote_tip and remote_tip != local_tip \
                    and remote_tip < local_tip:
                adopt = True
            elif remote_height > 1:
                reason = "equal height, remote tip not smaller"
        else:
            reason = f"remote {remote_height} not taller than local " \
                     f"{local_height}"

        if adopt:
            blocks = self._fetch_candidate(onion, remote_height, remote_genesis)
            if blocks is None:
                self._note_fail(onion, "incomplete chain sync")
            elif self.blockchain.adopt_chain(blocks):
                logger.info("adopted chain from %s: height %d -> %d",
                            onion[:12], local_height, len(blocks))
                self._note_ok(onion, max(remote_height, len(blocks)))
                self.broadcast_chain(blocks)
                self.broadcast_block(blocks[-1])
            else:
                self._note_fail(
                    onion,
                    f"chain rejected by adopt_chain "
                    f"(h {len(blocks)} vs {local_height})", backoff=False)
        elif reason:
            self._note_fail(onion, reason, backoff=False)

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