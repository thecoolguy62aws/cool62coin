import time
import hashlib
import json
import pickle
import threading
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

import config

TRANSACTION_FEE = 1.0

DEFAULT_KEY_FILE = Path(__file__).with_name("public_key.pem")
CHAIN_FILE = Path(__file__).with_name("blockchain.pkl")

def address_from_public_key(public_key):
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return der.hex()

def load_key_address(path=None):
    key_file = Path(path) if path else DEFAULT_KEY_FILE
    with open(key_file, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return address_from_public_key(public_key)

def load_private_key(path="private_key.pem", password=None):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)

def verify_transaction(sender, signature, transaction_string):
    signature_bytes = bytes.fromhex(signature)
    sender_bytes = bytes.fromhex(sender)

    try:
        public_key = serialization.load_der_public_key(sender_bytes)
        public_key.verify(
            signature_bytes,
            transaction_string,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except (InvalidSignature, ValueError):
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(sender_bytes)
            public_key.verify(signature_bytes, transaction_string)
            return True
        except (InvalidSignature, ValueError):
            return False

def sign_transaction(private_key, sender, receiver, amount, nonce=0):
    transaction_string = json.dumps({
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "nonce": nonce
    }, sort_keys=True).encode()

    if isinstance(private_key, rsa.RSAPrivateKey):
        signature = private_key.sign(
            transaction_string,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    else:
        signature = private_key.sign(transaction_string)

    return signature.hex()

class MiningInterrupted(Exception):
    pass

class Block:
    def __init__(self, index, transactions, previous_hash, miner=None,
                 difficulty=0, nonce=0, timestamp=None):
        self.index = index
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.miner = miner
        self.difficulty = difficulty
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "miner": self.miner,
            "nonce": self.nonce,
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def is_mined(self):
        return self.hash.startswith("0" * self.difficulty)

    def mine(self, yield_every=0, step=1, stop_event=None):
        while not self.is_mined():
            if stop_event is not None and stop_event.is_set():
                raise MiningInterrupted()
            self.nonce += step
            self.hash = self.calculate_hash()
            if yield_every and self.nonce % yield_every == 0:
                time.sleep(0)

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "miner": self.miner,
            "difficulty": self.difficulty,
            "nonce": self.nonce,
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            index=data["index"],
            transactions=data["transactions"],
            previous_hash=data["previous_hash"],
            miner=data.get("miner"),
            difficulty=data.get("difficulty", 0),
            nonce=data["nonce"],
            timestamp=data.get("timestamp"),
        )

def solve_block(candidate, yield_every=1024, nonce_start=0, stride=1,
                stop_event=None):
    block = Block(
        index=candidate["index"],
        transactions=candidate["transactions"],
        previous_hash=candidate["previous_hash"],
        miner=candidate.get("miner"),
        difficulty=candidate.get("difficulty", 0),
        timestamp=candidate.get("timestamp"),
        nonce=nonce_start,
    )
    block.mine(yield_every=yield_every, step=stride, stop_event=stop_event)
    return block.to_dict()

class Blockchain:
    _schema_version = 2

    def __init__(self, difficulty=config.DIFFICULTY, reward=config.REWARD,
                 miner_address=None, chain_file=CHAIN_FILE):
        self.chain = []
        self.unconfirmed_transactions = []
        self.pending_debits = {}
        self.difficulty = difficulty
        self.reward = reward
        self.miner_address = miner_address or load_key_address()
        self.chain_file = Path(chain_file)
        self._lock = threading.Lock()
        self.create_genesis_block()

    def __getstate__(self):
        state = {
            "_schema_version": self._schema_version,
            "chain": self.chain,
            "unconfirmed_transactions": self.unconfirmed_transactions,
            "pending_debits": self.pending_debits,
            "difficulty": self.difficulty,
            "reward": self.reward,
            "miner_address": self.miner_address,
        }
        return state

    def __setstate__(self, state):
        if state.get("_schema_version") != self._schema_version:
            raise ValueError("incompatible persisted chain")
        self.chain = state["chain"]
        self.unconfirmed_transactions = state["unconfirmed_transactions"]
        self.pending_debits = state["pending_debits"]
        self.difficulty = state["difficulty"]
        self.reward = state["reward"]
        self.miner_address = state.get("miner_address") or load_key_address()
        self.chain_file = CHAIN_FILE
        self._lock = threading.Lock()

    def save(self, path=None):
        chain_file = Path(path) if path else self.chain_file
        with open(chain_file, "wb") as f:
            pickle.dump(self, f)

    @classmethod
    def load(cls, path=None):
        chain_file = Path(path) if path else CHAIN_FILE
        if not chain_file.exists():
            return cls(chain_file=chain_file)
        try:
            with open(chain_file, "rb") as f:
                instance = pickle.load(f)
            instance.chain_file = chain_file
            return instance
        except Exception:
            return cls(chain_file=chain_file)

    def create_genesis_block(self):
        genesis = Block(0, [], "0", miner=self.miner_address, difficulty=self.difficulty)
        genesis.mine()
        self.chain.append(genesis)

    def difficulty_at_next(self, chain=None):
        chain = chain if chain is not None else self.chain
        if not chain:
            return config.DIFFICULTY
        if len(chain) % config.RETARGET_INTERVAL != 0:
            return chain[-1].difficulty
        window = chain[-config.RETARGET_INTERVAL:]
        span = window[-1].timestamp - window[0].timestamp
        if span < 1:
            span = 1
        target = config.RETARGET_INTERVAL * config.TARGET_BLOCK_TIME
        difficulty = int(round(chain[-1].difficulty * target / span))
        return min(config.MAX_DIFFICULTY, max(config.MIN_DIFFICULTY, difficulty))

    @property
    def last_block(self):
        return self.chain[-1]

    @property
    def height(self):
        return len(self.chain)

    def tx_id(self, tx):
        canonical = json.dumps(tx, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def get_balance(self, address):
        balances = self.rebuild_balances(self.chain)
        return balances.get(address, 0)

    def rebuild_balances(self, chain, verify=False):
        balances = {}
        for block in chain:
            if block.miner:
                balances[block.miner] = balances.get(block.miner, 0) + self.reward
            for tx in block.transactions:
                if verify:
                    transaction_string = json.dumps(
                        {k: tx[k] for k in ("sender", "receiver", "amount", "nonce")},
                        sort_keys=True
                    ).encode()
                    ok = verify_transaction(tx["sender"], tx["signature"], transaction_string)
                    if not ok:
                        return None
                if tx["amount"] < 0 or balances.get(tx["sender"], 0) < tx["amount"] + TRANSACTION_FEE:
                    return None
                balances[tx["sender"]] = balances.get(tx["sender"], 0) - tx["amount"] - TRANSACTION_FEE
                balances[tx["receiver"]] = balances.get(tx["receiver"], 0) + tx["amount"]
        return balances

    def add_transaction(self, sender, receiver, amount, signature, nonce=0):
        if isinstance(amount, bool) or not isinstance(amount, (int, float)) or amount < 0:
            return False
        if isinstance(nonce, bool) or not isinstance(nonce, int):
            return False

        transaction_string = json.dumps({
            "sender": sender,
            "receiver": receiver,
            "amount": amount,
            "nonce": nonce
        }, sort_keys=True).encode()

        try:
            if not verify_transaction(sender, signature, transaction_string):
                return False
        except ValueError:
            return False

        with self._lock:
            if self.rebuild_balances(self.chain).get(sender, 0) - self.pending_debits.get(sender, 0) < amount + TRANSACTION_FEE:
                return False

            tx = {
                "sender": sender,
                "receiver": receiver,
                "amount": amount,
                "nonce": nonce,
                "signature": signature
            }
            if self.mempool_has(tx):
                return False
            self.unconfirmed_transactions.append(tx)
            self.pending_debits[sender] = self.pending_debits.get(sender, 0) + amount
            self.save()
        return True

    def mine_block_candidate(self):
        with self._lock:
            if not self.unconfirmed_transactions:
                return None
            return {
                "index": len(self.chain),
                "transactions": list(self.unconfirmed_transactions),
                "previous_hash": self.last_block.hash,
                "miner": self.miner_address,
                "difficulty": self.difficulty_at_next(),
            }

    def commit_mined(self, block_dict):
        try:
            block = Block.from_dict(block_dict)
        except (KeyError, TypeError, ValueError):
            return False
        with self._lock:
            if block.index != len(self.chain):
                return False
            if block.previous_hash != self.last_block.hash:
                return False
            if not self.validate_chain(self.chain + [block]):
                return False
            self.chain.append(block)
            self._drop_confirmed()
            self._recompute_pending()
            self.save()
        return True

    def mine_pending_transactions(self, yield_every=1024):
        candidate = self.mine_block_candidate()
        if candidate is None:
            return False
        return self.commit_mined(solve_block(candidate, yield_every=yield_every))

    def validate_chain(self, chain):
        if not chain:
            return False

        for i, block in enumerate(chain):
            if block.index != i:
                return False
            if not block.miner:
                return False
            if block.hash != block.calculate_hash():
                return False
            if not block.hash.startswith("0" * block.difficulty):
                return False
            if i == 0:
                if block.previous_hash != "0":
                    return False
            else:
                if block.previous_hash != chain[i - 1].hash:
                    return False
                if block.difficulty != self.difficulty_at_next(chain[:i]):
                    return False

        return self.rebuild_balances(chain, verify=True) is not None

    def add_block(self, block_dict):
        try:
            block = Block.from_dict(block_dict)
        except (KeyError, TypeError, ValueError):
            return False

        with self._lock:
            if block.index != len(self.chain):
                return False
            if block.previous_hash != self.last_block.hash:
                return False
            if not self.validate_chain(self.chain + [block]):
                return False
            self.chain.append(block)
            self._drop_confirmed()
            self._recompute_pending()
            self.save()
        return True

    def adopt_chain(self, block_dicts):
        try:
            blocks = [Block.from_dict(b) for b in block_dicts]
        except (KeyError, TypeError, ValueError):
            return False

        with self._lock:
            if len(blocks) < len(self.chain):
                return False
            if len(blocks) == len(self.chain):
                if len(self.chain) < 2:
                    return False
                if blocks[-1].hash >= self.chain[-1].hash:
                    return False
            if not self.validate_chain(blocks):
                return False
            self.chain = blocks
            self._drop_confirmed()
            self._recompute_pending()
            self.save()
        return True

    def mempool_has(self, tx):
        txid = self.tx_id(tx)
        for confirmed in self.chain:
            for confirmed_tx in confirmed.transactions:
                if self.tx_id(confirmed_tx) == txid:
                    return True
        return any(self.tx_id(pending) == txid for pending in self.unconfirmed_transactions)

    def _drop_confirmed(self):
        confirmed = set()
        for block in self.chain:
            for tx in block.transactions:
                confirmed.add(self.tx_id(tx))
        self.unconfirmed_transactions = [
            tx for tx in self.unconfirmed_transactions
            if self.tx_id(tx) not in confirmed
        ]

    def _recompute_pending(self):
        pending = {}
        for tx in self.unconfirmed_transactions:
            pending[tx["sender"]] = pending.get(tx["sender"], 0) + tx["amount"] + TRANSACTION_FEE
        self.pending_debits = pending

    def is_chain_valid(self):
        return self.validate_chain(self.chain)