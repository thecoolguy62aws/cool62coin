# SPDX-FileCopyrightText: © 2026 thecoolguy62aws
# SPDX-License-Identifier: AGPL-3.0-or-later

import time
import hashlib
import json
import logging
import math
import pickle
import threading
from decimal import Decimal, InvalidOperation
from functools import lru_cache
from pathlib import Path
import shutil

from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

import bech32_codec

try:
    import config
except ImportError:
    if not Path("config.py").is_file():
        shutil.copyfile("config_example/config.py", "config.py")
    import config

logger = logging.getLogger(__name__)

COIN_DECIMALS = getattr(config, "COIN_DECIMALS", 8)
COIN_ATOMS = 10 ** COIN_DECIMALS
ATOMIC_ACTIVATION = getattr(config, "ATOMIC_ACTIVATION", 8000)
MAX_AMOUNT_ATOMS = getattr(config, "MAX_AMOUNT_ATOMS", (1 << 63) - 1)
MAX_FUTURE_DRIFT = getattr(config, "MAX_FUTURE_DRIFT", 2 * 60 * 60)
MAX_BLOCK_INDEX = (1 << 63) - 1
MAX_BLOCK_TIMESTAMP = (1 << 63) - 1
MAX_BLOCK_NONCE = (1 << 63) - 1
MAX_BLOCK_DIFFICULTY = 1 << 256
MAX_BLOCK_TRANSACTIONS = getattr(config, "MAX_BLOCK_TRANSACTIONS", 10_000)
MTP_WINDOW = 11
CONSENSUS_VERSION = 2
TX_VERSION_LEGACY = 1
TX_VERSION_ATOMS = 2
LEGACY_TRANSACTION_FEE_COINS = 1.0
TRANSACTION_FEE = getattr(config, "TRANSACTION_FEE", 100_000_000)
RETARGET_FACTOR = 4
TX_MEMO_MAX = getattr(config, "TX_MEMO_MAX", 512)
POW_V2_ACTIVATION = getattr(config, "POW_V2_ACTIVATION", 500)
POW_V2_VERSION = 2
POW_V2_NONCE_DIGITS = 20
EMPTY_MERKLE_ROOT = b"\x00" * 32

ADDRESS_VERSION_RSA = "0"
ADDRESS_VERSION_ED25519 = "1"
ADDRESS_CHECKSUM_LEN = 8
RSA_MODULUS_HEX_LEN = 512
RSA_PUBLIC_EXPONENT = 65537
ED25519_PUBLIC_HEX_LEN = 64
ED25519_PUBLIC_BYTES_LEN = 32
_HEX_DIGITS = set("0123456789abcdef")

ADDRESS_SCHEME_HEX = "hex"
ADDRESS_SCHEME_BECH32 = "bech32"
BECH32_HRP = getattr(config, "BECH32_HRP", "c62")
BECH32_ACTIVATION = getattr(config, "BECH32_ACTIVATION", 1500)

DEFAULT_KEY_FILE = Path(__file__).with_name("public_key.pem")
CHAIN_FILE = Path(__file__).with_name("blockchain.pkl")


def _decimal_amount(value):
    if isinstance(value, bool):
        raise ValueError("amount must be a number")
    if isinstance(value, Decimal):
        amount = value
    elif isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("amount must be finite")
        amount = Decimal(str(value))
    elif isinstance(value, str):
        try:
            amount = Decimal(value)
        except InvalidOperation as exc:
            raise ValueError("invalid amount") from exc
    else:
        raise ValueError("amount must be a number")
    if not amount.is_finite() or amount < 0:
        raise ValueError("amount must be a finite non-negative number")
    return amount


def coins_to_atoms(value):
    """Convert a legacy coin amount to integer atoms, rejecting excess precision."""
    amount = _decimal_amount(value)
    atoms = amount * COIN_ATOMS
    if atoms != atoms.to_integral_value():
        raise ValueError(f"amount has more than {COIN_DECIMALS} decimal places")
    result = int(atoms)
    if result > MAX_AMOUNT_ATOMS:
        raise ValueError("amount is too large")
    return result


def parse_amount_to_atoms(value):
    """Parse a user-supplied decimal amount directly into integer atoms."""
    return coins_to_atoms(value)


def atoms_to_coins(atoms):
    if isinstance(atoms, bool) or not isinstance(atoms, int):
        raise ValueError("atom amount must be an integer")
    return Decimal(atoms) / COIN_ATOMS


def atoms_to_coins_float(atoms):
    return atoms / COIN_ATOMS


def format_atoms(atoms):
    if isinstance(atoms, bool) or not isinstance(atoms, int):
        raise ValueError("atom amount must be an integer")
    sign = "-" if atoms < 0 else ""
    whole, fraction = divmod(abs(atoms), COIN_ATOMS)
    if not fraction:
        return f"{sign}{whole}"
    digits = str(fraction).rjust(COIN_DECIMALS, "0").rstrip("0")
    return f"{sign}{whole}.{digits}"


def transaction_fee_atoms(height):
    if height is not None and height < ATOMIC_ACTIVATION:
        return coins_to_atoms(LEGACY_TRANSACTION_FEE_COINS)
    return TRANSACTION_FEE


def tx_version(tx):
    if not isinstance(tx, dict):
        raise ValueError("transaction must be an object")
    version = tx.get("version", TX_VERSION_LEGACY)
    if isinstance(version, bool) or not isinstance(version, int):
        raise ValueError("transaction version must be an integer")
    if version not in (TX_VERSION_LEGACY, TX_VERSION_ATOMS):
        raise ValueError("unsupported transaction version")
    return version


def amount_atoms_for_height(amount, version, height):
    if version == TX_VERSION_ATOMS:
        if height is not None and height < ATOMIC_ACTIVATION:
            raise ValueError("atom transactions are not active yet")
        if isinstance(amount, bool) or not isinstance(amount, int):
            raise ValueError("atom amounts must be integers")
        if amount < 0 or amount > MAX_AMOUNT_ATOMS:
            raise ValueError("amount is out of range")
        return amount
    if version == TX_VERSION_LEGACY:
        if height is not None and height >= ATOMIC_ACTIVATION:
            raise ValueError("legacy transactions are no longer accepted")
        return coins_to_atoms(amount)
    raise ValueError("unsupported transaction version")


def tx_amount_atoms(tx, height):
    version = tx_version(tx)
    if "amount" not in tx:
        raise ValueError("transaction is missing amount")
    return amount_atoms_for_height(tx["amount"], version, height)


def _address_checksum(body):
    return hashlib.sha256(body.encode()).hexdigest()[:ADDRESS_CHECKSUM_LEN]

def _encode_hex_address(public_key):
    if isinstance(public_key, rsa.RSAPublicKey):
        modulus_hex = format(public_key.public_numbers().n, "x")
        if len(modulus_hex) > RSA_MODULUS_HEX_LEN:
            raise ValueError("unsupported RSA key size")
        body = ADDRESS_VERSION_RSA + modulus_hex.rjust(RSA_MODULUS_HEX_LEN, "0")
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        raw_hex = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()
        body = ADDRESS_VERSION_ED25519 + raw_hex
    else:
        raise ValueError("unsupported public key type")
    return body + _address_checksum(body)

def _encode_bech32_address(public_key):
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise ValueError("Bech32 addresses are only supported for Ed25519 keys")
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    data = bech32_codec.convertbits(raw, 8, 5, True)
    return bech32_codec.encode(BECH32_HRP, data, bech32_codec.BECH32M_CONST)

def encode_address(public_key, scheme=ADDRESS_SCHEME_HEX):
    if scheme == ADDRESS_SCHEME_HEX:
        return _encode_hex_address(public_key)
    if scheme == ADDRESS_SCHEME_BECH32:
        return _encode_bech32_address(public_key)
    raise ValueError(f"unknown address scheme {scheme!r}")

def _decode_hex_address(address):
    if any(c not in _HEX_DIGITS for c in address):
        raise ValueError("address must be lowercase hex")
    body, checksum = address[:-ADDRESS_CHECKSUM_LEN], address[-ADDRESS_CHECKSUM_LEN:]
    if _address_checksum(body) != checksum:
        raise ValueError("address checksum mismatch")
    version, payload = body[0], body[1:]
    if version == ADDRESS_VERSION_RSA:
        if len(payload) != RSA_MODULUS_HEX_LEN:
            raise ValueError("invalid RSA address length")
        numbers = rsa.RSAPublicNumbers(RSA_PUBLIC_EXPONENT, int(payload, 16))
        return numbers.public_key()
    if version == ADDRESS_VERSION_ED25519:
        if len(payload) != ED25519_PUBLIC_HEX_LEN:
            raise ValueError("invalid Ed25519 address length")
        return ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(payload))
    raise ValueError(f"unknown address version {version!r}")

def _decode_bech32_address(address):
    hrp, data = bech32_codec.decode(address, bech32_codec.BECH32M_CONST)
    if hrp != BECH32_HRP:
        raise ValueError(f"address prefix must be {BECH32_HRP!r}")
    payload = bech32_codec.convertbits(data, 5, 8, False)
    if payload is None or len(payload) != ED25519_PUBLIC_BYTES_LEN:
        raise ValueError("invalid Bech32 address length")
    return ed25519.Ed25519PublicKey.from_public_bytes(bytes(payload))

def _parse_address(address):
    if not isinstance(address, str) or len(address) <= ADDRESS_CHECKSUM_LEN:
        raise ValueError("address must be a non-empty string")
    hex_like = all(c in _HEX_DIGITS for c in address)
    try:
        return _decode_hex_address(address), ADDRESS_SCHEME_HEX
    except ValueError as hex_error:
        try:
            return _decode_bech32_address(address), ADDRESS_SCHEME_BECH32
        except ValueError as bech32_error:
            raise (hex_error if hex_like else bech32_error) from None

def decode_address(address):
    return _parse_address(address)[0]

def address_scheme(address):
    return _parse_address(address)[1]

@lru_cache(maxsize=4096)
def _canonical_address_cached(address):
    public_key, scheme = _parse_address(address)
    if scheme == ADDRESS_SCHEME_BECH32:
        return _encode_hex_address(public_key)
    return address

def canonical_address(address):
    if not isinstance(address, str):
        raise ValueError("address must be a string")
    return _canonical_address_cached(address)

def _address_allowed(scheme, height):
    return (scheme == ADDRESS_SCHEME_HEX
            or height is None
            or height >= BECH32_ACTIVATION)

def is_valid_address(address, height=None):
    try:
        _, scheme = _parse_address(address)
    except (ValueError, TypeError):
        return False
    return _address_allowed(scheme, height)

def address_from_public_key(public_key, scheme=ADDRESS_SCHEME_HEX):
    return encode_address(public_key, scheme)

def load_key_address(path=None, scheme=ADDRESS_SCHEME_HEX):
    key_file = Path(path) if path else DEFAULT_KEY_FILE
    with open(key_file, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return address_from_public_key(public_key, scheme)

def display_key_address(path=None, scheme=None, height=None):
    if scheme is None and height is not None:
        scheme = (ADDRESS_SCHEME_BECH32 if height >= BECH32_ACTIVATION
                  else ADDRESS_SCHEME_HEX)
    scheme = scheme or getattr(config, "ADDRESS_DISPLAY", ADDRESS_SCHEME_BECH32)
    try:
        return load_key_address(path, scheme)
    except ValueError:
        if scheme == ADDRESS_SCHEME_BECH32:
            return load_key_address(path, ADDRESS_SCHEME_HEX)
        raise

def load_private_key(path="private_key.pem", password=None):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)

def _validated_memo(memo):
    if memo is None or memo == "":
        return None
    if not isinstance(memo, str):
        raise ValueError("memo must be a string")
    if len(memo.encode("utf-8")) > TX_MEMO_MAX:
        raise ValueError(f"memo exceeds {TX_MEMO_MAX} bytes")
    return memo

def tx_signing_payload(sender, receiver, amount, nonce, memo=None,
                       version=TX_VERSION_LEGACY):
    if version not in (TX_VERSION_LEGACY, TX_VERSION_ATOMS):
        raise ValueError("unsupported transaction version")
    payload = {
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "nonce": nonce,
    }
    if version == TX_VERSION_ATOMS:
        payload["version"] = TX_VERSION_ATOMS
    if memo:
        payload["memo"] = memo
    return json.dumps(payload, sort_keys=True).encode()

def verify_transaction(sender, signature, transaction_string):
    try:
        public_key = decode_address(sender)
        signature_bytes = bytes.fromhex(signature)
    except (ValueError, TypeError):
        return False

    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature_bytes,
                transaction_string,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        else:
            public_key.verify(signature_bytes, transaction_string)
        return True
    except (InvalidSignature, ValueError):
        return False

def sign_transaction(private_key, sender, receiver, amount, nonce=0, memo=None,
                     version=TX_VERSION_LEGACY):
    memo = _validated_memo(memo)
    if version == TX_VERSION_ATOMS:
        if isinstance(amount, bool) or not isinstance(amount, int):
            raise ValueError("atom amounts must be integers")
        if amount < 0 or amount > MAX_AMOUNT_ATOMS:
            raise ValueError("amount is out of range")
    else:
        coins_to_atoms(amount)
    transaction_string = tx_signing_payload(
        sender, receiver, amount, nonce, memo, version=version)

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


def tx_hash(tx):
    canonical = json.dumps(tx, sort_keys=True)
    return hashlib.sha256(canonical.encode()).digest()


def merkle_root(transactions):
    if not transactions:
        return EMPTY_MERKLE_ROOT
    layer = [tx_hash(tx) for tx in transactions]
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [hashlib.sha256(layer[i] + layer[i + 1]).digest()
                 for i in range(0, len(layer), 2)]
    return layer[0]


def pow_v2_header_parts(index, timestamp, transactions, previous_hash, miner):
    prefix = (
        bytes([POW_V2_VERSION])
        + int(index).to_bytes(8, "big")
        + int(timestamp).to_bytes(8, "big")
    )
    suffix = (
        bytes.fromhex(previous_hash)
        + merkle_root(transactions)
        + hashlib.sha256((miner or "").encode()).digest()
    )
    return prefix, suffix


def pow_v2_preimage(index, timestamp, transactions, previous_hash, miner, nonce):
    prefix, suffix = pow_v2_header_parts(
        index, timestamp, transactions, previous_hash, miner)
    nonce_bytes = f"{nonce:0{POW_V2_NONCE_DIGITS}d}".encode("ascii")
    return prefix + nonce_bytes + suffix


def network_id():
    params = {
        "model": "target-int",
        "CONSENSUS_VERSION": CONSENSUS_VERSION,
        "RETARGET_INTERVAL": config.RETARGET_INTERVAL,
        "TARGET_BLOCK_TIME": config.TARGET_BLOCK_TIME,
        "MIN_DIFFICULTY": config.MIN_DIFFICULTY,
        "MAX_DIFFICULTY": config.MAX_DIFFICULTY,
        "REWARD": config.REWARD,
        "TRANSACTION_FEE": TRANSACTION_FEE,
        "COIN_DECIMALS": COIN_DECIMALS,
        "ATOMIC_ACTIVATION": ATOMIC_ACTIVATION,
        "BECH32_ACTIVATION": BECH32_ACTIVATION,
        "TX_MEMO_MAX": TX_MEMO_MAX,
        "MAX_FUTURE_DRIFT": MAX_FUTURE_DRIFT,
        "MTP_WINDOW": MTP_WINDOW,
        "GENESIS": config.GENESIS,
        "RETARGET_FACTOR": RETARGET_FACTOR,
        "POW": "v2-header-merkle",
        "POW_V2_ACTIVATION": POW_V2_ACTIVATION,
    }
    return hashlib.sha256(json.dumps(params, sort_keys=True).encode()).hexdigest()

class Block:
    def __init__(self, index, transactions, previous_hash, miner=None,
                 difficulty=0, nonce=0, timestamp=None):
        self.index = index
        if timestamp is None:
            timestamp = int(time.time())
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
            raise ValueError("timestamp must be an integer")
        if isinstance(timestamp, float) and not math.isfinite(timestamp):
            raise ValueError("timestamp must be finite")
        self.timestamp = int(timestamp)
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.miner = miner
        self.difficulty = difficulty
        self.nonce = nonce
        self.target = (1 << 256) // difficulty \
            if isinstance(difficulty, int) and difficulty > 0 else None
        if self.index >= POW_V2_ACTIVATION:
            self._pow_prefix, self._pow_suffix = pow_v2_header_parts(
                self.index, self.timestamp, self.transactions,
                self.previous_hash, self.miner)
        else:
            self._pow_prefix = self._pow_suffix = None
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        if self.index >= POW_V2_ACTIVATION:
            if getattr(self, "_pow_prefix", None) is None:
                self._pow_prefix, self._pow_suffix = pow_v2_header_parts(
                    self.index, self.timestamp, self.transactions,
                    self.previous_hash, self.miner)
            nonce_bytes = f"{self.nonce:0{POW_V2_NONCE_DIGITS}d}".encode("ascii")
            return hashlib.sha256(
                self._pow_prefix + nonce_bytes + self._pow_suffix).hexdigest()
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
        if self.target is None:
            return False
        return int(self.hash, 16) < self.target

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
        if not isinstance(data, dict):
            raise ValueError("block must be an object")

        index = data.get("index")
        if isinstance(index, bool) or not isinstance(index, int) or index < 0 \
                or index > MAX_BLOCK_INDEX:
            raise ValueError("invalid block index")

        timestamp = data.get("timestamp")
        if isinstance(timestamp, bool) or not isinstance(timestamp, int) \
                or timestamp < 0 or timestamp > MAX_BLOCK_TIMESTAMP:
            raise ValueError("invalid block timestamp")

        transactions = data.get("transactions")
        if not isinstance(transactions, list) \
                or len(transactions) > MAX_BLOCK_TRANSACTIONS:
            raise ValueError("invalid block transactions")

        previous_hash = data.get("previous_hash")
        if not isinstance(previous_hash, str) or not previous_hash:
            raise ValueError("invalid previous hash")
        if index == 0:
            if previous_hash != "0":
                raise ValueError("invalid genesis previous hash")
        elif len(previous_hash) != 64 or \
                any(c not in _HEX_DIGITS for c in previous_hash):
            raise ValueError("invalid previous hash")

        miner = data.get("miner")
        if not isinstance(miner, str) or not miner:
            raise ValueError("invalid block miner")

        difficulty = data.get("difficulty")
        if isinstance(difficulty, bool) or not isinstance(difficulty, int) \
                or difficulty <= 0 or difficulty > MAX_BLOCK_DIFFICULTY:
            raise ValueError("invalid block difficulty")

        nonce = data.get("nonce")
        if isinstance(nonce, bool) or not isinstance(nonce, int) or nonce < 0 \
                or nonce > MAX_BLOCK_NONCE:
            raise ValueError("invalid block nonce")

        return cls(
            index=index,
            transactions=transactions,
            previous_hash=previous_hash,
            miner=miner,
            difficulty=difficulty,
            nonce=nonce,
            timestamp=timestamp,
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
    _schema_version = 6

    def __init__(self, difficulty=config.DIFFICULTY, reward=config.REWARD,
                 miner_address=None, chain_file=CHAIN_FILE):
        self.chain = []
        self.unconfirmed_transactions = []
        self.pending_debits = {}
        self.difficulty = difficulty
        if isinstance(reward, bool):
            raise ValueError("reward must be a number")
        self.reward = reward if isinstance(reward, int) else coins_to_atoms(reward)
        self.miner_address = miner_address or load_key_address()
        self.chain_file = Path(chain_file)
        self._lock = threading.Lock()
        self._deterministic = bool(
            miner_address is None and difficulty == config.DIFFICULTY)
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
        schema = state.get("_schema_version")
        if schema not in (5, 6):
            raise ValueError("incompatible persisted chain")
        self.chain = state["chain"]
        self.unconfirmed_transactions = state["unconfirmed_transactions"]
        self.pending_debits = {}
        self.difficulty = state["difficulty"]
        reward = state["reward"]
        if schema == 5:
            reward = coins_to_atoms(reward)
        self.reward = reward
        self.miner_address = state.get("miner_address") or load_key_address()
        self.chain_file = CHAIN_FILE
        self._lock = threading.Lock()
        self._prune_invalid_mempool()

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
            if getattr(instance, "_lock", None) is None:
                instance._lock = threading.Lock()
            if not instance.is_chain_valid():
                logger.warning("stored chain invalid on load; "
                               "starting fresh from deterministic genesis")
                return cls(chain_file=chain_file)
            return instance
        except Exception:
            return cls(chain_file=chain_file)

    def create_genesis_block(self):
        if self._deterministic and config.GENESIS:
            spec = config.GENESIS
            genesis = Block(
                0, [], "0", miner=spec["miner"], difficulty=spec["difficulty"],
                nonce=spec["nonce"], timestamp=spec["timestamp"],
            )
        else:
            miner = self.miner_address
            try:
                _, miner_scheme = _parse_address(miner)
            except (ValueError, TypeError):
                miner_scheme = None
            if miner_scheme == ADDRESS_SCHEME_BECH32 and not _address_allowed(miner_scheme, 0):
                miner = canonical_address(miner)
            genesis = Block(0, [], "0", miner=miner,
                            difficulty=self.difficulty)
            genesis.mine()
        self.chain.append(genesis)

    def difficulty_at_next(self, chain=None):
        chain = chain if chain is not None else self.chain
        if not chain:
            return config.MIN_DIFFICULTY
        if len(chain) % config.RETARGET_INTERVAL != 0:
            return chain[-1].difficulty
        window = chain[-(config.RETARGET_INTERVAL + 1):] \
            if len(chain) >= config.RETARGET_INTERVAL + 1 else chain[:]
        span = window[-1].timestamp - window[0].timestamp
        target_window = config.RETARGET_INTERVAL * config.TARGET_BLOCK_TIME
        prev = chain[-1].difficulty
        candidate = prev * target_window // max(1, int(round(span)))
        lo = max(config.MIN_DIFFICULTY, prev // RETARGET_FACTOR)
        hi = min(config.MAX_DIFFICULTY, prev * RETARGET_FACTOR)
        return min(hi, max(lo, candidate))

    @property
    def last_block(self):
        return self.chain[-1]

    def next_timestamp(self):
        now = int(time.time())
        if len(self.chain) < ATOMIC_ACTIVATION or not self.chain:
            return now
        prior = self.chain[-MTP_WINDOW:]
        median = sorted(block.timestamp for block in prior)[len(prior) // 2]
        return max(now, median + 1)

    @property
    def height(self):
        return len(self.chain)

    def chain_page(self, from_index=0, limit=None):
        with self._lock:
            chain = self.chain
            height = len(chain)
            start = max(0, min(from_index, height))
            end = height if limit is None else min(height, start + max(0, limit))
            blocks = [block.to_dict() for block in chain[start:end]]
            genesis = chain[0].hash if chain else None
            tip = chain[-1].hash if chain else None
        has_more = end < height
        return {
            "height": height,
            "from_index": start,
            "count": len(blocks),
            "blocks": blocks,
            "genesis": genesis,
            "tip": tip,
            "has_more": has_more,
            "next_from": end if has_more else None,
        }

    def tx_id(self, tx):
        version = tx_version(tx)
        try:
            sender = canonical_address(tx["sender"])
            receiver = canonical_address(tx["receiver"])
            payload = tx_signing_payload(
                sender, receiver, tx["amount"], tx["nonce"], tx.get("memo"),
                version=version)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("invalid transaction") from exc
        return hashlib.sha256(payload).hexdigest()

    def get_balance(self, address):
        try:
            address = canonical_address(address)
        except (ValueError, TypeError):
            return 0
        balances = self.rebuild_balances(self.chain) or {}
        return balances.get(address, 0)

    def _validated_transaction(self, tx, height, verify):
        if not isinstance(tx, dict):
            raise ValueError("invalid transaction")
        version = tx_version(tx)
        expected = (TX_VERSION_ATOMS if height >= ATOMIC_ACTIVATION
                    else TX_VERSION_LEGACY)
        if version != expected:
            raise ValueError("wrong transaction version for height")

        amount = tx.get("amount")
        amount_atoms = amount_atoms_for_height(amount, version, height)

        nonce = tx.get("nonce")
        if isinstance(nonce, bool) or not isinstance(nonce, int):
            raise ValueError("invalid nonce")

        sender = tx.get("sender")
        receiver = tx.get("receiver")
        signature = tx.get("signature")
        if not isinstance(sender, str) or not sender:
            raise ValueError("invalid sender")
        if not isinstance(receiver, str) or not receiver:
            raise ValueError("invalid receiver")
        if not isinstance(signature, str) or not signature:
            raise ValueError("invalid signature")
        memo = _validated_memo(tx.get("memo"))

        if verify:
            transaction_string = tx_signing_payload(
                sender, receiver, amount, nonce, memo, version=version)
            if not verify_transaction(sender, signature, transaction_string):
                raise ValueError("invalid signature")

        _, sender_scheme = _parse_address(sender)
        _, receiver_scheme = _parse_address(receiver)
        if not (_address_allowed(sender_scheme, height)
                and _address_allowed(receiver_scheme, height)):
            raise ValueError("address not active at this height")
        return (canonical_address(sender), canonical_address(receiver),
                amount_atoms)

    def rebuild_balances(self, chain, verify=False):
        try:
            balances = {}
            seen_txids = set()
            for index, block in enumerate(chain):
                if not isinstance(block, Block):
                    return None
                if not isinstance(block.miner, str) or not block.miner:
                    return None
                if not isinstance(block.transactions, list):
                    return None

                try:
                    miner_key, miner_scheme = _parse_address(block.miner)
                except (ValueError, TypeError):
                    if index >= ATOMIC_ACTIVATION:
                        return None
                    miner_key, miner_scheme = None, None
                if miner_scheme == ADDRESS_SCHEME_BECH32:
                    if not _address_allowed(miner_scheme, index):
                        return None
                    miner_address = _encode_hex_address(miner_key)
                else:
                    miner_address = block.miner
                balances[miner_address] = balances.get(miner_address, 0) + self.reward

                for tx in block.transactions:
                    try:
                        txid = self.tx_id(tx)
                        if txid in seen_txids:
                            return None
                        seen_txids.add(txid)
                        sender, receiver, amount_atoms = \
                            self._validated_transaction(tx, index, verify)
                    except (KeyError, TypeError, ValueError):
                        return None

                    fee = transaction_fee_atoms(index)
                    required = amount_atoms + fee
                    if balances.get(sender, 0) < required:
                        return None
                    balances[sender] = balances.get(sender, 0) - required
                    balances[receiver] = balances.get(receiver, 0) + amount_atoms
            return balances
        except (KeyError, TypeError, ValueError, OverflowError):
            logger.warning("invalid balances rejected", exc_info=True)
            return None

    def add_transaction(self, sender, receiver, amount, signature, nonce=0,
                        memo=None, version=None):
        next_height = len(self.chain)
        expected_version = (TX_VERSION_ATOMS if next_height >= ATOMIC_ACTIVATION
                            else TX_VERSION_LEGACY)
        if version is None:
            version = expected_version
        if isinstance(version, bool) or not isinstance(version, int):
            return False
        if version != expected_version:
            return False
        if isinstance(nonce, bool) or not isinstance(nonce, int):
            return False
        try:
            amount_atoms = amount_atoms_for_height(amount, version, next_height)
            memo = _validated_memo(memo)
        except ValueError:
            return False

        if not is_valid_address(sender, next_height):
            return False
        if not is_valid_address(receiver, next_height):
            return False

        transaction_string = tx_signing_payload(
            sender, receiver, amount, nonce, memo, version=version)

        try:
            if not verify_transaction(sender, signature, transaction_string):
                return False
        except ValueError:
            return False

        canonical_sender = canonical_address(sender)
        fee = transaction_fee_atoms(next_height)
        with self._lock:
            balances = self.rebuild_balances(self.chain) or {}
            available = (balances.get(canonical_sender, 0)
                         - self.pending_debits.get(canonical_sender, 0))
            if available < amount_atoms + fee:
                return False

            tx = {
                "sender": sender,
                "receiver": receiver,
                "amount": amount,
                "nonce": nonce,
                "signature": signature
            }
            if version == TX_VERSION_ATOMS:
                tx["version"] = version
            if memo:
                tx["memo"] = memo
            if self.mempool_has(tx):
                return False
            self.unconfirmed_transactions.append(tx)
            self.pending_debits[canonical_sender] = (
                self.pending_debits.get(canonical_sender, 0)
                + amount_atoms + fee)
            self.save()
        return True

    def mine_block_candidate(self):
        with self._lock:
            self._prune_invalid_mempool()
            if not self.unconfirmed_transactions:
                return None
            index = len(self.chain)
            miner = self.miner_address
            try:
                _, miner_scheme = _parse_address(miner)
            except (ValueError, TypeError):
                miner_scheme = None
            if miner_scheme == ADDRESS_SCHEME_BECH32 and not _address_allowed(miner_scheme, index):
                miner = canonical_address(miner)
            return {
                "index": index,
                "transactions": list(self.unconfirmed_transactions),
                "previous_hash": self.last_block.hash,
                "miner": miner,
                "difficulty": self.difficulty_at_next(),
                "timestamp": self.next_timestamp(),
            }

    def commit_mined(self, block_dict):
        try:
            block = Block.from_dict(block_dict)
        except (KeyError, TypeError, ValueError, OverflowError):
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
            self._prune_invalid_mempool()
            self.save()
        return True

    def mine_pending_transactions(self, yield_every=1024):
        candidate = self.mine_block_candidate()
        if candidate is None:
            return False
        return self.commit_mined(solve_block(candidate, yield_every=yield_every))

    def validate_chain(self, chain):
        try:
            if not chain:
                return False

            for i, block in enumerate(chain):
                if not isinstance(block, Block):
                    return False
                if block.index != i:
                    return False
                if not isinstance(block.miner, str) or not block.miner:
                    return False
                if not isinstance(block.transactions, list) \
                        or len(block.transactions) > MAX_BLOCK_TRANSACTIONS:
                    return False
                if not isinstance(block.timestamp, int) \
                        or block.timestamp < 0 \
                        or block.timestamp > MAX_BLOCK_TIMESTAMP:
                    return False
                if isinstance(block.nonce, bool) or not isinstance(block.nonce, int) \
                        or block.nonce < 0 or block.nonce > MAX_BLOCK_NONCE:
                    return False
                if isinstance(block.difficulty, bool) \
                        or not isinstance(block.difficulty, int) \
                        or block.difficulty <= 0 \
                        or block.difficulty > MAX_BLOCK_DIFFICULTY:
                    return False
                if block.hash != block.calculate_hash():
                    return False
                if not block.is_mined():
                    return False
                if i == 0:
                    if block.previous_hash != "0":
                        return False
                else:
                    if block.previous_hash != chain[i - 1].hash:
                        return False
                    if block.difficulty != self.difficulty_at_next(chain[:i]):
                        return False

                if i >= ATOMIC_ACTIVATION:
                    if block.timestamp > int(time.time()) + MAX_FUTURE_DRIFT:
                        return False
                    prior = chain[max(0, i - MTP_WINDOW):i]
                    if prior:
                        median = sorted(b.timestamp for b in prior)[len(prior) // 2]
                        if block.timestamp <= median:
                            return False

            return self.rebuild_balances(chain, verify=True) is not None
        except (KeyError, TypeError, ValueError, OverflowError):
            logger.warning("invalid chain rejected", exc_info=True)
            return False

    def add_block(self, block_dict):
        try:
            block = Block.from_dict(block_dict)
        except (KeyError, TypeError, ValueError, OverflowError):
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
            self._prune_invalid_mempool()
            self.save()
        return True

    def adopt_chain(self, block_dicts):
        try:
            blocks = [Block.from_dict(b) for b in block_dicts]
        except (KeyError, TypeError, ValueError, OverflowError):
            return False

        with self._lock:
            if not blocks or not self.chain:
                return False
            if blocks[0].hash != self.chain[0].hash:
                return False
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
            self._prune_invalid_mempool()
            self.save()
        return True

    def mempool_has(self, tx):
        try:
            txid = self.tx_id(tx)
        except ValueError:
            return False
        for confirmed in self.chain:
            for confirmed_tx in confirmed.transactions:
                try:
                    if self.tx_id(confirmed_tx) == txid:
                        return True
                except ValueError:
                    continue
        for pending in self.unconfirmed_transactions:
            try:
                if self.tx_id(pending) == txid:
                    return True
            except ValueError:
                continue
        return False

    def _drop_confirmed(self):
        confirmed = set()
        for block in self.chain:
            for tx in block.transactions:
                try:
                    confirmed.add(self.tx_id(tx))
                except ValueError:
                    continue
        kept = []
        for tx in self.unconfirmed_transactions:
            try:
                if self.tx_id(tx) not in confirmed:
                    kept.append(tx)
            except ValueError:
                continue
        self.unconfirmed_transactions = kept

    def _prune_invalid_mempool(self):
        next_height = len(self.chain)
        expected_version = (TX_VERSION_ATOMS if next_height >= ATOMIC_ACTIVATION
                            else TX_VERSION_LEGACY)
        fee = transaction_fee_atoms(next_height)
        balances = dict(self.rebuild_balances(self.chain) or {})
        pending = {}
        kept = []
        seen = set()
        for tx in self.unconfirmed_transactions:
            try:
                if tx_version(tx) != expected_version:
                    continue
                amount_atoms = tx_amount_atoms(tx, next_height)
                sender = tx["sender"]
                receiver = tx["receiver"]
                if not is_valid_address(sender, next_height):
                    continue
                if not is_valid_address(receiver, next_height):
                    continue
                sender = canonical_address(sender)
                receiver = canonical_address(receiver)
                txid = self.tx_id(tx)
            except (KeyError, ValueError, TypeError):
                continue
            if txid in seen:
                continue
            required = amount_atoms + fee
            if balances.get(sender, 0) < required:
                continue
            balances[sender] = balances.get(sender, 0) - required
            balances[receiver] = balances.get(receiver, 0) + amount_atoms
            pending[sender] = pending.get(sender, 0) + required
            seen.add(txid)
            kept.append(tx)
        self.unconfirmed_transactions = kept
        self.pending_debits = pending

    def _recompute_pending(self):
        next_height = len(self.chain)
        fee = transaction_fee_atoms(next_height)
        pending = {}
        for tx in self.unconfirmed_transactions:
            try:
                sender = canonical_address(tx["sender"])
                required = tx_amount_atoms(tx, next_height) + fee
            except (KeyError, ValueError, TypeError):
                continue
            pending[sender] = pending.get(sender, 0) + required
        self.pending_debits = pending

    def is_chain_valid(self):
        return self.validate_chain(self.chain)