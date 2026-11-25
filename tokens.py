# SPDX-FileCopyrightText: © 2026 thecoolguy62aws
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Off-chain secondary tokens carried in cool62coin transaction memos.

``c62tok1`` is a client-side protocol: nodes see only opaque memo strings and
every wallet replays the canonical chain to compute the same token state.
This module is the reference implementation.
"""

import argparse
import base64
import copy
import hashlib
import json
import secrets
import shlex
from collections import namedtuple
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import quote

import requests
from cryptography.hazmat.primitives import serialization

import config
from core import (ADDRESS_SCHEME_BECH32, ADDRESS_SCHEME_HEX, ATOMIC_ACTIVATION,
                  BECH32_ACTIVATION, TX_MEMO_MAX, TX_VERSION_ATOMS,
                  TX_VERSION_LEGACY, address_from_public_key, canonical_address,
                  decode_address, format_atoms, is_valid_address,
                  load_private_key, sign_transaction, transaction_fee_atoms,
                  tx_amount_atoms, tx_signing_payload, tx_version,
                  verify_transaction)

DEFAULT_NODE = "http://127.0.0.1:8090"
REMOTE_NODE = "https://coinnode.cool62.net/"
DEFAULT_KEY = "private_key.pem"
STATE_FILE = Path("token_state.json")

TOKEN_PREFIX = "c62tok1:"
PROTOCOL_VERSION = 1
OP_ISSUE = 1
OP_MINT = 2
OP_TRANSFER = 3
OP_BURN = 4
OP_PUBLIC_MINT = 5
OP_SET_AUTHORITY = 6
OP_NAMES = {
    OP_ISSUE: "issue", OP_MINT: "mint", OP_TRANSFER: "transfer",
    OP_BURN: "burn", OP_PUBLIC_MINT: "public_mint",
    OP_SET_AUTHORITY: "set_authority",
}
POLICY_FIXED = 0
POLICY_CAPPED = 1
POLICY_OPEN = 2
POLICY_NAMES = {"fixed": POLICY_FIXED, "capped": POLICY_CAPPED,
                "open": POLICY_OPEN}
POLICY_LABELS = {POLICY_FIXED: "fixed", POLICY_CAPPED: "capped",
                 POLICY_OPEN: "open"}
MAX_NAME = 16
MAX_AUTHORITY = 80
MAX_METADATA = 64
MAX_NOTE = 32
MAX_DECIMALS = 18
MAX_U64 = (1 << 64) - 1
ASSET_ID_BYTES = 16
GENESIS_DOMAIN = b"c62tok1-asset-v2"
NO_AUTHORITY = "\x00"
NO_AUTHORITY_LABEL = "none"
STATE_VERSION = 2
_NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

TokenOp = namedtuple("TokenOp", """
    op seq asset_id name decimals policy initial max_supply mint_amount
    mint_cap start_height end_height authority metadata amount note
""")


class TokenError(Exception):
    pass


# ---------------------------------------------------------------------------
# encoding
# ---------------------------------------------------------------------------

def _b64encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text):
    allowed = frozenset(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    if not isinstance(text, str) or any(c not in allowed for c in text):
        raise TokenError("token payload is not valid base64url")
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4),
                                altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise TokenError("token payload is not valid base64url") from exc


def _u64(value):
    if isinstance(value, bool) or not isinstance(value, int):
        raise TokenError("integer fields must be integers")
    if value < 0 or value > MAX_U64:
        raise TokenError("integer field is out of range")
    return value.to_bytes(8, "little")


def _name_text(name):
    if not isinstance(name, str):
        raise TokenError("name must be a string")
    text = name.strip().upper()
    if not 1 <= len(text) <= MAX_NAME or any(c not in _NAME_CHARS for c in text):
        raise TokenError(f"name must be 1-{MAX_NAME} characters, A-Z or 0-9")
    return text


def _name_bytes(name):
    return _name_text(name).ljust(MAX_NAME, "\0").encode("ascii")


def _decode_name(data):
    raw = data[:MAX_NAME]
    head, _, tail = raw.partition(b"\x00")
    if not head or any(c not in _NAME_CHARS for c in head.decode("ascii", "replace")):
        raise TokenError("invalid asset name")
    if any(byte != 0 for byte in tail):
        raise TokenError("invalid name padding")
    return head.decode("ascii")


def _text_field(value, limit, label):
    if not isinstance(value, str):
        raise TokenError(f"{label} must be a string")
    encoded = value.encode("utf-8")
    if len(encoded) > limit:
        raise TokenError(f"{label} exceeds {limit} bytes")
    return encoded


def _is_none_authority(value):
    return value == NO_AUTHORITY or (
        isinstance(value, str) and value.lower() == NO_AUTHORITY_LABEL)


def _authority_bytes(value):
    if _is_none_authority(value):
        return b"\x00"
    encoded = _text_field(value, MAX_AUTHORITY, "authority")
    if b"\x00" in encoded:
        raise TokenError("invalid authority")
    return encoded


def _decode_authority(data):
    if data == b"\x00":
        return NO_AUTHORITY
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TokenError("authority is not UTF-8") from exc
    if "\x00" in text:
        raise TokenError("invalid authority")
    return text


def _asset_bytes(asset_id):
    if not isinstance(asset_id, str) or len(asset_id) != ASSET_ID_BYTES * 2:
        raise TokenError("asset id must be 32 hex characters")
    try:
        return bytes.fromhex(asset_id)
    except ValueError as exc:
        raise TokenError("asset id must be hex") from exc


def encode_op(op, seq, *, asset_id=None, name=None, decimals=0,
              policy=POLICY_FIXED, initial=0, max_supply=0, mint_amount=0,
              mint_cap=0, start_height=0, end_height=0, authority="",
              metadata="", amount=0, note=""):
    """Return a memo string encoding one token operation."""
    if op not in OP_NAMES:
        raise TokenError("unknown operation")
    data = bytearray([PROTOCOL_VERSION, op]) + _u64(seq)
    if op == OP_ISSUE:
        data += _name_bytes(name)
        if isinstance(decimals, bool) or not isinstance(decimals, int) \
                or not 0 <= decimals <= MAX_DECIMALS:
            raise TokenError(f"decimals must be 0-{MAX_DECIMALS}")
        if policy not in (POLICY_FIXED, POLICY_CAPPED, POLICY_OPEN):
            raise TokenError("unknown supply policy")
        data.append(decimals)
        data.append(policy)
        for value in (initial, max_supply, mint_amount, mint_cap,
                      start_height, end_height):
            data += _u64(value)
        auth = _authority_bytes(authority)
        data.append(len(auth))
        data += auth
        meta = _text_field(metadata, MAX_METADATA, "metadata")
        data.append(len(meta))
        data += meta
    elif op == OP_SET_AUTHORITY:
        data += _asset_bytes(asset_id)
        auth = _authority_bytes(authority)
        data.append(len(auth))
        data += auth
    elif op == OP_PUBLIC_MINT:
        data += _asset_bytes(asset_id)
    else:
        data += _asset_bytes(asset_id)
        data += _u64(amount)
    note_bytes = _text_field(note, MAX_NOTE, "note")
    data.append(len(note_bytes))
    data += note_bytes
    memo = TOKEN_PREFIX + _b64encode(bytes(data))
    if len(memo.encode("utf-8")) > TX_MEMO_MAX:
        raise TokenError("encoded operation exceeds the node memo limit")
    return memo


def decode_op(memo):
    """Parse a token memo. Raises TokenError for anything malformed."""
    if not isinstance(memo, str) or not memo.startswith(TOKEN_PREFIX):
        raise TokenError("not a c62tok1 memo")
    if len(memo.encode("utf-8")) > TX_MEMO_MAX:
        raise TokenError("memo exceeds the node memo limit")
    data = _b64decode(memo[len(TOKEN_PREFIX):])
    if len(data) < 10:
        raise TokenError("token payload is too short")
    version, op = data[0], data[1]
    seq = int.from_bytes(data[2:10], "little")
    if version != PROTOCOL_VERSION:
        raise TokenError("unsupported token protocol version")

    fields = dict.fromkeys(TokenOp._fields)
    fields.update(op=op, seq=seq)
    offset = 10

    if op == OP_ISSUE:
        if len(data) < offset + MAX_NAME + 2 + 48:
            raise TokenError("issue payload is too short")
        fields["name"] = _decode_name(data[offset:offset + MAX_NAME])
        offset += MAX_NAME
        decimals, policy = data[offset], data[offset + 1]
        offset += 2
        if decimals > MAX_DECIMALS or policy not in (POLICY_FIXED, POLICY_CAPPED,
                                                     POLICY_OPEN):
            raise TokenError("invalid decimals or supply policy")
        fields["decimals"], fields["policy"] = decimals, policy
        for key in ("initial", "max_supply", "mint_amount", "mint_cap",
                    "start_height", "end_height"):
            fields[key] = int.from_bytes(data[offset:offset + 8], "little")
            offset += 8
        for key, limit in (("authority", MAX_AUTHORITY),
                           ("metadata", MAX_METADATA)):
            if len(data) < offset + 1:
                raise TokenError("missing field length")
            length = data[offset]
            offset += 1
            if length > limit or len(data) < offset + length:
                raise TokenError(f"invalid {key} length")
            chunk = data[offset:offset + length]
            if key == "authority":
                fields[key] = _decode_authority(chunk)
            else:
                try:
                    fields[key] = chunk.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise TokenError(f"{key} is not UTF-8") from exc
            offset += length
    elif op == OP_SET_AUTHORITY:
        if len(data) < offset + ASSET_ID_BYTES + 1:
            raise TokenError("payload is too short")
        fields["asset_id"] = data[offset:offset + ASSET_ID_BYTES].hex()
        offset += ASSET_ID_BYTES
        length = data[offset]
        offset += 1
        if length > MAX_AUTHORITY or len(data) < offset + length:
            raise TokenError("invalid authority length")
        fields["authority"] = _decode_authority(data[offset:offset + length])
        offset += length
    elif op == OP_PUBLIC_MINT:
        if len(data) < offset + ASSET_ID_BYTES:
            raise TokenError("payload is too short")
        fields["asset_id"] = data[offset:offset + ASSET_ID_BYTES].hex()
        offset += ASSET_ID_BYTES
    elif op in (OP_MINT, OP_TRANSFER, OP_BURN):
        if len(data) < offset + ASSET_ID_BYTES + 8:
            raise TokenError("payload is too short")
        fields["asset_id"] = data[offset:offset + ASSET_ID_BYTES].hex()
        offset += ASSET_ID_BYTES
        fields["amount"] = int.from_bytes(data[offset:offset + 8], "little")
        offset += 8
    else:
        raise TokenError("unknown token operation")

    if len(data) < offset + 1:
        raise TokenError("missing note length")
    note_len = data[offset]
    offset += 1
    if note_len > MAX_NOTE or len(data) != offset + note_len:
        raise TokenError("invalid note length")
    try:
        fields["note"] = data[offset:].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TokenError("note is not UTF-8") from exc
    return TokenOp(**fields)


def _public_key_bytes(address):
    public = decode_address(address)
    try:
        return public.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    except (ValueError, TypeError):
        return hashlib.sha256(public.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)).digest()


def asset_id_for(sender, name, genesis_hash):
    """Derive the 16-byte asset id from issuer, name and chain genesis."""
    if not isinstance(genesis_hash, str) or len(genesis_hash) != 64:
        raise TokenError("genesis hash is unavailable or malformed")
    try:
        genesis = bytes.fromhex(genesis_hash)
    except ValueError as exc:
        raise TokenError("genesis hash is not hex") from exc
    digest = hashlib.sha256()
    digest.update(GENESIS_DOMAIN)
    digest.update(genesis)
    digest.update(_public_key_bytes(sender))
    digest.update(_name_bytes(name))
    return digest.digest()[:ASSET_ID_BYTES].hex()


# ---------------------------------------------------------------------------
# state machine
# ---------------------------------------------------------------------------

def new_state(genesis=None):
    return {
        "version": STATE_VERSION,
        "genesis": genesis,
        "height": 0,
        "tip": None,
        "names": {},
        "assets": {},
        "balances": {},
        "sequences": {},
        "processed": {},
        "history": [],
    }


def _balance(state, asset_id, address):
    return state["balances"].get(asset_id, {}).get(address, 0)


def _set_balance(state, asset_id, address, value):
    if value < 0:
        raise TokenError("negative token balance")
    book = state["balances"].setdefault(asset_id, {})
    if value == 0:
        book.pop(address, None)
    else:
        book[address] = value


def _held_asset_ids(state, pending, address):
    """Asset ids the wallet holds now, has pending, or held in the past."""
    asset_ids = set()
    for snapshot in (state, pending):
        for asset_id, book in snapshot["balances"].items():
            if book.get(address, 0) > 0:
                asset_ids.add(asset_id)
    for event in state["history"]:
        asset_id = event.get("asset_id")
        if not asset_id:
            continue
        amount = event.get("amount", 0)
        if ((event.get("receiver") == address and amount > 0)
                or (event.get("sender") == address and amount > 0
                    and event.get("op") in (OP_NAMES[OP_TRANSFER],
                                            OP_NAMES[OP_BURN]))):
            asset_ids.add(asset_id)
    return asset_ids


def _verify_tx(tx):
    try:
        version = tx_version(tx)
        payload = tx_signing_payload(tx["sender"], tx["receiver"],
                                     tx["amount"], tx["nonce"],
                                     tx.get("memo"), version=version)
        return verify_transaction(tx["sender"], tx["signature"], payload)
    except (KeyError, TypeError, ValueError):
        return False


def tx_id(tx):
    """Match Blockchain.tx_id so dedup agrees with the node's view."""
    try:
        version = tx_version(tx)
        payload = tx_signing_payload(
            canonical_address(tx["sender"]), canonical_address(tx["receiver"]),
            tx["amount"], tx["nonce"], tx.get("memo"), version=version)
    except (KeyError, TypeError, ValueError) as exc:
        raise TokenError("invalid transaction") from exc
    return hashlib.sha256(payload).hexdigest()


def _authority(state, asset, height, authority):
    if authority == NO_AUTHORITY:
        return NO_AUTHORITY
    if not authority:
        return asset["issuer"]
    try:
        if not is_valid_address(authority, height):
            return None
        return canonical_address(authority)
    except (ValueError, TypeError):
        return None


def _next_seq(state, asset_id, sender, seq):
    expected = state["sequences"].get(asset_id, {}).get(sender, 0) + 1
    return (True, None) if seq == expected else (
        False, f"expected sequence {expected}, got {seq}")


def apply_op(state, tx, height):
    """Apply one transaction to the token state, atomically.

    Returns ``(True, None)`` on success or ``(False, reason)`` on rejection.
    Invalid operations never mutate state.
    """
    if not isinstance(tx, dict):
        return False, "invalid transaction"
    try:
        if tx_amount_atoms(tx, height) != 0:
            return False, "token transactions must have zero coin amount"
    except (ValueError, TypeError, KeyError):
        return False, "invalid coin amount"
    if not _verify_tx(tx):
        return False, "invalid signature"
    txid = tx_id(tx)
    if txid in state["processed"]:
        return False, "duplicate transaction"
    try:
        op = decode_op(tx.get("memo"))
        sender = canonical_address(tx["sender"])
        receiver = canonical_address(tx["receiver"])
    except (TokenError, KeyError, TypeError, ValueError) as exc:
        return False, str(exc)

    if op.op == OP_ISSUE:
        if op.seq != 1:
            return False, "issue sequence must be 1"
        if op.name in state["names"]:
            return False, f"name '{op.name}' is already taken"
        if op.policy == POLICY_FIXED:
            if op.initial < 1:
                return False, "fixed policy requires a positive initial supply"
            if op.max_supply or op.mint_amount or op.mint_cap \
                    or op.start_height or op.end_height:
                return False, "fixed supply cannot have mint terms"
        elif op.policy == POLICY_CAPPED:
            if op.max_supply < 1:
                return False, "capped policy requires a max supply"
            if op.max_supply < op.initial:
                return False, "max supply is below the initial supply"
            if op.mint_amount or op.mint_cap or op.start_height or op.end_height:
                return False, "capped supply cannot have public mint terms"
        else:
            if op.mint_amount < 1:
                return False, "open policy requires a positive mint amount"
            if op.max_supply and op.max_supply < op.initial:
                return False, "max supply is below the initial supply"
            if op.start_height and op.end_height and op.start_height > op.end_height:
                return False, "mint window is inverted"
        authority = _authority(state, {"issuer": sender}, height, op.authority)
        if authority is None:
            return False, "authority is not a valid address"
        asset_id = asset_id_for(tx["sender"], op.name, state.get("genesis"))
        state["assets"][asset_id] = {
            "id": asset_id,
            "name": op.name,
            "issuer": sender,
            "authority": authority,
            "decimals": op.decimals,
            "policy": op.policy,
            "supply": op.initial,
            "max_supply": op.max_supply,
            "mint_amount": op.mint_amount,
            "mint_cap": op.mint_cap,
            "mints_used": 0,
            "start_height": op.start_height,
            "end_height": op.end_height,
            "metadata": op.metadata,
            "height": height,
            "txid": txid,
        }
        state["names"][op.name] = asset_id
        _set_balance(state, asset_id, receiver,
                     _balance(state, asset_id, receiver) + op.initial)
        state["sequences"].setdefault(asset_id, {})[sender] = 1
        op = op._replace(asset_id=asset_id)
    else:
        asset = state["assets"].get(op.asset_id)
        if asset is None:
            return False, "unknown asset"

        if op.op == OP_PUBLIC_MINT:
            if asset["policy"] != POLICY_OPEN:
                return False, "asset does not allow public minting"
            if asset["start_height"] and height < asset["start_height"]:
                return False, "mint window has not opened"
            if asset["end_height"] and height > asset["end_height"]:
                return False, "mint window has closed"
            if asset["mint_cap"] and asset["mints_used"] >= asset["mint_cap"]:
                return False, "mint cap reached"
            amount = asset["mint_amount"]
            if asset["max_supply"] and asset["supply"] > asset["max_supply"] - amount:
                return False, "max supply reached"
            if asset["supply"] > MAX_U64 - amount:
                return False, "supply overflow"
            _set_balance(state, op.asset_id, receiver,
                         _balance(state, op.asset_id, receiver) + amount)
            asset["supply"] += amount
            asset["mints_used"] += 1
            op = op._replace(amount=amount)
        else:
            ok, reason = _next_seq(state, op.asset_id, sender, op.seq)
            if not ok:
                return False, reason
            if op.op == OP_SET_AUTHORITY:
                if sender != asset["authority"]:
                    return False, "only the authority may change authority"
                new_authority = _authority(state, asset, height, op.authority)
                if new_authority is None:
                    return False, "new authority is not a valid address"
                asset["authority"] = new_authority
            else:
                if op.op == OP_MINT:
                    if sender != asset["authority"]:
                        return False, "only the authority may mint"
                    if asset["policy"] == POLICY_FIXED:
                        return False, "asset has a fixed supply"
                    if asset["max_supply"] and op.amount > asset["max_supply"] - asset["supply"]:
                        return False, "max supply reached"
                if op.amount < 1:
                    return False, "amount must be positive"
                available = _balance(state, op.asset_id, sender)
                if op.op in (OP_TRANSFER, OP_BURN) and available < op.amount:
                    return False, "insufficient token balance"
                if op.op == OP_MINT:
                    if asset["supply"] > MAX_U64 - op.amount:
                        return False, "supply overflow"
                    asset["supply"] += op.amount
                    _set_balance(state, op.asset_id, receiver,
                                 _balance(state, op.asset_id, receiver) + op.amount)
                elif op.op == OP_TRANSFER:
                    _set_balance(state, op.asset_id, sender, available - op.amount)
                    _set_balance(state, op.asset_id, receiver,
                                 _balance(state, op.asset_id, receiver) + op.amount)
                else:
                    _set_balance(state, op.asset_id, sender, available - op.amount)
                    asset["supply"] -= op.amount
            state["sequences"][op.asset_id][sender] = op.seq

    state["processed"][txid] = height
    state["history"].append({
        "height": height,
        "txid": txid,
        "op": OP_NAMES[op.op],
        "seq": op.seq,
        "asset_id": op.asset_id,
        "name": state["assets"][op.asset_id]["name"] if op.asset_id else None,
        "sender": sender,
        "receiver": receiver,
        "amount": op.initial if op.op == OP_ISSUE else op.amount,
        "note": op.note,
    })
    return True, None


def _block_fields(block):
    if isinstance(block, dict):
        return block
    if hasattr(block, "to_dict"):
        return block.to_dict()
    raise TokenError("invalid block")


def replay(blocks, genesis=None):
    """Rebuild token state from a full canonical chain."""
    blocks = [_block_fields(block) for block in blocks]
    if genesis is None and blocks:
        genesis = blocks[0].get("hash")
    if genesis is not None and blocks and blocks[0].get("hash") != genesis:
        raise TokenError("chain does not start at the expected genesis")
    state = new_state(genesis)
    previous = None
    for block in blocks:
        index = block.get("index")
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            raise TokenError("invalid block index")
        if previous is None:
            if index != 0:
                raise TokenError("chain must start at index 0")
        elif block.get("previous_hash") != previous:
            raise TokenError(f"chain is not contiguous at block {index}")
        previous = block.get("hash")
        transactions = block.get("transactions")
        if not isinstance(transactions, list):
            raise TokenError("invalid transaction list")
        for tx in transactions:
            apply_op(state, tx, index)
        state["height"] = max(state["height"], index + 1)
    state["tip"] = previous
    return state


# ---------------------------------------------------------------------------
# node helpers
# ---------------------------------------------------------------------------

def _node(base, path, method="GET", body=None):
    url = base.rstrip("/") + path
    try:
        resp = requests.request(method, url, json=body, timeout=30)
    except requests.RequestException as exc:
        raise TokenError(f"cannot reach node ({exc})") from exc
    if resp.status_code >= 400:
        try:
            data = resp.json()
        except ValueError:
            data = {}
        raise TokenError(f"{resp.status_code} {data.get('error', resp.text)}")
    try:
        return resp.json()
    except ValueError as exc:
        raise TokenError("node returned invalid JSON") from exc


def _node_info(base):
    try:
        resp = requests.get(base.rstrip("/") + "/info", timeout=5)
        if resp.ok:
            return resp.json()
    except requests.RequestException:
        pass
    return None


def _resolve_node(value):
    if value != "auto":
        return value
    try:
        response = requests.get(DEFAULT_NODE.rstrip("/") + "/info", timeout=3)
        if response.ok:
            print("Using local node")
            return DEFAULT_NODE
    except requests.RequestException:
        pass
    print("Local node not detected. Using https://coinnode.cool62.net/")
    return REMOTE_NODE


def _iter_pages(node, start=0):
    cursor = start
    while True:
        page = _node(node, f"/chain?from_index={cursor}&limit=500")
        blocks = page.get("blocks")
        if not isinstance(blocks, list) or not blocks:
            return
        yield page
        if not page.get("has_more"):
            return
        nxt = page.get("next_from")
        cursor = nxt if nxt is not None and nxt > cursor else cursor + len(blocks)


def scan(node):
    """Replay the canonical chain from genesis, then preview the mempool."""
    pages = list(_iter_pages(node, 0))
    genesis = pages[0].get("genesis") if pages else None
    blocks = [block for page in pages for block in page.get("blocks", [])]
    state = replay(blocks, genesis)
    pending = copy.deepcopy(state)
    try:
        pool = _node(node, "/txpool")
        height = max(0, state["height"] - 1)
        for tx in pool.get("transactions", []):
            apply_op(pending, tx, height)
    except TokenError:
        pass
    return state, pending


def _load_state():
    if not STATE_FILE.exists():
        return new_state()
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return new_state()
    if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
        return new_state()
    for key, value in new_state().items():
        data.setdefault(key, value)
    return data


def _save_state(state):
    STATE_FILE.write_text(json.dumps(state, indent=4, sort_keys=True),
                          encoding="utf-8")


# ---------------------------------------------------------------------------
# wallet and formatting helpers
# ---------------------------------------------------------------------------

def _self_address(private_key):
    return address_from_public_key(private_key.public_key(), ADDRESS_SCHEME_HEX)


def _display_scheme(height=None):
    if height is not None:
        return (ADDRESS_SCHEME_BECH32 if height >= BECH32_ACTIVATION
                else ADDRESS_SCHEME_HEX)
    return getattr(config, "ADDRESS_DISPLAY", ADDRESS_SCHEME_BECH32)


def _self_display(private_key, height=None):
    scheme = _display_scheme(height)
    try:
        return address_from_public_key(private_key.public_key(), scheme)
    except ValueError:
        return address_from_public_key(private_key.public_key(), ADDRESS_SCHEME_HEX)


def _display_address(address, height=None):
    """Render a canonical token-state address using the normal display scheme."""
    if _is_none_authority(address):
        return NO_AUTHORITY_LABEL
    scheme = _display_scheme(height)
    try:
        public_key = decode_address(address)
        return address_from_public_key(public_key, scheme)
    except (ValueError, TypeError):
        return address


def _onchain_scheme(height):
    """Address scheme accepted by consensus for transactions at ``height``."""
    if height is not None and height >= BECH32_ACTIVATION:
        return ADDRESS_SCHEME_BECH32
    return ADDRESS_SCHEME_HEX


def _submit_address(address, height):
    """Encode a canonical token address for broadcast at ``height``."""
    scheme = _onchain_scheme(height)
    try:
        public_key = decode_address(address)
        return address_from_public_key(public_key, scheme)
    except (ValueError, TypeError):
        return address


def _self_submit_address(private_key, height):
    return _submit_address(_self_address(private_key), height)


def _display_units(amount, decimals):
    if decimals == 0:
        return str(amount)
    text = str(amount).rjust(decimals + 1, "0")
    return f"{text[:-decimals]}.{text[-decimals:]}"


def _parse_units(text, decimals, allow_zero=False):
    try:
        value = Decimal(str(text))
    except (InvalidOperation, ValueError) as exc:
        raise TokenError("invalid amount") from exc
    if not value.is_finite() or value < 0:
        raise TokenError("amount must be a non-negative number")
    scaled = value * (10 ** decimals)
    if scaled != scaled.to_integral_value():
        raise TokenError(f"amount has more than {decimals} decimal places")
    result = int(scaled)
    if result < (0 if allow_zero else 1) or result > MAX_U64:
        raise TokenError("amount is out of range")
    return result


def _parse_int(text, label):
    try:
        value = int(str(text))
    except (ValueError, TypeError) as exc:
        raise TokenError(f"{label} must be an integer") from exc
    if value < 0 or value > MAX_U64:
        raise TokenError(f"{label} is out of range")
    return value


def _parse_options(parts, flags=frozenset()):
    positional, options = [], {}
    index = 0
    while index < len(parts):
        token = parts[index]
        if token.startswith("--"):
            key, sep, inline = token[2:].partition("=")
            if key in flags:
                if sep:
                    raise TokenError(f"--{key} takes no value")
                options[key] = True
            elif sep:
                options[key] = inline
            else:
                index += 1
                if index >= len(parts):
                    raise TokenError(f"missing value for --{key}")
                options[key] = parts[index]
        else:
            positional.append(token)
        index += 1
    return positional, options


def _find_asset(state, token):
    token = token.strip()
    name, full_id = token.upper(), token.lower()
    matches = [asset for asset in state["assets"].values()
               if asset["name"] == name or asset["id"] == full_id]
    if not matches and len(full_id) >= 4 and full_id == token:
        matches = [asset for asset in state["assets"].values()
                   if asset["id"].startswith(full_id)]
    if not matches:
        raise TokenError(f"no asset matches '{token}'")
    if len(matches) > 1:
        raise TokenError(f"'{token}' is ambiguous; use more of the asset id")
    return matches[0]


def _version_for(height):
    if height is not None and height >= ATOMIC_ACTIVATION:
        return TX_VERSION_ATOMS, 0
    return TX_VERSION_LEGACY, 0.0


def _check_fee(args, address, height):
    try:
        data = _node(args.node, f"/balance?address={quote(address)}")
        if "balance_atoms" in data:
            balance = int(data["balance_atoms"])
        else:
            balance = int(Decimal(str(data["balance"])) * (10 ** 8))
    except (TokenError, KeyError, TypeError, ValueError) as exc:
        raise TokenError(f"cannot read balance ({exc})") from exc
    fee = transaction_fee_atoms(height)
    pending = 0
    try:
        pool = _node(args.node, "/txpool")
        for tx in pool.get("transactions", []):
            try:
                if canonical_address(tx.get("sender")) == address:
                    pending += tx_amount_atoms(tx, height) + fee
            except (ValueError, TypeError):
                continue
    except TokenError:
        pass
    if balance - pending < fee:
        raise TokenError(f"insufficient funds (need {format_atoms(fee)})")


def _publish(args, private_key, receiver, memo, nonce, height):
    from_address = _self_address(private_key)
    _check_fee(args, from_address, height)
    submit_sender = _self_submit_address(private_key, height)
    submit_receiver = _submit_address(receiver, height)
    version, amount = _version_for(height)
    signature = sign_transaction(private_key, submit_sender, submit_receiver,
                                 amount, nonce, memo, version=version)
    tx = {"sender": submit_sender, "receiver": submit_receiver,
          "amount": amount, "nonce": nonce, "signature": signature,
          "memo": memo}
    if version == TX_VERSION_ATOMS:
        tx["version"] = version
    _node(args.node, "/transaction", method="POST", body=tx)
    return tx_id(tx)


def _confirm(prompt):
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def _check_receiver(value, height):
    if not is_valid_address(value, height):
        raise TokenError("receiver is not a valid address")
    return canonical_address(value)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def cmd_address(args, private_key):
    height = None if args.scheme else ((_node_info(args.node) or {}).get("height"))
    if args.scheme == ADDRESS_SCHEME_HEX:
        print(_self_address(private_key))
    elif args.scheme == ADDRESS_SCHEME_BECH32:
        print(address_from_public_key(private_key.public_key(), ADDRESS_SCHEME_BECH32))
    else:
        print(_self_display(private_key, height))


def cmd_status(args, private_key):
    info = _node_info(args.node) or {}
    state, _ = scan(args.node)
    print(f"node:    {args.node}")
    print(f"height:  {info.get('height', '?')}   token state: {state['height']}")
    print(f"genesis: {state.get('genesis') or '?'}")
    print(f"tip:     {state.get('tip') or '?'}")
    print(f"assets:  {len(state['assets'])}   ops: {len(state['processed'])}")


def cmd_scan(args, private_key):
    state, _ = scan(args.node)
    _save_state(state)
    print(f"scanned to height {state['height']} "
          f"({len(state['assets'])} assets, {len(state['history'])} ops)")


def cmd_assets(args, rest, private_key):
    state, _ = scan(args.node)
    height = (_node_info(args.node) or {}).get("height")
    assets = sorted(state["assets"].values(), key=lambda a: a["name"])
    if not assets:
        print("no assets issued")
        return
    print(f"{'NAME':<17}{'ID':<10}{'POLICY':<8}{'DEC':<5}{'SUPPLY':>16}  ISSUER")
    for asset in assets:
        supply = _display_units(asset["supply"], asset["decimals"])
        issuer = _display_address(asset["issuer"], height)[:12]
        print(f"{asset['name']:<17}{asset['id'][:8]:<10}"
              f"{POLICY_LABELS[asset['policy']]:<8}{asset['decimals']:<5}"
              f"{supply:>16}  {issuer}")


def cmd_issue(args, rest, private_key):
    parts = shlex.split(rest)
    positional, opts = _parse_options(parts, {"no-authority"})
    if len(positional) < 3:
        print("usage: issue <name> <decimals> <initial> [--policy fixed|capped|open]")
        print("       initial may be 0 with --policy open or capped")
        print("       [--max N] [--mint-amount N] [--mint-cap N] [--start H]")
        print("       [--end H] [--authority ADDR|--no-authority]")
        print("       [--metadata TEXT] [--to ADDR]")
        return
    name = _name_text(positional[0])
    decimals = _parse_int(positional[1], "decimals")
    if decimals > MAX_DECIMALS:
        raise TokenError(f"decimals must be 0-{MAX_DECIMALS}")
    policy_name = opts.get("policy", "fixed").lower()
    if policy_name not in POLICY_NAMES:
        raise TokenError("policy must be fixed, capped or open")
    policy = POLICY_NAMES[policy_name]
    initial = _parse_units(positional[2], decimals,
                           allow_zero=policy != POLICY_FIXED)
    if policy == POLICY_FIXED and initial < 1:
        raise TokenError("fixed policy requires a positive initial supply")
    maximum = (_parse_units(opts["max"], decimals, allow_zero=True)
               if "max" in opts else 0)
    if policy == POLICY_CAPPED and maximum < 1:
        raise TokenError("capped policy requires a max supply")
    if maximum and maximum < initial:
        raise TokenError("max supply is below the initial supply")
    mint_amount = (_parse_units(opts["mint-amount"], decimals)
                   if "mint-amount" in opts else 0)
    mint_cap = _parse_int(opts["mint-cap"], "mint-cap") if "mint-cap" in opts else 0
    start = _parse_int(opts["start"], "start") if "start" in opts else 0
    end = _parse_int(opts["end"], "end") if "end" in opts else 0
    if opts.get("no-authority"):
        if "authority" in opts:
            raise TokenError("cannot combine --no-authority with --authority")
        authority = NO_AUTHORITY
    else:
        authority = opts.get("authority", "")
        if _is_none_authority(authority):
            authority = NO_AUTHORITY
    metadata = opts.get("metadata", "")
    receiver = opts.get("to") or _self_address(private_key)

    state, _ = scan(args.node)
    height = (_node_info(args.node) or {}).get("height")
    sender = _self_address(private_key)
    if authority == NO_AUTHORITY:
        memo_authority = NO_AUTHORITY
    else:
        authority = _check_receiver(authority or sender, height)
        memo_authority = _submit_address(authority, height)
    receiver = _check_receiver(receiver, height)
    asset_id = asset_id_for(sender, name, state.get("genesis"))
    memo = encode_op(OP_ISSUE, 1, name=name, decimals=decimals, policy=policy,
                     initial=initial, max_supply=maximum, mint_amount=mint_amount,
                     mint_cap=mint_cap, start_height=start, end_height=end,
                     authority=memo_authority, metadata=metadata)
    auth_label = (NO_AUTHORITY_LABEL if authority == NO_AUTHORITY
                  else _display_address(authority or sender, height))
    print(f"asset:  {asset_id}")
    print(f"name:   {name}   policy: {policy_name}   decimals: {decimals}")
    print(f"authority: {auth_label}")
    print(f"supply: {_display_units(initial, decimals)}   "
          f"to: {_display_address(receiver, height)}")
    if not _confirm("issue? [y/N] "):
        print("cancelled")
        return
    txid = _publish(args, private_key, receiver, memo, 1, height)
    print(f"issued (tx {txid[:12]})")


def cmd_info(args, rest, private_key):
    token = rest.strip()
    if not token:
        print("usage: info <asset id|prefix|name>")
        return
    state, _ = scan(args.node)
    height = (_node_info(args.node) or {}).get("height")
    try:
        asset = _find_asset(state, token)
    except TokenError as exc:
        print(f"error: {exc}")
        return
    print(f"id:          {asset['id']}")
    print(f"name:        {asset['name']}")
    print(f"policy:      {POLICY_LABELS[asset['policy']]}")
    print(f"decimals:    {asset['decimals']}")
    print(f"issuer:      {_display_address(asset['issuer'], height)}")
    auth_label = (NO_AUTHORITY_LABEL if asset["authority"] == NO_AUTHORITY
                  else _display_address(asset["authority"], height))
    print(f"authority:   {auth_label}")
    print(f"supply:      {_display_units(asset['supply'], asset['decimals'])} "
          f"({asset['supply']} base units)")
    if asset["max_supply"]:
        print(f"max supply:  {_display_units(asset['max_supply'], asset['decimals'])}")
    if asset["policy"] == POLICY_OPEN:
        print(f"mint amount: {_display_units(asset['mint_amount'], asset['decimals'])}")
        print(f"mint cap:    {asset['mint_cap'] or 'unlimited'} "
              f"({asset['mints_used']} used)")
        window = f"{asset['start_height'] or 'now'} .. {asset['end_height'] or 'never'}"
        print(f"window:      {window}")
    if asset["metadata"]:
        print(f"metadata:    {asset['metadata']}")
    print(f"height:      {asset['height']}")
    print(f"holders:     {len(state['balances'].get(asset['id'], {}))}")


def cmd_balance(args, rest, private_key):
    state, pending = scan(args.node)
    me = _self_address(private_key)
    token = rest.strip()
    held = _held_asset_ids(state, pending, me)
    if token:
        try:
            assets = [_find_asset(state, token)]
        except TokenError as exc:
            print(f"error: {exc}")
            return
        assets = [asset for asset in assets if asset["id"] in held]
    else:
        assets = [state["assets"][aid] for aid in held
                  if aid in state["assets"]]
    if not assets:
        print("no token balances")
        return
    for asset in sorted(assets, key=lambda a: a["name"]):
        aid = asset["id"]
        confirmed = _balance(state, aid, me)
        incoming = _balance(pending, aid, me) - confirmed
        line = (f"{asset['name']:<17}{_display_units(confirmed, asset['decimals']):>20}"
                f"  ({aid[:8]})")
        if incoming:
            sign = "+" if incoming > 0 else "-"
            line += f"  pending {sign}{_display_units(abs(incoming), asset['decimals'])}"
        print(line)


def cmd_holders(args, rest, private_key):
    state, _ = scan(args.node)
    height = (_node_info(args.node) or {}).get("height")
    try:
        asset = _find_asset(state, rest.strip())
    except TokenError as exc:
        print(f"error: {exc}")
        return
    holders = state["balances"].get(asset["id"], {})
    if not holders:
        print("no holders")
        return
    for address, amount in sorted(holders.items(), key=lambda kv: -kv[1]):
        shown = _display_address(address, height)
        print(f"{_display_units(amount, asset['decimals']):>20}  {shown}")


def cmd_send(args, rest, private_key, op):
    parts = shlex.split(rest)
    names = {OP_TRANSFER: "send", OP_MINT: "mint", OP_BURN: "burn",
             OP_SET_AUTHORITY: "setauth"}
    authority_value = None
    if op == OP_SET_AUTHORITY:
        if len(parts) != 2:
            print("usage: setauth <asset> <new authority|none>")
            return
        token, authority_value = parts
        receiver = _self_address(private_key)
    elif op == OP_BURN:
        if len(parts) != 2:
            print("usage: burn <asset> <amount>")
            return
        token, amount_text = parts
        receiver = _self_address(private_key)
    else:
        if len(parts) != 3:
            print(f"usage: {names[op]} <asset> <receiver> <amount>")
            return
        token, receiver_value, amount_text = parts
        receiver = receiver_value

    state, _ = scan(args.node)
    height = (_node_info(args.node) or {}).get("height")
    try:
        asset = _find_asset(state, token)
        receiver = _check_receiver(receiver, height)
        me = _self_address(private_key)
        seq = state["sequences"].get(asset["id"], {}).get(me, 0) + 1
        if op == OP_SET_AUTHORITY:
            if me != asset["authority"]:
                raise TokenError("only the authority may change authority")
            if _is_none_authority(authority_value):
                new_authority = NO_AUTHORITY
            else:
                new_authority = _check_receiver(authority_value, height)
            memo = encode_op(op, seq, asset_id=asset["id"],
                             authority=(NO_AUTHORITY if new_authority == NO_AUTHORITY
                                        else _submit_address(new_authority, height)))
            label = (NO_AUTHORITY_LABEL if new_authority == NO_AUTHORITY
                     else _display_address(new_authority, height))
            description = f"authority -> {label}"
        else:
            amount = _parse_units(amount_text, asset["decimals"])
            if op == OP_MINT:
                if me != asset["authority"]:
                    raise TokenError("only the authority may mint")
                if asset["policy"] == POLICY_FIXED:
                    raise TokenError("asset has a fixed supply")
                if asset["max_supply"] and asset["supply"] + amount > asset["max_supply"]:
                    raise TokenError("mint would exceed max supply")
            if op == OP_TRANSFER and _balance(state, asset["id"], me) < amount:
                raise TokenError("insufficient token balance")
            if op == OP_BURN and _balance(state, asset["id"], me) < amount:
                raise TokenError("insufficient token balance")
            memo = encode_op(op, seq, asset_id=asset["id"], amount=amount)
            description = (f"{_display_units(amount, asset['decimals'])} "
                           f"{asset['name']} -> {_display_address(receiver, height)}")
    except (TokenError, ValueError) as exc:
        print(f"error: {exc}")
        return
    print(f"{names[op]}: {description} (seq {seq})")
    if not _confirm("send? [y/N] "):
        print("cancelled")
        return
    txid = _publish(args, private_key, receiver, memo, seq, height)
    print(f"broadcast tx {txid[:12]}")


def cmd_claim(args, rest, private_key):
    parts = shlex.split(rest)
    if not 1 <= len(parts) <= 2:
        print("usage: claim <asset> [receiver]")
        return
    token = parts[0]
    state, _ = scan(args.node)
    height = (_node_info(args.node) or {}).get("height")
    try:
        asset = _find_asset(state, token)
        if asset["policy"] != POLICY_OPEN:
            raise TokenError("asset does not allow public minting")
        if asset["start_height"] and (height or 0) < asset["start_height"]:
            raise TokenError("mint window has not opened")
        if asset["end_height"] and (height or 0) > asset["end_height"]:
            raise TokenError("mint window has closed")
        if asset["mint_cap"] and asset["mints_used"] >= asset["mint_cap"]:
            raise TokenError("mint cap reached")
        receiver = _check_receiver(parts[1] if len(parts) == 2
                                   else _self_address(private_key), height)
        memo = encode_op(OP_PUBLIC_MINT, 0, asset_id=asset["id"])
    except (TokenError, ValueError) as exc:
        print(f"error: {exc}")
        return
    print(f"claim {_display_units(asset['mint_amount'], asset['decimals'])} "
          f"{asset['name']} -> {_display_address(receiver, height)}")
    if not _confirm("send? [y/N] "):
        print("cancelled")
        return
    nonce = secrets.randbits(62)  # public mints have no token sequence
    txid = _publish(args, private_key, receiver, memo, nonce, height)
    print(f"broadcast tx {txid[:12]}")


def cmd_history(args, rest, private_key):
    state, _ = scan(args.node)
    events = state["history"]
    token = rest.strip()
    if token:
        try:
            asset = _find_asset(state, token)
            events = [e for e in events if e["asset_id"] == asset["id"]]
        except TokenError as exc:
            print(f"error: {exc}")
            return
    if not events:
        print("no token operations")
        return
    for event in events[-30:]:
        print(f"#{event['height']:<7} {event['op']:<14} "
              f"{(event['name'] or (event['asset_id'] or '')[:8]):<17} "
              f"seq={event['seq']:<12} amount={event['amount']:<14} {event['note']}")


HELP_TEXT = """commands:
  address [hex|bech32]        show this wallet's address
  status                      node height and token state tip
  scan                        rescan the chain and save state
  assets                      list all assets
  issue <name> <decimals> <initial> [options]
                              create; initial 0 ok for open/capped;
                              --no-authority removes mint authority
  info <asset>                show asset metadata and supply
  balance [asset]             show your token balances
  holders <asset>             list holders of an asset
  send <asset> <receiver> <amount>
                              transfer tokens
  mint <asset> <receiver> <amount>
                              mint as the asset authority
  claim <asset> [receiver]    public mint (open policy only)
  burn <asset> <amount>       burn your own tokens
  setauth <asset> <address|none>
                              transfer or irrevocably remove authority
  history [asset]             recent operations
  help                        show this help
  quit                        exit

asset selectors: full id, a unique id prefix (4+ hex chars), or unique name.
token operations live in signed transaction memos. nodes do not validate
them; wallets replay the canonical chain. each operation costs one coin."""


def dispatch(args, private_key, line):
    try:
        parts = shlex.split(line)
    except ValueError as exc:
        print(f"error: {exc}")
        return True
    if not parts:
        return True
    command, rest = parts[0].lower(), " ".join(parts[1:])
    if command in ("quit", "exit", "q", "bye"):
        return False
    try:
        if command in ("help", "h"):
            print(HELP_TEXT)
        elif command == "address":
            if rest not in ("", "hex", "bech32"):
                print("usage: address [hex|bech32]")
            else:
                args.scheme = rest or None
                cmd_address(args, private_key)
        elif command == "status":
            cmd_status(args, private_key)
        elif command == "scan":
            cmd_scan(args, private_key)
        elif command == "assets":
            cmd_assets(args, rest, private_key)
        elif command == "issue":
            cmd_issue(args, rest, private_key)
        elif command == "info":
            cmd_info(args, rest, private_key)
        elif command == "balance":
            cmd_balance(args, rest, private_key)
        elif command == "holders":
            cmd_holders(args, rest, private_key)
        elif command == "send":
            cmd_send(args, rest, private_key, OP_TRANSFER)
        elif command == "mint":
            cmd_send(args, rest, private_key, OP_MINT)
        elif command == "burn":
            cmd_send(args, rest, private_key, OP_BURN)
        elif command == "setauth":
            cmd_send(args, rest, private_key, OP_SET_AUTHORITY)
        elif command == "claim":
            cmd_claim(args, rest, private_key)
        elif command == "history":
            cmd_history(args, rest, private_key)
        else:
            print(f"unknown command '{command}' - try 'help'")
    except (TokenError, ValueError) as exc:
        print(f"error: {exc}")
    return True


def interactive(args, private_key):
    print(f"interactive cool62coin tokens - node {args.node} "
          f"(type 'help' for commands)")
    while dispatch(args, private_key, input("C62 Token> ")):
        pass


def main():
    parser = argparse.ArgumentParser(description="cool62coin memo tokens")
    parser.add_argument("--node", default="auto",
                        help=f"node API base URL (default auto, then {DEFAULT_NODE})")
    parser.add_argument("--key", default=DEFAULT_KEY,
                        help=f"wallet private key file (default {DEFAULT_KEY})")
    parser.add_argument("command", nargs="?",
                        help="optional one-shot command; omit for interactive mode")
    parser.add_argument("rest", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    args.node = _resolve_node(args.node)
    args.scheme = None
    try:
        private_key = load_private_key(args.key)
    except (OSError, ValueError, TypeError) as exc:
        print(f"error: cannot load wallet key ({exc})")
        return
    if args.command:
        dispatch(args, private_key, " ".join([args.command] + args.rest))
    else:
        interactive(args, private_key)


if __name__ == "__main__":
    main()
