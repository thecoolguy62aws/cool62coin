# SPDX-FileCopyrightText: © 2026 thecoolguy62aws
# SPDX-License-Identifier: AGPL-3.0-or-later

import argparse
import base64
import hashlib
import json
import secrets
import time
from pathlib import Path
from urllib.parse import quote

import requests
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import config
from core import (ADDRESS_SCHEME_BECH32, ADDRESS_SCHEME_HEX, BECH32_ACTIVATION,
                  TRANSACTION_FEE, address_from_public_key, canonical_address,
                  decode_address, is_valid_address, load_private_key,
                  sign_transaction)

DEFAULT_NODE = "http://127.0.0.1:8090"
REMOTE_NODE = "https://coinnode.cool62.net/"
DEFAULT_KEY = "private_key.pem"
STATE_FILE = Path("mail_state.json")

MAIL_PREFIX = "c62mail1:"
SCHEME_X25519 = 1
SCHEME_RSA = 2
REORG_OVERLAP = 12
MAX_PARTS = 255
CURVE_P = 2 ** 255 - 19
KDF_INFO = b"cool62coin-mail-v1"
MEMO_MAX = getattr(config, "TX_MEMO_MAX", 512)


class MailError(Exception):
    pass


def _node(base, path, method="GET", body=None):
    url = base.rstrip("/") + path
    try:
        resp = requests.request(method, url, json=body, timeout=30)
    except requests.RequestException as e:
        raise MailError(f"cannot reach node ({e})") from e
    if resp.status_code >= 400:
        try:
            data = resp.json()
        except ValueError:
            data = {}
        raise MailError(f"{resp.status_code} {data.get('error', resp.text)}")
    try:
        return resp.json()
    except ValueError as e:
        raise MailError("node returned invalid JSON") from e


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


def _b64len(size):
    return (size * 8 + 5) // 6


def _max_payload_len():
    budget = MEMO_MAX - len(MAIL_PREFIX)
    size = max(0, budget * 3 // 4)
    while size > 0 and _b64len(size) > budget:
        size -= 1
    return size


def _b64encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text):
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _ed25519_to_x25519_public(public_key):
    raw = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    u = (1 + y) * pow(1 - y, -1, CURVE_P) % CURVE_P
    return u.to_bytes(32, "little")


def _ed25519_to_x25519_private(private_key):
    seed = private_key.private_bytes_raw()
    digest = hashlib.sha512(seed).digest()
    scalar = bytearray(digest[:32])
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return x25519.X25519PrivateKey.from_private_bytes(bytes(scalar))


def _aad(scheme, msg_id, part, total):
    return MAIL_PREFIX.encode() + bytes([scheme]) + msg_id + bytes([part, total])


def _scheme_for_public(public_key):
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return SCHEME_X25519
    if isinstance(public_key, rsa.RSAPublicKey):
        return SCHEME_RSA
    raise MailError("unsupported recipient key type")


def _header_len(scheme, recipient_public=None):
    common = 1 + 8 + 1 + 1
    if scheme == SCHEME_X25519:
        return common + 32 + 12
    if scheme == SCHEME_RSA:
        wrapped_len = (recipient_public.key_size + 7) // 8 \
            if recipient_public is not None else 256
        return common + 2 + wrapped_len + 12
    raise MailError("unsupported encryption scheme")


def _chunk_size(scheme, recipient_public=None):
    size = _max_payload_len() - _header_len(scheme, recipient_public) - 16
    if size < 1:
        raise MailError("node memo limit is too small for encrypted mail")
    return size


def _encrypt_part(recipient_public, plaintext, msg_id, part, total):
    scheme = _scheme_for_public(recipient_public)
    aad = _aad(scheme, msg_id, part, total)
    header = bytes([scheme]) + msg_id + bytes([part, total])
    if scheme == SCHEME_X25519:
        x_public_bytes = _ed25519_to_x25519_public(recipient_public)
        x_public = x25519.X25519PublicKey.from_public_bytes(x_public_bytes)
        ephemeral = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        shared = ephemeral.exchange(x_public)
        key = HKDF(algorithm=hashes.SHA256(), length=32,
                   salt=ephemeral_public + x_public_bytes,
                   info=KDF_INFO).derive(shared)
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        payload = header + ephemeral_public + nonce + ciphertext
    else:
        aes_key = secrets.token_bytes(32)
        wrapped = recipient_public.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None))
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, aad)
        payload = (header + len(wrapped).to_bytes(2, "big") + wrapped
                   + nonce + ciphertext)
    return MAIL_PREFIX + _b64encode(payload)


def _parse_payload(payload):
    if len(payload) < 11:
        raise MailError("message envelope is too short")
    scheme = payload[0]
    if scheme not in (SCHEME_X25519, SCHEME_RSA):
        raise MailError("unknown encryption scheme")
    msg_id = payload[1:9]
    part = payload[9]
    total = payload[10]
    if total < 1 or total > MAX_PARTS or part >= total:
        raise MailError("invalid message part header")
    return scheme, msg_id, part, total, payload


def _decode_part(memo):
    if not isinstance(memo, str) or not memo.startswith(MAIL_PREFIX):
        raise MailError("not a cool62coin mail message")
    try:
        payload = _b64decode(memo[len(MAIL_PREFIX):])
    except (ValueError, TypeError) as e:
        raise MailError("message is not valid base64") from e
    return _parse_payload(payload)


def _decrypt_part(private_key, payload):
    scheme, msg_id, part, total, payload = _parse_payload(payload)
    aad = _aad(scheme, msg_id, part, total)
    offset = 11
    try:
        if scheme == SCHEME_X25519:
            if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                raise MailError("this message needs an Ed25519 wallet key")
            ephemeral_public = payload[offset:offset + 32]
            offset += 32
            nonce = payload[offset:offset + 12]
            offset += 12
            ciphertext = payload[offset:]
            x_private = _ed25519_to_x25519_private(private_key)
            x_public_bytes = x_private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            shared = x_private.exchange(
                x25519.X25519PublicKey.from_public_bytes(ephemeral_public))
            key = HKDF(algorithm=hashes.SHA256(), length=32,
                       salt=ephemeral_public + x_public_bytes,
                       info=KDF_INFO).derive(shared)
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
        else:
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise MailError("this message needs an RSA wallet key")
            wrapped_len = int.from_bytes(payload[offset:offset + 2], "big")
            offset += 2
            wrapped = payload[offset:offset + wrapped_len]
            offset += wrapped_len
            nonce = payload[offset:offset + 12]
            offset += 12
            ciphertext = payload[offset:]
            aes_key = private_key.decrypt(
                wrapped,
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None))
            plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, aad)
    except (InvalidTag, ValueError, IndexError) as e:
        raise MailError("could not decrypt message (wrong key or corrupt data)") from e
    return msg_id, part, total, plaintext


def _encrypt_message(recipient_public, message):
    scheme = _scheme_for_public(recipient_public)
    chunk_size = _chunk_size(scheme, recipient_public)
    data = message.encode("utf-8")
    total = (len(data) + chunk_size - 1) // chunk_size
    if total == 0:
        raise MailError("message is empty")
    if total > MAX_PARTS:
        raise MailError(
            f"message is too long (max {chunk_size * MAX_PARTS} bytes)")
    msg_id = secrets.token_bytes(8)
    parts = [
        _encrypt_part(recipient_public, data[i * chunk_size:(i + 1) * chunk_size],
                      msg_id, i, total)
        for i in range(total)
    ]
    return msg_id, parts


def _self_address(private_key):
    return address_from_public_key(private_key.public_key(), ADDRESS_SCHEME_HEX)


def _self_display(private_key, height=None):
    scheme = None
    if height is not None:
        scheme = (ADDRESS_SCHEME_BECH32 if height >= BECH32_ACTIVATION
                  else ADDRESS_SCHEME_HEX)
    scheme = scheme or getattr(config, "ADDRESS_DISPLAY", ADDRESS_SCHEME_BECH32)
    try:
        return address_from_public_key(private_key.public_key(), scheme)
    except ValueError:
        return address_from_public_key(private_key.public_key(), ADDRESS_SCHEME_HEX)


def _load_state():
    if not STATE_FILE.exists():
        return {"version": 1, "wallets": {}}
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"version": 1, "wallets": {}}
    if not isinstance(data, dict):
        return {"version": 1, "wallets": {}}
    data.setdefault("version", 1)
    data.setdefault("wallets", {})
    return data


def _save_state(state):
    STATE_FILE.write_text(json.dumps(state, indent=4, sort_keys=True),
                          encoding="utf-8")


def _wallet(state, address):
    wallets = state.setdefault("wallets", {})
    entry = wallets.setdefault(
        address, {"scanned_height": 0, "messages": {}, "outbox": {}})
    entry.setdefault("scanned_height", 0)
    entry.setdefault("messages", {})
    entry.setdefault("outbox", {})
    return entry


def _store_transaction(wallet, my_address, tx, height, timestamp):
    if not isinstance(tx, dict):
        return
    receiver = tx.get("receiver")
    memo = tx.get("memo")
    if not isinstance(receiver, str) or not isinstance(memo, str):
        return
    if not memo.startswith(MAIL_PREFIX):
        return
    try:
        if canonical_address(receiver) != my_address:
            return
        _, msg_id, part, total, _ = _decode_part(memo)
        sender = tx.get("sender")
        sender_canon = canonical_address(sender)
    except (ValueError, TypeError, MailError):
        return
    messages = wallet["messages"]
    key = msg_id.hex()
    record = messages.get(key)
    if record is not None and record.get("sender_canon") != sender_canon:
        key = f"{key}-{sender_canon[:8]}"
        record = messages.get(key)
    if record is None:
        record = {
            "id": msg_id.hex(),
            "sender": sender,
            "sender_canon": sender_canon,
            "amount": 0,
            "total": total,
            "chunks": {},
            "heights": {},
            "timestamps": {},
            "first_seen": time.time(),
        }
        messages[key] = record
    if record.get("total") != total:
        return
    part_key = str(part)
    if part_key in record["chunks"]:
        if height is not None and record["heights"].get(part_key) is None:
            record["heights"][part_key] = height
            record["timestamps"][part_key] = timestamp or time.time()
        return
    record["chunks"][part_key] = memo
    record["heights"][part_key] = height
    record["timestamps"][part_key] = timestamp if timestamp is not None else time.time()
    amount = tx.get("amount")
    if isinstance(amount, (int, float)) and not isinstance(amount, bool):
        record["amount"] = record.get("amount", 0) + amount


def _iter_blocks(node, start):
    cursor = start
    while True:
        page = _node(node, f"/chain?from_index={cursor}&limit=500")
        blocks = page.get("blocks")
        if not isinstance(blocks, list) or not blocks:
            break
        for block in blocks:
            yield block
        if not page.get("has_more"):
            break
        nxt = page.get("next_from")
        if nxt is None or nxt <= cursor:
            cursor += len(blocks)
        else:
            cursor = nxt


def _scan(node, wallet, my_address):
    info = _node_info(node)
    height = info.get("height") if info else None
    current = int(wallet.get("scanned_height", 0))
    if height is not None and height < current:
        current = height
    start = max(0, current - REORG_OVERLAP)
    scanned = start
    try:
        for block in _iter_blocks(node, start):
            index = block.get("index", 0)
            timestamp = block.get("timestamp")
            for tx in block.get("transactions", []):
                _store_transaction(wallet, my_address, tx, index, timestamp)
            scanned = max(scanned, index + 1)
        pool = _node(node, "/txpool")
        for tx in pool.get("transactions", []):
            _store_transaction(wallet, my_address, tx, None, None)
    except MailError:
        wallet["scanned_height"] = scanned
        raise
    wallet["scanned_height"] = scanned


def _message_time(record):
    values = [v for v in record.get("timestamps", {}).values()
              if isinstance(v, (int, float))]
    return max(values) if values else record.get("first_seen", 0)


def _sorted_messages(wallet):
    return sorted(wallet["messages"].values(), key=_message_time, reverse=True)


def _find_message(wallet, token):
    messages = _sorted_messages(wallet)
    token = token.strip().lower()
    if token.isdigit():
        index = int(token)
        if 1 <= index <= len(messages):
            return messages[index - 1]
        raise MailError(f"no message number {index}")
    matches = [m for m in messages if m["id"].startswith(token)]
    if not matches:
        raise MailError(f"no message matches '{token}'")
    if len(matches) > 1:
        raise MailError(f"'{token}' matches more than one message")
    return matches[0]


def _outbox(wallet):
    return wallet.setdefault("outbox", {})


def _add_outbox_entry(wallet, msg_id, recipient, message, total, sent, fee):
    entry = {
        "id": msg_id.hex(),
        "recipient": recipient,
        "message": message,
        "total": total,
        "sent": sent,
        "fee": fee,
        "timestamp": time.time(),
    }
    _outbox(wallet)[entry["id"]] = entry
    return entry


def _sorted_outbox(wallet):
    return sorted(_outbox(wallet).values(),
                  key=lambda entry: entry.get("timestamp", 0), reverse=True)


def _find_outbox(wallet, token):
    entries = _sorted_outbox(wallet)
    token = token.strip().lower()
    if token.isdigit():
        index = int(token)
        if 1 <= index <= len(entries):
            return entries[index - 1]
        raise MailError(f"no sent message number {index}")
    matches = [entry for entry in entries if entry["id"].startswith(token)]
    if not matches:
        raise MailError(f"no sent message matches '{token}'")
    if len(matches) > 1:
        raise MailError(f"'{token}' matches more than one sent message")
    return matches[0]


def _sanitize(text):
    return "".join(ch if ch in "\n\t" or ch.isprintable() else " "
                   for ch in text)


def _preview(private_key, record):
    for part in range(record.get("total", 0)):
        memo = record["chunks"].get(str(part))
        if memo is None:
            continue
        try:
            _, _, _, plaintext = _decrypt_part(private_key, _decode_part(memo)[4])
        except MailError:
            return "(cannot decrypt)"
        text = _sanitize(plaintext.decode("utf-8", "replace"))
        text = " ".join(text.split())
        return text[:60] + ("..." if len(text) > 60 else "")
    return ""


def cmd_address(args, private_key):
    height = None if args.scheme else (
        (_node_info(args.node) or {}).get("height"))
    if args.scheme == ADDRESS_SCHEME_HEX:
        print(address_from_public_key(private_key.public_key(), ADDRESS_SCHEME_HEX))
    elif args.scheme == ADDRESS_SCHEME_BECH32:
        print(address_from_public_key(private_key.public_key(), ADDRESS_SCHEME_BECH32))
    else:
        print(_self_display(private_key, height))


def cmd_status(args):
    data = _node(args.node, "/info")
    print(f"node:  {args.node}")
    print(f"onion: {data.get('onion', '?')}")
    print(f"height: {data.get('height')}   difficulty: {data.get('difficulty')}   "
          f"reward: {data.get('reward')}")


def cmd_send(args, rest, private_key):
    receiver, _, message = rest.partition(" ")
    receiver = receiver.strip()
    message = message.lstrip()
    if not receiver:
        print("usage: send <address> [message]")
        return
    if not message:
        try:
            message = input("message> ")
        except (EOFError, KeyboardInterrupt):
            print()
            return
    if not message:
        print("empty message; nothing sent")
        return

    info = _node_info(args.node)
    height = info.get("height") if info else None
    if not is_valid_address(receiver, height):
        activation = (info or {}).get("bech32_activation", BECH32_ACTIVATION)
        if is_valid_address(receiver) and height is not None and height < activation:
            print(f"error: Bech32 addresses activate at block {activation} "
                  f"(current height {height})")
        else:
            print("error: receiver is not a valid address")
        return

    try:
        recipient_public = decode_address(receiver)
    except (ValueError, TypeError) as e:
        print(f"error: {e}")
        return

    try:
        msg_id, parts = _encrypt_message(recipient_public, message)
    except (MailError, ValueError) as e:
        print(f"error: {e}")
        return

    from_address = _self_address(private_key)
    try:
        balance = float(_node(
            args.node, f"/balance?address={quote(from_address)}")["balance"])
    except (MailError, KeyError, TypeError, ValueError) as e:
        print(f"error: {e}")
        return

    pending = 0.0
    try:
        pool = _node(args.node, "/txpool")
        for tx in pool.get("transactions", []):
            try:
                if canonical_address(tx.get("sender")) == from_address:
                    pending += float(tx.get("amount", 0)) + TRANSACTION_FEE
            except (ValueError, TypeError):
                continue
    except MailError:
        pass
    balance -= pending

    fee = len(parts) * TRANSACTION_FEE
    if balance < fee:
        print(f"error: insufficient funds (need {fee:g}, have {balance:g})")
        return

    from_display = _self_display(private_key, height)
    print(f"message id: {msg_id.hex()[:8]}")
    print(f"from: {from_display}")
    print(f"to:   {receiver}")
    print(f"parts: {len(parts)}   fee: {fee:g}")
    answer = input("send? [y/N] ").strip().lower()
    if answer not in ("y", "yes"):
        print("cancelled")
        return

    sent = 0
    for index, memo in enumerate(parts):
        nonce = int(time.time()) + index
        try:
            signature = sign_transaction(
                private_key, from_address, receiver, 0, nonce, memo)
            tx = {
                "sender": from_address,
                "receiver": receiver,
                "amount": 0,
                "nonce": nonce,
                "signature": signature,
                "memo": memo,
            }
            _node(args.node, "/transaction", method="POST", body=tx)
        except (MailError, ValueError) as e:
            print(f"error sending part {index + 1}/{len(parts)}: {e}")
            break
        sent += 1
        print(f"sent part {sent}/{len(parts)}")
    if sent:
        try:
            state = _load_state()
            wallet = _wallet(state, from_address)
            _add_outbox_entry(
                wallet, msg_id, receiver, message, len(parts), sent, fee)
            _save_state(state)
        except (OSError, TypeError, ValueError) as e:
            print(f"warning: could not save sent message ({e})")
    if sent == len(parts):
        print(f"message sent (id {msg_id.hex()[:8]})")
    elif sent:
        print(f"incomplete message sent ({sent}/{len(parts)} parts)")
    else:
        print("message was not sent")


def cmd_inbox(args, private_key):
    my_address = _self_address(private_key)
    state = _load_state()
    wallet = _wallet(state, my_address)
    try:
        _scan(args.node, wallet, my_address)
    finally:
        _save_state(state)
    messages = _sorted_messages(wallet)
    if not messages:
        print("inbox is empty")
        return
    print(f"{'#':>3}  {'id':<8}  {'from':<14}  {'date':<16}  {'parts':>5}  preview")
    for index, record in enumerate(messages, 1):
        stamp = time.strftime("%Y-%m-%d %H:%M",
                              time.localtime(_message_time(record)))
        sender = record.get("sender", "?")
        sender = sender[:12] + ("..." if len(sender) > 12 else "")
        parts = f"{len(record['chunks'])}/{record.get('total', '?')}"
        preview = _preview(private_key, record)
        print(f"{index:>3}  {record['id'][:8]:<8}  {sender:<14}  "
              f"{stamp:<16}  {parts:>5}  {preview}")


def cmd_outbox(args, private_key):
    state = _load_state()
    wallet = _wallet(state, _self_address(private_key))
    entries = _sorted_outbox(wallet)
    if not entries:
        print("outbox is empty")
        return
    print(f"{'#':>3}  {'id':<8}  {'to':<14}  {'date':<16}  {'parts':>5}  preview")
    for index, entry in enumerate(entries, 1):
        stamp = time.strftime("%Y-%m-%d %H:%M",
                              time.localtime(entry.get("timestamp", 0)))
        recipient = entry.get("recipient", "?")
        recipient = recipient[:12] + ("..." if len(recipient) > 12 else "")
        parts = f"{entry.get('sent', '?')}/{entry.get('total', '?')}"
        preview = " ".join(_sanitize(str(entry.get("message", ""))).split())
        preview = preview[:60] + ("..." if len(preview) > 60 else "")
        print(f"{index:>3}  {entry['id'][:8]:<8}  {recipient:<14}  "
              f"{stamp:<16}  {parts:>5}  {preview}")


def _print_outbox_entry(entry):
    stamp = time.strftime("%Y-%m-%d %H:%M",
                          time.localtime(entry.get("timestamp", 0)))
    print(f"id:     {entry.get('id', '?')}")
    print(f"to:     {entry.get('recipient', '?')}")
    print(f"date:   {stamp}")
    print(f"parts:  {entry.get('sent', '?')}/{entry.get('total', '?')}")
    print(f"fee:    {entry.get('fee', 0):g}")
    print("")
    print(_sanitize(str(entry.get("message", ""))))


def _print_inbox_entry(private_key, record):
    total = record.get("total", 0)
    missing = [str(part) for part in range(total)
               if str(part) not in record["chunks"]]
    if missing:
        print(f"message is incomplete (missing part(s) "
              f"{', '.join(missing)} of {total})")
        return
    chunks = []
    for part in range(total):
        try:
            _, _, _, plaintext = _decrypt_part(
                private_key, _decode_part(record["chunks"][str(part)])[4])
        except MailError as e:
            print(f"error: {e}")
            return
        chunks.append(plaintext)
    body = _sanitize(b"".join(chunks).decode("utf-8", "replace"))
    stamp = time.strftime("%Y-%m-%d %H:%M",
                          time.localtime(_message_time(record)))
    print(f"id:     {record['id']}")
    print(f"from:   {record.get('sender', '?')}")
    print(f"date:   {stamp}")
    print(f"amount: {record.get('amount', 0):g}")
    print("")
    print(body)


def cmd_read(args, rest, private_key):
    rest = rest.strip()
    if not rest:
        print("usage: read [outbox] <id|number>")
        return
    folder = "inbox"
    token = rest
    first, _, remaining = rest.partition(" ")
    if first.lower() in ("inbox", "outbox") and remaining.strip():
        folder = first.lower()
        token = remaining.strip()
    state = _load_state()
    wallet = _wallet(state, _self_address(private_key))
    if folder == "outbox":
        try:
            entry = _find_outbox(wallet, token)
        except MailError as e:
            print(f"error: {e}")
            return
        _print_outbox_entry(entry)
        return
    try:
        record = _find_message(wallet, token)
    except MailError as e:
        try:
            entry = _find_outbox(wallet, token)
        except MailError:
            if not wallet["messages"]:
                print("inbox is empty (run 'inbox' to fetch mail)")
            else:
                print(f"error: {e}")
            return
        _print_outbox_entry(entry)
        return
    _print_inbox_entry(private_key, record)


HELP_TEXT = """commands:
  send <address> [message]     encrypt and send a message (prompts if omitted)
  inbox                        fetch and list encrypted messages to this wallet
  outbox                       list messages you have sent
  read <id|number>             decrypt and read a message from the inbox
  read outbox <id|number>      read a message you sent
  address [hex|bech32]         print this wallet's address
  status                       node height / difficulty / own onion
  help                         show this help
  quit                         exit

messages are encrypted with the recipient's address key and travel in the
blockchain memo field. each transaction costs the network fee (1 coin)."""


def interactive(args):
    key_file = Path(args.key)
    if not key_file.is_file():
        print(f"error: wallet key not found at {args.key}")
        print("run send.py once to create your wallet keys")
        return
    try:
        private_key = load_private_key(args.key)
    except (OSError, ValueError, TypeError) as e:
        print(f"error: cannot load wallet key ({e})")
        return
    args.scheme = None
    print(f"interactive cool62coin mail - node {args.node} "
          f"(type 'help' for commands)")
    while True:
        try:
            line = input("C62 Mail> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        command, _, rest = line.partition(" ")
        rest = rest.strip()
        try:
            if command in ("quit", "exit", "q", "bye"):
                break
            elif command in ("help", "h"):
                print(HELP_TEXT)
            elif command == "address":
                scheme = rest.lower() if rest else None
                if scheme not in (None, ADDRESS_SCHEME_HEX, ADDRESS_SCHEME_BECH32):
                    print("usage: address [hex|bech32]")
                    continue
                args.scheme = scheme
                cmd_address(args, private_key)
            elif command == "status":
                cmd_status(args)
            elif command == "send":
                cmd_send(args, rest, private_key)
            elif command in ("inbox", "list"):
                cmd_inbox(args, private_key)
            elif command in ("outbox", "sent"):
                cmd_outbox(args, private_key)
            elif command == "read":
                cmd_read(args, rest, private_key)
            else:
                print(f"unknown command '{command}' - try 'help'")
        except MailError as e:
            print(f"error: {e}")


def main():
    parser = argparse.ArgumentParser(description="cool62coin encrypted mail")
    parser.add_argument("--node", default="auto",
                        help=f"node API base URL (default auto, then {DEFAULT_NODE})")
    parser.add_argument("--key", default=DEFAULT_KEY,
                        help=f"wallet private key file (default {DEFAULT_KEY})")
    args = parser.parse_args()
    args.node = _resolve_node(args.node)
    interactive(args)


if __name__ == "__main__":
    main()
