# SPDX-FileCopyrightText: © 2026 thecoolguy62aws
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the c62tok1 memo-token protocol (TOKENS.md)."""

import base64
import io
import json
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

from core import (ADDRESS_SCHEME_BECH32, ADDRESS_SCHEME_HEX, BECH32_ACTIVATION,
                  Blockchain, address_from_public_key, load_private_key,
                  sign_transaction, solve_block)
from tokens import (MAX_U64, NO_AUTHORITY, OP_BURN, OP_ISSUE, OP_MINT,
                    OP_PUBLIC_MINT, OP_SET_AUTHORITY, OP_TRANSFER,
                    POLICY_CAPPED, POLICY_FIXED, POLICY_OPEN, TOKEN_PREFIX,
                    TokenError, _find_asset, _parse_options, _parse_units,
                    apply_op, asset_id_for, decode_op, encode_op, replay, tx_id)

DIFF = 3


def address(priv):
    return address_from_public_key(priv.public_key(), ADDRESS_SCHEME_HEX)


def bech32_address(priv):
    return address_from_public_key(priv.public_key(), ADDRESS_SCHEME_BECH32)


def build_tx(priv, sender, receiver, memo, nonce, amount=0.0):
    signature = sign_transaction(priv, sender, receiver, amount, nonce, memo)
    return {"sender": sender, "receiver": receiver, "amount": amount,
            "nonce": nonce, "signature": signature, "memo": memo}


def mine_tx(bc, priv, sender, receiver, memo, nonce):
    signature = sign_transaction(priv, sender, receiver, 0.0, nonce, memo)
    assert bc.add_transaction(sender, receiver, 0.0, signature, nonce, memo,
                              version=1) is True, "node rejected token tx"
    solved = solve_block(bc.mine_block_candidate())
    assert bc.commit_mined(solved) is True
    return solved


def fund(bc, priv, sender, receiver, coins, nonce):
    signature = sign_transaction(priv, sender, receiver, coins, nonce)
    assert bc.add_transaction(sender, receiver, coins, signature, nonce,
                              version=1) is True
    solved = solve_block(bc.mine_block_candidate())
    assert bc.commit_mined(solved) is True


def replay_chain(bc, genesis=None):
    return replay([block.to_dict() for block in bc.chain],
                  genesis or bc.chain[0].hash)


def new_chain(tmp, filename, miner=None):
    return Blockchain(difficulty=DIFF, miner_address=miner or address(load_private_key(
        "private_key.pem")), chain_file=Path(tmp) / filename)


def test_codec():
    issue = encode_op(OP_ISSUE, 1, name="tkn2", decimals=2, policy=POLICY_OPEN,
                      initial=12345, max_supply=99999, mint_amount=500,
                      mint_cap=7, start_height=10, end_height=20,
                      authority="A" * 32, metadata="hello", note="note")
    op = decode_op(issue)
    assert issue.startswith(TOKEN_PREFIX)
    assert op.op == OP_ISSUE and op.seq == 1 and op.name == "TKN2"
    assert op.decimals == 2 and op.policy == POLICY_OPEN
    assert (op.initial, op.max_supply, op.mint_amount, op.mint_cap) == (
        12345, 99999, 500, 7)
    assert (op.start_height, op.end_height) == (10, 20)
    assert op.authority == "A" * 32 and op.metadata == "hello"
    assert op.note == "note"

    aid = "ab" * 16
    transfer = decode_op(encode_op(OP_TRANSFER, 3, asset_id=aid, amount=MAX_U64,
                                   note="x" * 32))
    assert transfer.asset_id == aid and transfer.amount == MAX_U64
    assert transfer.note == "x" * 32
    assert decode_op(encode_op(OP_PUBLIC_MINT, 0, asset_id=aid)).op == OP_PUBLIC_MINT
    assert decode_op(encode_op(OP_SET_AUTHORITY, 2, asset_id=aid,
                               authority="B" * 32)).authority == "B" * 32
    assert decode_op(encode_op(OP_MINT, 2, asset_id=aid, amount=1)).amount == 1
    assert decode_op(encode_op(OP_BURN, 2, asset_id=aid, amount=1)).amount == 1

    max_memo = encode_op(OP_ISSUE, 1, name="MAXNAME", decimals=18,
                         policy=POLICY_OPEN, initial=1, max_supply=MAX_U64,
                         mint_amount=1, mint_cap=MAX_U64, start_height=MAX_U64,
                         end_height=MAX_U64, authority="a" * 80,
                         metadata="m" * 64, note="n" * 32)
    assert len(max_memo.encode("utf-8")) <= 512

    for bad in ("", "other:abc", TOKEN_PREFIX, TOKEN_PREFIX + "!!!", TOKEN_PREFIX + "AQ"):
        try:
            decode_op(bad)
        except TokenError:
            continue
        raise AssertionError(f"accepted malformed memo {bad!r}")

    for kwargs in ({"name": "a-b"}, {"name": ""}, {"name": "A" * 17},
                   {"name": "TKN", "decimals": 19},
                   {"name": "TKN", "note": "x" * 33},
                   {"name": "TKN", "metadata": "m" * 65}):
        try:
            encode_op(OP_ISSUE, 1, initial=1, **kwargs)
        except TokenError:
            continue
        raise AssertionError(f"accepted invalid issue {kwargs}")

    for op_code in (0, 7, 99):
        try:
            encode_op(op_code, 1, asset_id=aid, amount=1)
        except TokenError:
            continue
        raise AssertionError("accepted unknown op")

    raw = bytearray(base64.urlsafe_b64decode(transfer_memo()[len(TOKEN_PREFIX):] + "=="))
    for index, value in ((0, 2), (1, 99)):
        broken = bytearray(raw)
        broken[index] = value
        memo = TOKEN_PREFIX + base64.urlsafe_b64encode(bytes(broken)).rstrip(b"=").decode()
        try:
            decode_op(memo)
        except TokenError:
            continue
        raise AssertionError("accepted corrupted version/op")

    noauth = decode_op(encode_op(OP_ISSUE, 1, name="NOAUTH", initial=1,
                                 authority=NO_AUTHORITY))
    assert noauth.authority == NO_AUTHORITY
    assert decode_op(encode_op(OP_SET_AUTHORITY, 2, asset_id=aid,
                               authority="none")).authority == NO_AUTHORITY
    try:
        encode_op(OP_ISSUE, 1, name="BAD", initial=1, authority="A\x00B")
    except TokenError:
        pass
    else:
        raise AssertionError("accepted an embedded NUL authority")

    assert _parse_options(["TKN", "2", "--policy", "open", "--max=5"]) == (
        ["TKN", "2"], {"policy": "open", "max": "5"})
    assert _parse_options(["--no-authority", "TKN"], {"no-authority"}) == (
        ["TKN"], {"no-authority": True})
    assert _parse_units("0", 0, allow_zero=True) == 0
    assert _parse_units("0.00", 2, allow_zero=True) == 0
    try:
        _parse_units("0", 0)
    except TokenError:
        pass
    else:
        raise AssertionError("accepted zero without allow_zero")


def transfer_memo():
    return encode_op(OP_TRANSFER, 1, asset_id="cd" * 16, amount=1)


def test_issue_and_fixed(tmp):
    issuer = load_private_key("private_key.pem")
    alice = ed25519.Ed25519PrivateKey.generate()
    issuer_addr, alice_addr = address(issuer), address(alice)
    bc = new_chain(tmp, "fixed.pkl")
    fund(bc, issuer, issuer_addr, alice_addr, 10.0, 90)

    aid = asset_id_for(issuer_addr, "TKN", bc.chain[0].hash)
    memo = encode_op(OP_ISSUE, 1, name="tkn", decimals=2, policy=POLICY_FIXED,
                     initial=100000)
    mine_tx(bc, issuer, issuer_addr, alice_addr, memo, 100)
    state = replay_chain(bc)

    assert state["names"] == {"TKN": aid}
    assert state["assets"][aid]["name"] == "TKN"
    assert state["assets"][aid]["issuer"] == issuer_addr
    assert state["assets"][aid]["authority"] == issuer_addr
    assert state["balances"][aid] == {alice_addr: 100000}
    assert state["sequences"][aid] == {issuer_addr: 1}

    # fixed policy rejects any mint
    bad_mint = build_tx(issuer, issuer_addr, issuer_addr,
                        encode_op(OP_MINT, 2, asset_id=aid, amount=1), 101)
    ok, reason = apply_op(state, bad_mint, bc.height)
    assert not ok and "fixed supply" in reason, reason

    # duplicate name is rejected even from a different issuer
    duplicate = build_tx(alice, alice_addr, alice_addr,
                         encode_op(OP_ISSUE, 1, name="TKN", initial=1), 102)
    ok, reason = apply_op(state, duplicate, bc.height)
    assert not ok and "already taken" in reason, reason


def test_capped_and_authority(tmp):
    issuer = load_private_key("private_key.pem")
    authority = ed25519.Ed25519PrivateKey.generate()
    alice = ed25519.Ed25519PrivateKey.generate()
    issuer_addr, auth_addr, alice_addr = (address(issuer), address(authority),
                                          address(alice))
    bc = new_chain(tmp, "capped.pkl")
    fund(bc, issuer, issuer_addr, auth_addr, 10.0, 150)
    fund(bc, issuer, issuer_addr, alice_addr, 10.0, 151)

    aid = asset_id_for(issuer_addr, "CAP", bc.chain[0].hash)
    issue = encode_op(OP_ISSUE, 1, name="CAP", policy=POLICY_CAPPED,
                      initial=100, max_supply=300, authority=auth_addr)
    mine_tx(bc, issuer, issuer_addr, issuer_addr, issue, 160)
    state = replay_chain(bc)
    assert state["assets"][aid]["authority"] == auth_addr

    # issuer is no longer the authority
    mint = build_tx(issuer, issuer_addr, alice_addr,
                    encode_op(OP_MINT, 2, asset_id=aid, amount=50), 161)
    ok, reason = apply_op(state, mint, bc.height)
    assert not ok and "only the authority" in reason, reason

    # authority mints, then transfers authority to alice
    mine_tx(bc, authority, auth_addr, alice_addr,
            encode_op(OP_MINT, 1, asset_id=aid, amount=100), 162)
    mine_tx(bc, authority, auth_addr, auth_addr,
            encode_op(OP_SET_AUTHORITY, 2, asset_id=aid,
                      authority=alice_addr), 163)
    state = replay_chain(bc)
    assert state["assets"][aid]["supply"] == 200
    assert state["assets"][aid]["authority"] == alice_addr
    assert state["balances"][aid][alice_addr] == 100

    # old authority can no longer mint
    stale = build_tx(authority, auth_addr, alice_addr,
                     encode_op(OP_MINT, 3, asset_id=aid, amount=1), 164)
    ok, reason = apply_op(state, stale, bc.height)
    assert not ok and "only the authority" in reason, reason

    # new authority mints but cannot exceed max supply
    over = build_tx(alice, alice_addr, alice_addr,
                    encode_op(OP_MINT, 1, asset_id=aid, amount=101), 165)
    ok, reason = apply_op(state, over, bc.height)
    assert not ok and "max supply" in reason, reason
    mine_tx(bc, alice, alice_addr, alice_addr,
            encode_op(OP_MINT, 1, asset_id=aid, amount=100), 166)
    state = replay_chain(bc)
    assert state["assets"][aid]["supply"] == 300


def test_open_mint(tmp):
    issuer = load_private_key("private_key.pem")
    alice = ed25519.Ed25519PrivateKey.generate()
    bob = ed25519.Ed25519PrivateKey.generate()
    issuer_addr, alice_addr, bob_addr = (address(issuer), address(alice),
                                         address(bob))
    bc = new_chain(tmp, "open.pkl")
    fund(bc, issuer, issuer_addr, alice_addr, 10.0, 200)
    fund(bc, issuer, issuer_addr, bob_addr, 10.0, 201)

    aid = asset_id_for(issuer_addr, "OPEN", bc.chain[0].hash)
    issue = encode_op(OP_ISSUE, 1, name="OPEN", policy=POLICY_OPEN,
                      initial=100, max_supply=400, mint_amount=100,
                      mint_cap=3)
    mine_tx(bc, issuer, issuer_addr, issuer_addr, issue, 210)

    for index, (priv, who) in enumerate(((alice, alice_addr), (bob, bob_addr),
                                         (issuer, issuer_addr))):
        mine_tx(bc, priv, who, who,
                encode_op(OP_PUBLIC_MINT, 0, asset_id=aid), 300 + index)
    state = replay_chain(bc)
    assert state["assets"][aid]["supply"] == 400
    assert state["assets"][aid]["mints_used"] == 3
    assert state["balances"][aid][alice_addr] == 100
    assert state["balances"][aid][bob_addr] == 100

    # cap reached and max supply reached both reject
    extra = build_tx(alice, alice_addr, alice_addr,
                     encode_op(OP_PUBLIC_MINT, 0, asset_id=aid), 310)
    ok, reason = apply_op(state, extra, bc.height)
    assert not ok and "cap reached" in reason, reason

    # window enforcement
    window_bc = new_chain(tmp, "window.pkl")
    window_aid = asset_id_for(issuer_addr, "WIN", window_bc.chain[0].hash)
    start = window_bc.height + 1  # block index of the first mint
    mine_tx(window_bc, issuer, issuer_addr, issuer_addr,
            encode_op(OP_ISSUE, 1, name="WIN", policy=POLICY_OPEN,
                      initial=1, mint_amount=1, start_height=start,
                      end_height=start), 400)
    mine_tx(window_bc, issuer, issuer_addr, issuer_addr,
            encode_op(OP_PUBLIC_MINT, 0, asset_id=window_aid), 401)
    outside = build_tx(issuer, issuer_addr, issuer_addr,
                       encode_op(OP_PUBLIC_MINT, 0, asset_id=window_aid), 402)
    window_state = replay_chain(window_bc)
    ok, reason = apply_op(window_state, outside, window_bc.height)
    assert not ok and "window has closed" in reason, reason
    assert window_state["assets"][window_aid]["mints_used"] == 1


def test_zero_initial_open(tmp):
    issuer = load_private_key("private_key.pem")
    alice = ed25519.Ed25519PrivateKey.generate()
    issuer_addr, alice_addr = address(issuer), address(alice)
    bc = new_chain(tmp, "zero.pkl")
    fund(bc, issuer, issuer_addr, alice_addr, 10.0, 450)

    aid = asset_id_for(issuer_addr, "ZERO", bc.chain[0].hash)
    issue = encode_op(OP_ISSUE, 1, name="ZERO", policy=POLICY_OPEN,
                      initial=0, max_supply=3, mint_amount=1)
    mine_tx(bc, issuer, issuer_addr, issuer_addr, issue, 451)
    state = replay_chain(bc)
    assert state["assets"][aid]["supply"] == 0
    assert state["balances"].get(aid, {}) == {}

    for index in range(3):
        mine_tx(bc, alice, alice_addr, alice_addr,
                encode_op(OP_PUBLIC_MINT, 0, asset_id=aid), 460 + index)
    state = replay_chain(bc)
    assert state["assets"][aid]["supply"] == 3
    assert state["balances"][aid][alice_addr] == 3

    extra = build_tx(alice, alice_addr, alice_addr,
                     encode_op(OP_PUBLIC_MINT, 0, asset_id=aid), 470)
    ok, reason = apply_op(state, extra, bc.height)
    assert not ok and "max supply" in reason, reason

    # fixed cannot have zero supply, capped requires a positive max
    fixed = build_tx(issuer, issuer_addr, issuer_addr,
                     encode_op(OP_ISSUE, 1, name="FIX0", policy=POLICY_FIXED,
                               initial=0), 480)
    ok, reason = apply_op(state, fixed, bc.height)
    assert not ok and "positive initial" in reason, reason

    capped = build_tx(issuer, issuer_addr, issuer_addr,
                      encode_op(OP_ISSUE, 1, name="CAP0", policy=POLICY_CAPPED,
                                initial=0, max_supply=0), 481)
    ok, reason = apply_op(state, capped, bc.height)
    assert not ok and "max supply" in reason, reason

    capped_ok = build_tx(issuer, issuer_addr, issuer_addr,
                         encode_op(OP_ISSUE, 1, name="CAP0",
                                   policy=POLICY_CAPPED, initial=0,
                                   max_supply=5), 482)
    assert apply_op(state, capped_ok, bc.height)[0]
    assert state["assets"][asset_id_for(issuer_addr, "CAP0",
                                        bc.chain[0].hash)]["supply"] == 0


def test_no_authority(tmp):
    issuer = load_private_key("private_key.pem")
    alice = ed25519.Ed25519PrivateKey.generate()
    issuer_addr, alice_addr = address(issuer), address(alice)
    bc = new_chain(tmp, "noauth.pkl")
    fund(bc, issuer, issuer_addr, alice_addr, 10.0, 600)

    aid = asset_id_for(issuer_addr, "NOAUTH", bc.chain[0].hash)
    issue = encode_op(OP_ISSUE, 1, name="NOAUTH", policy=POLICY_OPEN,
                      initial=0, max_supply=2, mint_amount=1,
                      authority=NO_AUTHORITY)
    mine_tx(bc, issuer, issuer_addr, issuer_addr, issue, 601)
    state = replay_chain(bc)
    assert state["assets"][aid]["authority"] == NO_AUTHORITY

    for nonce in (610, 611):
        mine_tx(bc, alice, alice_addr, alice_addr,
                encode_op(OP_PUBLIC_MINT, 0, asset_id=aid), nonce)
    state = replay_chain(bc)
    assert state["assets"][aid]["supply"] == 2
    assert state["assets"][aid]["mints_used"] == 2

    # issuer has no privileged mint and cannot restore authority
    mint = build_tx(issuer, issuer_addr, alice_addr,
                    encode_op(OP_MINT, 2, asset_id=aid, amount=10), 620)
    ok, reason = apply_op(state, mint, bc.height)
    assert not ok and "only the authority" in reason, reason

    setauth = build_tx(issuer, issuer_addr, issuer_addr,
                       encode_op(OP_SET_AUTHORITY, 2, asset_id=aid,
                                 authority=issuer_addr), 621)
    ok, reason = apply_op(state, setauth, bc.height)
    assert not ok and "only the authority" in reason, reason
    assert state["assets"][aid]["authority"] == NO_AUTHORITY

    # public cap still applies to everyone, including the issuer
    extra = build_tx(issuer, issuer_addr, issuer_addr,
                     encode_op(OP_PUBLIC_MINT, 0, asset_id=aid), 622)
    ok, reason = apply_op(state, extra, bc.height)
    assert not ok and "max supply" in reason, reason


def test_transfer_burn_conflict_reorg(tmp):
    issuer = load_private_key("private_key.pem")
    alice = ed25519.Ed25519PrivateKey.generate()
    bob = ed25519.Ed25519PrivateKey.generate()
    issuer_addr, alice_addr, bob_addr = (address(issuer), address(alice),
                                         address(bob))
    bc = new_chain(tmp, "transfer.pkl")
    fund(bc, issuer, issuer_addr, alice_addr, 10.0, 500)
    fund(bc, issuer, issuer_addr, bob_addr, 10.0, 501)

    aid = asset_id_for(issuer_addr, "XFER", bc.chain[0].hash)
    mine_tx(bc, issuer, issuer_addr, alice_addr,
            encode_op(OP_ISSUE, 1, name="XFER", initial=100), 510)
    mine_tx(bc, alice, alice_addr, bob_addr,
            encode_op(OP_TRANSFER, 1, asset_id=aid, amount=40), 511)
    mine_tx(bc, bob, bob_addr, bob_addr,
            encode_op(OP_BURN, 1, asset_id=aid, amount=10), 512)
    state = replay_chain(bc)
    assert state["balances"][aid] == {alice_addr: 60, bob_addr: 30}
    assert state["assets"][aid]["supply"] == 90

    # same seq conflict: first in chain wins
    conflict = new_chain(tmp, "conflict.pkl")
    fund(conflict, issuer, issuer_addr, alice_addr, 10.0, 520)
    conflict_aid = asset_id_for(issuer_addr, "CNF", conflict.chain[0].hash)
    mine_tx(conflict, issuer, issuer_addr, alice_addr,
            encode_op(OP_ISSUE, 1, name="CNF", initial=100), 530)
    mine_tx(conflict, alice, alice_addr, bob_addr,
            encode_op(OP_TRANSFER, 1, asset_id=conflict_aid, amount=60), 531)
    mine_tx(conflict, alice, alice_addr, bob_addr,
            encode_op(OP_TRANSFER, 1, asset_id=conflict_aid, amount=90,
                      note="rival"), 532)
    conflict_state = replay_chain(conflict)
    assert conflict_state["balances"][conflict_aid] == {
        alice_addr: 40, bob_addr: 60}
    assert conflict_state["history"][-1]["amount"] == 60

    # fork that never issued the asset produces no state
    fork = new_chain(tmp, "fork.pkl")
    assert fork.chain[0].hash == conflict.chain[0].hash
    mine_tx(fork, issuer, issuer_addr, alice_addr,
            encode_op(OP_TRANSFER, 2, asset_id=conflict_aid, amount=90), 540)
    assert replay_chain(fork)["assets"] == {}

    # broken chain links are detected
    blocks = [block.to_dict() for block in conflict.chain]
    blocks[3]["previous_hash"] = "00" * 64
    try:
        replay(blocks, conflict.chain[0].hash)
    except TokenError:
        pass
    else:
        raise AssertionError("accepted a broken chain")


def test_rejections(tmp):
    issuer = load_private_key("private_key.pem")
    alice = ed25519.Ed25519PrivateKey.generate()
    issuer_addr, alice_addr = address(issuer), address(alice)
    bc = new_chain(tmp, "reject.pkl")
    aid = asset_id_for(issuer_addr, "REJ", bc.chain[0].hash)
    mine_tx(bc, issuer, issuer_addr, issuer_addr,
            encode_op(OP_ISSUE, 1, name="REJ", initial=100), 600)
    state = replay_chain(bc)

    good = build_tx(issuer, issuer_addr, alice_addr,
                    encode_op(OP_TRANSFER, 2, asset_id=aid, amount=10), 601)
    assert apply_op(state, good, bc.height)[0]

    def rejected(tx, expected):
        snapshot = json.dumps(state, sort_keys=True)
        ok, reason = apply_op(state, tx, bc.height)
        assert not ok and expected in reason, reason
        assert json.dumps(state, sort_keys=True) == snapshot, "state mutated"

    bad_sig = dict(good)
    bad_sig["signature"] = "00" * 64
    rejected(bad_sig, "invalid signature")
    rejected(build_tx(issuer, issuer_addr, alice_addr, transfer_memo(), 602),
             "unknown asset")
    rejected(build_tx(issuer, issuer_addr, alice_addr, "not:a:memo", 603),
             "not a c62tok1 memo")
    rejected(build_tx(issuer, issuer_addr, alice_addr,
                      encode_op(OP_TRANSFER, 2, asset_id=aid, amount=10), 604, 1.0),
             "zero coin amount")
    rejected(build_tx(issuer, issuer_addr, alice_addr,
                      encode_op(OP_TRANSFER, 3, asset_id=aid, amount=1000), 605),
             "insufficient token balance")
    rejected(build_tx(issuer, issuer_addr, alice_addr,
                      encode_op(OP_TRANSFER, 9, asset_id=aid, amount=1), 606),
             "expected sequence")


def test_cross_chain_and_selectors(tmp):
    issuer = load_private_key("private_key.pem")
    other = ed25519.Ed25519PrivateKey.generate()
    issuer_addr, other_addr = address(issuer), address(other)
    chain_a = new_chain(tmp, "a.pkl")
    chain_b = new_chain(tmp, "b.pkl", miner=other_addr)
    assert chain_a.chain[0].hash != chain_b.chain[0].hash
    aid_a = asset_id_for(issuer_addr, "XCH", chain_a.chain[0].hash)
    aid_b = asset_id_for(issuer_addr, "XCH", chain_b.chain[0].hash)
    assert aid_a != aid_b

    fund(chain_b, other, other_addr, issuer_addr, 10.0, 700)
    mine_tx(chain_a, issuer, issuer_addr, issuer_addr,
            encode_op(OP_ISSUE, 1, name="XCH", initial=100), 701)
    mine_tx(chain_b, issuer, issuer_addr, issuer_addr,
            encode_op(OP_ISSUE, 1, name="XCH", initial=100), 701)
    state_b = replay_chain(chain_b)
    assert aid_b in state_b["assets"] and aid_a not in state_b["assets"]
    stolen = build_tx(issuer, issuer_addr, issuer_addr,
                      encode_op(OP_TRANSFER, 2, asset_id=aid_a, amount=10), 702)
    assert not apply_op(state_b, stolen, chain_b.height)[0]

    assert _find_asset(state_b, "xch")["id"] == aid_b
    assert _find_asset(state_b, aid_b)["id"] == aid_b
    assert _find_asset(state_b, aid_b[:8])["id"] == aid_b
    try:
        _find_asset(state_b, aid_b[:4] if aid_b[:4] == "0" else "zzzz")
    except TokenError:
        pass
    else:
        raise AssertionError("accepted unknown selector")


def test_mocked_scan(tmp):
    import tokens
    issuer = load_private_key("private_key.pem")
    addr = address(issuer)
    bc = new_chain(tmp, "scan.pkl")
    aid = asset_id_for(addr, "SCN", bc.chain[0].hash)
    mine_tx(bc, issuer, addr, addr,
            encode_op(OP_ISSUE, 1, name="SCN", initial=55), 800)
    blocks = [block.to_dict() for block in bc.chain]

    def fake_node(base, path, method="GET", body=None):
        if path.startswith("/chain"):
            start = int(path.split("from_index=")[1].split("&")[0]) \
                if "from_index=" in path else 0
            page = blocks[start:]
            return {"height": len(blocks), "genesis": blocks[0]["hash"],
                    "tip": blocks[-1]["hash"], "blocks": page,
                    "has_more": False, "next_from": None}
        if path == "/txpool":
            return {"transactions": []}
        raise AssertionError(path)

    old_node, old_info = tokens._node, tokens._node_info
    tokens._node = fake_node
    tokens._node_info = lambda base: {"height": len(blocks)}
    try:
        state, pending = tokens.scan("http://fake")
    finally:
        tokens._node, tokens._node_info = old_node, old_info
    assert state["assets"][aid]["supply"] == 55
    assert state["names"] == {"SCN": aid}
    assert pending["assets"] == state["assets"]
    assert pending["balances"] == state["balances"]


def test_cli_commands(tmp):
    import tokens
    issuer = load_private_key("private_key.pem")
    alice = ed25519.Ed25519PrivateKey.generate()
    me, alice_addr = address(issuer), address(alice)
    aid = "ef" * 16
    state = tokens.new_state("00" * 32)
    state["assets"][aid] = {
        "id": aid, "name": "CLI", "issuer": me, "authority": me,
        "decimals": 2, "policy": POLICY_OPEN, "supply": 1000,
        "max_supply": 10000, "mint_amount": 100, "mint_cap": 5,
        "mints_used": 0, "start_height": 0, "end_height": 0,
        "metadata": "", "height": 1, "txid": "00" * 64,
    }
    state["sequences"][aid] = {me: 0}
    state["balances"][aid] = {me: 1000}
    captured = []

    def fake_node(base, path, method="GET", body=None):
        if method == "POST" and path == "/transaction":
            captured.append(body)
            return {"success": True}
        raise AssertionError(path)

    originals = (tokens.scan, tokens._node_info, tokens._node,
                 tokens._check_fee, tokens._confirm)
    tokens.scan = lambda node: (state, tokens.copy.deepcopy(state))
    tokens._node_info = lambda base: {"height": 2000}
    tokens._node = fake_node
    tokens._check_fee = lambda *args: None
    tokens._confirm = lambda prompt: True
    args = type("Args", (), {"node": "x", "key": "x", "scheme": None})()
    expected_display = bech32_address(issuer)
    expected_alice_display = bech32_address(alice)
    try:
        out = io.StringIO()
        with redirect_stdout(out):
            tokens.cmd_holders(args, aid, issuer)
        assert expected_display in out.getvalue(), \
            "holders must display Bech32m"

        out = io.StringIO()
        with redirect_stdout(out):
            tokens.cmd_info(args, aid, issuer)
        assert expected_display in out.getvalue(), \
            "info must display Bech32m"

        out = io.StringIO()
        with redirect_stdout(out):
            tokens.cmd_assets(args, "", issuer)
        assert expected_display[:12] in out.getvalue(), \
            "assets must display Bech32m"

        tokens.dispatch(args, issuer, f"setauth {aid} {alice_addr}")
        assert len(captured) == 1, "setauth did not publish"
        op = decode_op(captured[-1]["memo"])
        assert op.op == OP_SET_AUTHORITY and op.seq == 1
        assert op.authority == expected_alice_display
        assert captured[-1]["sender"] == expected_display
        assert captured[-1]["receiver"] == expected_display

        tokens.dispatch(args, issuer, f"setauth {aid} none")
        op = decode_op(captured[-1]["memo"])
        assert op.op == OP_SET_AUTHORITY and op.authority == NO_AUTHORITY

        tokens.dispatch(args, issuer, f"mint {aid} {alice_addr} 5.00")
        op = decode_op(captured[-1]["memo"])
        assert op.op == OP_MINT and op.amount == 500 and op.seq == 1
        assert captured[-1]["receiver"] == expected_alice_display

        tokens.dispatch(args, issuer, f"burn {aid} 2.00")
        op = decode_op(captured[-1]["memo"])
        assert op.op == OP_BURN and op.amount == 200 and op.seq == 1
        assert captured[-1]["receiver"] == expected_display

        tokens.dispatch(args, issuer, f"send {aid} {alice_addr} 1.00")
        op = decode_op(captured[-1]["memo"])
        assert op.op == OP_TRANSFER and op.amount == 100 and op.seq == 1
        assert captured[-1]["receiver"] == expected_alice_display

        tokens.dispatch(args, issuer, f"claim {aid}")
        op = decode_op(captured[-1]["memo"])
        assert op.op == OP_PUBLIC_MINT and op.seq == 0
        assert captured[-1]["nonce"] != 1, "public mint needs a varied nonce"
        assert captured[-1]["receiver"] == expected_display

        tokens.dispatch(args, issuer,
                        "issue ZERO 0 0 --policy open --mint-amount 1 "
                        "--max 100000000 --end 25000")
        op = decode_op(captured[-1]["memo"])
        assert op.op == OP_ISSUE and op.initial == 0
        assert op.policy == POLICY_OPEN and op.mint_amount == 1
        assert op.max_supply == 100000000 and op.end_height == 25000
        assert op.mint_cap == 0
        assert op.authority == expected_display
        assert captured[-1]["sender"] == expected_display
        assert captured[-1]["receiver"] == expected_display

        tokens.dispatch(args, issuer,
                        "issue NOAU 0 0 --policy open --mint-amount 1 "
                        "--no-authority")
        op = decode_op(captured[-1]["memo"])
        assert op.op == OP_ISSUE and op.authority == NO_AUTHORITY

        tokens.dispatch(args, issuer,
                        "issue NOAU2 0 0 --policy open --mint-amount 1 "
                        "--authority none")
        op = decode_op(captured[-1]["memo"])
        assert op.op == OP_ISSUE and op.authority == NO_AUTHORITY

        assert all(tx["sender"] == expected_display for tx in captured), \
            "all token transactions must use the active onchain scheme"

        before = len(captured)
        tokens.dispatch(args, issuer, "issue FIX0 0 0 --policy fixed")
        assert len(captured) == before, "published a zero-supply fixed asset"
    finally:
        (tokens.scan, tokens._node_info, tokens._node,
         tokens._check_fee, tokens._confirm) = originals


def test_address_display():
    import config
    import tokens

    issuer = load_private_key("private_key.pem")
    expected = address_from_public_key(issuer.public_key(), ADDRESS_SCHEME_BECH32)
    assert tokens._self_address(issuer) == address(issuer), \
        "transaction senders must stay canonical hex"

    had_display = hasattr(config, "ADDRESS_DISPLAY")
    old_display = getattr(config, "ADDRESS_DISPLAY", None)
    try:
        if had_display:
            del config.ADDRESS_DISPLAY
        assert tokens._self_display(issuer, None) == expected, \
            "default display must fall back to Bech32m"
        assert tokens._display_address(address(issuer), None) == expected
        assert tokens._display_address(address(issuer), 0) == address(issuer)
    finally:
        if had_display:
            config.ADDRESS_DISPLAY = old_display


def test_onchain_encoding():
    import tokens

    issuer = load_private_key("private_key.pem")
    alice = ed25519.Ed25519PrivateKey.generate()
    hex_addr, bech_addr = address(issuer), bech32_address(issuer)

    assert tokens._onchain_scheme(BECH32_ACTIVATION - 1) == ADDRESS_SCHEME_HEX
    assert tokens._onchain_scheme(BECH32_ACTIVATION) == ADDRESS_SCHEME_BECH32
    assert tokens._submit_address(hex_addr, BECH32_ACTIVATION - 1) == hex_addr
    assert tokens._submit_address(hex_addr, BECH32_ACTIVATION) == bech_addr
    assert tokens._submit_address(bech_addr, BECH32_ACTIVATION - 1) == hex_addr
    assert tokens._self_submit_address(issuer, BECH32_ACTIVATION) == bech_addr

    captured = []
    originals = tokens._node, tokens._check_fee

    def fake_node(base, path, method="GET", body=None):
        assert (method, path) == ("POST", "/transaction")
        captured.append(body)
        return {"success": True}

    args = type("Args", (), {"node": "x"})()
    memo = encode_op(OP_BURN, 1, asset_id="ef" * 16, amount=1)
    try:
        tokens._node = fake_node
        tokens._check_fee = lambda *a: None
        tokens._publish(args, issuer, hex_addr, memo, 9,
                        BECH32_ACTIVATION - 1)
    finally:
        tokens._node, tokens._check_fee = originals
    assert captured[0]["sender"] == hex_addr
    assert captured[0]["receiver"] == hex_addr

    state = tokens.new_state("00" * 32)
    memo = encode_op(OP_ISSUE, 1, name="ONCHAIN", policy=POLICY_OPEN,
                     initial=0, mint_amount=1, authority=bech_addr)
    tx = build_tx(issuer, bech_addr, bech_addr, memo, 1)
    ok, reason = apply_op(state, tx, BECH32_ACTIVATION)
    assert ok, reason
    aid = asset_id_for(hex_addr, "ONCHAIN", state["genesis"])
    assert state["assets"][aid]["issuer"] == hex_addr
    assert state["assets"][aid]["authority"] == hex_addr

    seq = state["sequences"][aid][hex_addr] + 1
    memo = encode_op(OP_SET_AUTHORITY, seq, asset_id=aid,
                     authority=bech32_address(alice))
    tx = build_tx(issuer, bech_addr, bech_addr, memo, 2)
    ok, reason = apply_op(state, tx, BECH32_ACTIVATION)
    assert ok, reason
    assert state["assets"][aid]["authority"] == address(alice)

    memo = encode_op(OP_ISSUE, 1, name="LEGACY", policy=POLICY_OPEN,
                     initial=0, mint_amount=1, authority=hex_addr)
    tx = build_tx(issuer, hex_addr, hex_addr, memo, 3)
    ok, reason = apply_op(state, tx, BECH32_ACTIVATION)
    assert ok, reason
    assert state["assets"][asset_id_for(hex_addr, "LEGACY",
                                        state["genesis"])]["issuer"] == hex_addr


def main():
    tmp = tempfile.mkdtemp()
    test_codec()
    print("codec ok")
    test_address_display()
    print("address display ok")
    test_onchain_encoding()
    print("onchain encoding ok")
    test_issue_and_fixed(tmp)
    print("issue/fixed ok")
    test_capped_and_authority(tmp)
    print("capped/authority ok")
    test_open_mint(tmp)
    print("open mint ok")
    test_zero_initial_open(tmp)
    print("zero initial ok")
    test_no_authority(tmp)
    print("no authority ok")
    test_transfer_burn_conflict_reorg(tmp)
    print("transfer/burn/conflict/reorg ok")
    test_rejections(tmp)
    print("rejections ok")
    test_cross_chain_and_selectors(tmp)
    print("cross-chain/selectors ok")
    test_mocked_scan(tmp)
    print("mocked scan ok")
    test_cli_commands(tmp)
    print("cli commands ok")
    print("all token tests passed")


if __name__ == "__main__":
    main()
