# SPDX-FileCopyrightText: © 2026 thecoolguy62aws
# SPDX-License-Identifier: AGPL-3.0-or-later

import math
import shutil
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

import core
from core import (Block, Blockchain, COIN_ATOMS, TX_VERSION_ATOMS,
                  TX_VERSION_LEGACY, address_from_public_key,
                  atoms_to_coins, coins_to_atoms, format_atoms,
                  parse_amount_to_atoms, sign_transaction, solve_block,
                  transaction_fee_atoms, tx_amount_atoms, tx_signing_payload,
                  verify_transaction)

DIFF = 3


def fresh(tmpdir, name, miner):
    return Blockchain(difficulty=DIFF, miner_address=miner,
                      chain_file=Path(tmpdir) / name)


def mine(bc, index, transactions, timestamp, miner=None, previous=None,
         difficulty=None):
    candidate = {
        "index": index,
        "transactions": transactions,
        "previous_hash": previous if previous is not None else bc.last_block.hash,
        "miner": miner if miner is not None else bc.miner_address,
        "difficulty": difficulty if difficulty is not None else bc.difficulty_at_next(),
        "timestamp": timestamp,
    }
    return solve_block(candidate)


def keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    address = address_from_public_key(priv.public_key())
    return priv, address


def test_activation_boundary(tmpdir):
    old = core.ATOMIC_ACTIVATION
    core.ATOMIC_ACTIVATION = 2
    try:
        miner_priv, miner = keypair()
        target_priv, target = keypair()
        bc = fresh(tmpdir, "boundary.pkl", miner)
        t0 = bc.chain[0].timestamp

        legacy_sig = sign_transaction(miner_priv, miner, target, 1.0, 1)
        legacy_tx = {"sender": miner, "receiver": target, "amount": 1.0,
                     "nonce": 1, "signature": legacy_sig}
        assert bc.add_block(mine(bc, 1, [legacy_tx], t0 + 10)) is True

        assert tx_amount_atoms(legacy_tx, 1) == coins_to_atoms(1.0)

        # A version 1 transaction is rejected at the activation height.
        stale_sig = sign_transaction(miner_priv, miner, target, 1.0, 2)
        stale_tx = {"sender": miner, "receiver": target, "amount": 1.0,
                    "nonce": 2, "signature": stale_sig}
        assert bc.add_block(mine(bc, 2, [stale_tx], t0 + 15)) is False

        # A version 2 transaction is required at and after activation.
        atoms = coins_to_atoms(0.5)
        atom_sig = sign_transaction(miner_priv, miner, target, atoms, 2,
                                    version=TX_VERSION_ATOMS)
        atom_tx = {"sender": miner, "receiver": target, "amount": atoms,
                   "nonce": 2, "signature": atom_sig,
                   "version": TX_VERSION_ATOMS}
        assert bc.add_block(mine(bc, 2, [atom_tx], t0 + 20)) is True

        assert bc.get_balance(target) == coins_to_atoms(1.5)
        assert bc.is_chain_valid()

        # A version 2 transaction before activation must also be rejected.
        early = fresh(tmpdir, "early.pkl", miner)
        early_sig = sign_transaction(miner_priv, miner, target, atoms, 3,
                                     version=TX_VERSION_ATOMS)
        early_tx = {"sender": miner, "receiver": target, "amount": atoms,
                    "nonce": 3, "signature": early_sig,
                    "version": TX_VERSION_ATOMS}
        assert early.add_block(mine(early, 1, [early_tx],
                                    early.chain[0].timestamp + 10)) is False
    finally:
        core.ATOMIC_ACTIVATION = old


def test_duplicate_transactions(tmpdir):
    miner_priv, miner = keypair()
    _, target = keypair()
    bc = fresh(tmpdir, "duplicate.pkl", miner)

    sig = sign_transaction(miner_priv, miner, target, 0.0, 7)
    tx = {"sender": miner, "receiver": target, "amount": 0.0,
          "nonce": 7, "signature": sig}
    t0 = bc.chain[0].timestamp

    assert bc.add_block(mine(bc, 1, [tx, tx], t0 + 10)) is False, \
        "the same transaction twice in one block must be rejected"

    assert bc.add_block(mine(bc, 1, [tx], t0 + 10)) is True
    assert bc.add_block(mine(bc, 2, [tx], t0 + 20)) is False, \
        "a transaction confirmed in an earlier block must be rejected"

    # Re-appending the same signed transaction through the mempool is
    # rejected as well.
    assert bc.add_transaction(miner, target, 0.0, sig, 7) is False


def test_alternate_genesis(tmpdir):
    _, miner_a = keypair()
    _, miner_b = keypair()
    a = fresh(tmpdir, "gen_a.pkl", miner_a)
    b = fresh(tmpdir, "gen_b.pkl", miner_b)
    assert a.chain[0].hash != b.chain[0].hash

    t = b.chain[0].timestamp
    for index in range(1, 4):
        assert b.add_block(mine(b, index, [], t + index * 10)) is True

    original = a.chain[0].hash
    assert a.adopt_chain([block.to_dict() for block in b.chain]) is False, \
        "a longer chain with a different genesis must not be adopted"
    assert a.chain[0].hash == original
    assert a.height == 1


def test_malformed_inputs(tmpdir):
    _, miner = keypair()
    _, target = keypair()
    bc = fresh(tmpdir, "malformed.pkl", miner)
    t0 = bc.chain[0].timestamp

    bad_transactions = [
        {"receiver": target, "amount": 1.0, "nonce": 1, "signature": "00"},
        ["not", "a", "dict"],
        {"sender": miner, "receiver": target, "amount": "oops",
         "nonce": 1, "signature": "00"},
        {"sender": miner, "receiver": target, "amount": -1.0,
         "nonce": 1, "signature": "00"},
        {"sender": miner, "receiver": target, "amount": float("nan"),
         "nonce": 1, "signature": "00"},
        {"sender": miner, "receiver": target, "amount": float("inf"),
         "nonce": 1, "signature": "00"},
        {"sender": miner, "receiver": target, "amount": True,
         "nonce": 1, "signature": "00"},
        {"sender": miner, "receiver": target, "amount": 1.0,
         "nonce": "1", "signature": "00"},
        {"sender": miner, "receiver": target, "amount": 1.0,
         "nonce": 1, "signature": 5},
        {"sender": miner, "receiver": target, "amount": 1.0,
         "nonce": 1, "signature": "00", "memo": 42},
    ]
    for tx in bad_transactions:
        block = mine(bc, 1, [tx], t0 + 10)
        assert bc.add_block(block) is False, tx
        assert bc.validate_chain(list(bc.chain) + [Block.from_dict(block)]) is False

    valid_tx = {"sender": miner, "receiver": target, "amount": 1.0,
                "nonce": 1, "signature": "00"}
    malformed_blocks = [
        {"index": 1, "transactions": [valid_tx],
         "previous_hash": bc.last_block.hash, "miner": miner,
         "difficulty": DIFF, "nonce": 0, "timestamp": "now"},
        {"index": 1, "transactions": [valid_tx],
         "previous_hash": "abc", "miner": miner,
         "difficulty": DIFF, "nonce": 0, "timestamp": t0 + 10},
        {"index": 1, "transactions": "nope",
         "previous_hash": bc.last_block.hash, "miner": miner,
         "difficulty": DIFF, "nonce": 0, "timestamp": t0 + 10},
        {"index": True, "transactions": [],
         "previous_hash": bc.last_block.hash, "miner": miner,
         "difficulty": DIFF, "nonce": 0, "timestamp": t0 + 10},
        {"index": 1, "transactions": [],
         "previous_hash": bc.last_block.hash, "miner": miner,
         "difficulty": DIFF, "nonce": -1, "timestamp": t0 + 10},
        {"index": 1 << 80, "transactions": [],
         "previous_hash": bc.last_block.hash, "miner": miner,
         "difficulty": DIFF, "nonce": 0, "timestamp": t0 + 10},
        {"index": 1, "transactions": [],
         "previous_hash": bc.last_block.hash, "miner": miner,
         "difficulty": DIFF, "nonce": 0, "timestamp": 1 << 80},
        {"index": 1, "transactions": [],
         "previous_hash": bc.last_block.hash, "miner": miner,
         "difficulty": DIFF, "nonce": 1 << 80, "timestamp": t0 + 10},
        {"index": 1, "transactions": [],
         "previous_hash": bc.last_block.hash, "miner": miner,
         "difficulty": 1 << 300, "nonce": 0, "timestamp": t0 + 10},
        {"index": 1, "transactions": [{}] * (core.MAX_BLOCK_TRANSACTIONS + 1),
         "previous_hash": bc.last_block.hash, "miner": miner,
         "difficulty": DIFF, "nonce": 0, "timestamp": t0 + 10},
        ["not", "a", "block"],
    ]
    for block in malformed_blocks:
        assert bc.add_block(block) is False, block


def test_timestamp_rules(tmpdir):
    old = core.ATOMIC_ACTIVATION
    core.ATOMIC_ACTIVATION = 2
    try:
        _, miner = keypair()
        bc = fresh(tmpdir, "timestamps.pkl", miner)
        t0 = bc.chain[0].timestamp
        assert bc.add_block(mine(bc, 1, [], t0 + 10)) is True

        future = int(time.time()) + core.MAX_FUTURE_DRIFT + 60
        assert bc.add_block(mine(bc, 2, [], future)) is False, \
            "blocks too far in the future must be rejected"

        assert bc.add_block(mine(bc, 2, [], t0 + 10)) is False, \
            "a timestamp at the median-time-past must be rejected"

        assert bc.add_block(mine(bc, 2, [], t0 + 20)) is True

        # Miner addresses must decode once the fork is active.
        assert bc.add_block(mine(bc, 3, [], t0 + 30,
                                 miner="not-an-address")) is False
    finally:
        core.ATOMIC_ACTIVATION = old


def test_signing_versions():
    priv, sender = keypair()
    _, receiver = keypair()

    atoms = 123_456_789
    legacy_sig = sign_transaction(priv, sender, receiver, 1.25, 1)
    legacy_payload = tx_signing_payload(sender, receiver, 1.25, 1)
    assert verify_transaction(sender, legacy_sig, legacy_payload)

    atom_sig = sign_transaction(priv, sender, receiver, atoms, 2,
                                version=TX_VERSION_ATOMS)
    atom_payload = tx_signing_payload(sender, receiver, atoms, 2,
                                      version=TX_VERSION_ATOMS)
    assert verify_transaction(sender, atom_sig, atom_payload)

    legacy_shape = tx_signing_payload(sender, receiver, atoms, 2,
                                      version=TX_VERSION_LEGACY)
    assert not verify_transaction(sender, atom_sig, legacy_shape), \
        "a version 2 signature must not replay as version 1"
    atom_shape = tx_signing_payload(sender, receiver, 1.25, 1,
                                    version=TX_VERSION_ATOMS)
    assert not verify_transaction(sender, legacy_sig, atom_shape), \
        "a version 1 signature must not replay as version 2"

    assert parse_amount_to_atoms("0.00000001") == 1
    assert parse_amount_to_atoms("1.23456789") == 123_456_789
    assert format_atoms(1) == "0.00000001"
    assert atoms_to_coins(COIN_ATOMS) == 1
    try:
        parse_amount_to_atoms("0.000000001")
        raise AssertionError("more than 8 decimals must be rejected")
    except ValueError:
        pass
    try:
        sign_transaction(priv, sender, receiver, 1.000000001, 3)
        raise AssertionError("legacy signing must reject excess precision")
    except ValueError:
        pass


def test_fee_and_identity():
    assert transaction_fee_atoms(core.ATOMIC_ACTIVATION - 1) == coins_to_atoms(1.0)
    assert transaction_fee_atoms(core.ATOMIC_ACTIVATION) == core.TRANSACTION_FEE

    before = core.network_id()
    original = core.ATOMIC_ACTIVATION
    try:
        core.ATOMIC_ACTIVATION = original + 1
        assert core.network_id() != before, \
            "network_id must commit to the activation height"
    finally:
        core.ATOMIC_ACTIVATION = original
    assert core.network_id() == before


def test_replay_live_chain(tmpdir):
    source = Path("blockchain.pkl")
    if not source.exists():
        print("  (no blockchain.pkl to replay)")
        return
    path = Path(tmpdir) / "replay.pkl"
    shutil.copyfile(source, path)
    bc = Blockchain.load(path)
    assert bc.is_chain_valid()
    assert bc.height > 1
    assert (core.config.GENESIS is None
            or bc.chain[0].miner == core.config.GENESIS["miner"])

    zero_txs = 0
    fractional = 0
    for index, block in enumerate(bc.chain):
        for tx in block.transactions:
            atoms = tx_amount_atoms(tx, index)
            if atoms == 0:
                zero_txs += 1
            if atoms % COIN_ATOMS:
                fractional += 1
            if tx.get("amount") == 10.5:
                assert atoms == coins_to_atoms(10.5)

    assert zero_txs > 0, "the historical zero-amount mail transactions must replay"

    if len(bc.chain) <= core.ATOMIC_ACTIVATION:
        balances = bc.rebuild_balances(bc.chain)
        tx_count = sum(len(block.transactions) for block in bc.chain)
        expected = (bc.reward * len(bc.chain)
                    - transaction_fee_atoms(0) * tx_count)
        assert sum(balances.values()) == expected
    print(f"  replayed height {bc.height}, zero-amount txs {zero_txs}, "
          f"fractional txs {fractional}")


def main():
    tmpdir = tempfile.mkdtemp()
    try:
        test_activation_boundary(tmpdir)
        test_duplicate_transactions(tmpdir)
        test_alternate_genesis(tmpdir)
        test_malformed_inputs(tmpdir)
        test_timestamp_rules(tmpdir)
        test_signing_versions()
        test_fee_and_identity()
        test_replay_live_chain(tmpdir)
    finally:
        shutil.rmtree(tmpdir)

    print("HARDFORK TESTS PASSED")


if __name__ == "__main__":
    main()
