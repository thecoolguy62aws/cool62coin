import shutil
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

import bech32_codec
import core
from core import (ADDRESS_SCHEME_BECH32, ADDRESS_SCHEME_HEX, Block,
                  Blockchain, canonical_address, decode_address,
                  encode_address, is_valid_address, sign_transaction)

DIFF = 3
VECTOR = "c621qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0sppecz3"


def main():
    tmpdir = tempfile.mkdtemp()
    old_activation = core.BECH32_ACTIVATION
    try:
        raw = bytes(range(32))
        pub = ed25519.Ed25519PublicKey.from_public_bytes(raw)
        assert encode_address(pub, ADDRESS_SCHEME_BECH32) == VECTOR, \
            "Bech32m encoding must match the reference vector"
        assert decode_address(VECTOR).public_bytes_raw() == raw

        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        hex_addr = encode_address(pub, ADDRESS_SCHEME_HEX)
        bech_addr = encode_address(pub, ADDRESS_SCHEME_BECH32)

        assert bech_addr.startswith("c621"), "Bech32 addresses use the c62 prefix"
        assert canonical_address(bech_addr) == hex_addr
        assert canonical_address(hex_addr) == hex_addr
        assert decode_address(bech_addr).public_bytes_raw() == pub.public_bytes_raw()
        assert is_valid_address(bech_addr)
        assert is_valid_address(hex_addr)
        assert is_valid_address(bech_addr.upper()), "all-uppercase Bech32 is valid"

        assert not is_valid_address(bech_addr[:-1] + ("q" if bech_addr[-1] != "q" else "p")), \
            "checksum tampering must be rejected"

        data = bech32_codec.convertbits(pub.public_bytes_raw(), 8, 5, True)
        wrong_hrp = bech32_codec.encode("bc", data)
        assert not is_valid_address(wrong_hrp), "wrong HRP must be rejected"

        mixed_index = next(i for i, c in enumerate(bech_addr) if c.isalpha())
        mixed = (bech_addr[:mixed_index] + bech_addr[mixed_index].upper()
                 + bech_addr[mixed_index + 1:])
        assert not is_valid_address(mixed), "mixed-case Bech32 must be rejected"

        core.BECH32_ACTIVATION = 0
        assert is_valid_address(bech_addr, 0)
        assert is_valid_address(bech_addr, 1499)

        core.BECH32_ACTIVATION = 1500
        assert is_valid_address(bech_addr, 1500)
        assert not is_valid_address(bech_addr, 1499)

        # ------- shared balances across encodings -------
        core.BECH32_ACTIVATION = 0
        miner_priv = ed25519.Ed25519PrivateKey.generate()
        miner_pub = miner_priv.public_key()
        miner_hex = encode_address(miner_pub, ADDRESS_SCHEME_HEX)
        miner_bech = encode_address(miner_pub, ADDRESS_SCHEME_BECH32)

        target_priv = ed25519.Ed25519PrivateKey.generate()
        target_pub = target_priv.public_key()
        target_hex = encode_address(target_pub, ADDRESS_SCHEME_HEX)
        target_bech = encode_address(target_pub, ADDRESS_SCHEME_BECH32)

        bc = Blockchain(difficulty=DIFF, miner_address=miner_hex,
                        chain_file=Path(tmpdir) / "chain.pkl")

        sig = sign_transaction(miner_priv, miner_hex, target_bech, 5.0, 1)
        assert bc.add_transaction(miner_hex, target_bech, 5.0, sig, 1) is True
        assert bc.mine_pending_transactions() is True

        assert bc.get_balance(target_hex) == 5.0
        assert bc.get_balance(target_bech) == 5.0, \
            "Bech32 form must see the same balance as hex"

        sig_back = sign_transaction(target_priv, target_bech, miner_hex, 1.0, 2)
        assert bc.add_transaction(target_bech, miner_hex, 1.0, sig_back, 2) is True
        assert bc.mine_pending_transactions() is True
        assert bc.get_balance(target_bech) == 3.0
        assert bc.get_balance(target_hex) == 3.0

        tx_hex = {"sender": target_hex, "receiver": miner_hex, "amount": 1.0,
                  "nonce": 9, "signature": "00"}
        tx_bech = dict(tx_hex, sender=target_bech)
        tx_receiver_bech = dict(tx_hex, receiver=miner_bech)
        assert bc.tx_id(tx_hex) == bc.tx_id(tx_bech), \
            "sender encoding must not change the logical tx id"
        assert bc.tx_id(tx_hex) == bc.tx_id(tx_receiver_bech), \
            "receiver encoding must not change the logical tx id"

        # ------- pending fees and mempool pruning -------
        fee_bc = Blockchain(difficulty=DIFF, miner_address=miner_hex,
                            chain_file=Path(tmpdir) / "fees.pkl")
        sig1 = sign_transaction(miner_priv, miner_hex, target_bech, 50.0, 101)
        sig2 = sign_transaction(miner_priv, miner_hex, target_bech, 49.0, 102)
        assert fee_bc.add_transaction(miner_hex, target_bech, 50.0, sig1, 101) is True
        assert fee_bc.add_transaction(miner_hex, target_bech, 49.0, sig2, 102) is False, \
            "second tx must reserve the fee for the first tx too"
        tx2 = {"sender": miner_hex, "receiver": target_bech, "amount": 49.0,
               "nonce": 102, "signature": sig2}
        fee_bc.unconfirmed_transactions.append(tx2)
        fee_bc._prune_invalid_mempool()
        assert len(fee_bc.unconfirmed_transactions) == 1, \
            "overcommitted mempool transaction must be pruned"
        assert fee_bc.pending_debits[canonical_address(miner_hex)] == 51.0
        candidate = fee_bc.mine_block_candidate()
        assert candidate is not None and len(candidate["transactions"]) == 1

        # ------- activation gates -------
        core.BECH32_ACTIVATION = 1500
        pre = Blockchain(difficulty=DIFF, miner_address=miner_hex,
                         chain_file=Path(tmpdir) / "pre.pkl")
        pre_sig = sign_transaction(miner_priv, miner_hex, target_bech, 1.0, 10)
        assert pre.add_transaction(miner_hex, target_bech, 1.0, pre_sig, 10) is False, \
            "Bech32 receivers must be rejected before activation"
        from_sig = sign_transaction(target_priv, target_bech, miner_hex, 1.0, 11)
        assert pre.add_transaction(target_bech, miner_hex, 1.0, from_sig, 11) is False, \
            "Bech32 senders must be rejected before activation"

        bad_block = Block(index=1, transactions=[],
                          previous_hash=pre.last_block.hash,
                          miner=target_bech, difficulty=pre.difficulty_at_next(),
                          nonce=0)
        bad_block.mine()
        assert pre.validate_chain(list(pre.chain) + [bad_block]) is False, \
            "Bech32 miners must be rejected before activation"

        core.BECH32_ACTIVATION = 0
        assert pre.add_transaction(miner_hex, target_bech, 1.0, pre_sig, 10) is True, \
            "Bech32 receivers must be accepted after activation"

        bech_miner = Blockchain(difficulty=DIFF, miner_address=target_bech,
                                chain_file=Path(tmpdir) / "bech_miner.pkl")
        assert bech_miner.chain[0].miner == target_bech
        assert bech_miner.get_balance(target_hex) == bech_miner.reward
        assert bech_miner.get_balance(target_bech) == bech_miner.reward, \
            "Bech32 mining rewards must credit the shared account"

        core.BECH32_ACTIVATION = 1500
        pre_miner = Blockchain(difficulty=DIFF, miner_address=target_bech,
                               chain_file=Path(tmpdir) / "pre_miner.pkl")
        assert pre_miner.chain[0].miner == target_hex, \
            "pre-activation genesis must fall back to the hex encoding"
    finally:
        core.BECH32_ACTIVATION = old_activation
        shutil.rmtree(tmpdir)

    print("ADDRESS TESTS PASSED")


if __name__ == "__main__":
    main()
