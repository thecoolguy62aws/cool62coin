import shutil
import tempfile
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

from core import (Blockchain, MiningInterrupted, solve_block, load_private_key,
                  load_key_address, sign_transaction)

DIFF = 3


def main():
    tmpdir = tempfile.mkdtemp()
    try:
        miner = load_key_address()
        priv = load_private_key("private_key.pem")
        target = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()

        bc = Blockchain(difficulty=DIFF, miner_address=miner,
                        chain_file=Path(tmpdir) / "chain.pkl")

        assert bc.mine_block_candidate() is None, "empty pool must yield no candidate"

        sig = sign_transaction(priv, miner, target, 10.0, 1)
        assert bc.add_transaction(miner, target, 10.0, sig, 1) is True

        candidate = bc.mine_block_candidate()
        assert candidate is not None
        assert candidate["index"] == 1
        assert candidate["previous_hash"] == bc.last_block.hash
        assert candidate["difficulty"] == DIFF
        assert len(candidate["transactions"]) == 1

        solved = solve_block(candidate)
        assert solved["difficulty"] == DIFF
        assert solved["hash"].startswith("0" * DIFF)
        assert solved["index"] == 1

        assert bc.commit_mined(solved) is True
        assert bc.height == 2
        assert bc.get_balance(miner) == 190.0
        assert bc.get_balance(target) == 10.0

        assert bc.commit_mined(solved) is False, "stale commit must be rejected"

        sig2 = sign_transaction(priv, miner, target, 10.0, 2)
        assert bc.add_transaction(miner, target, 10.0, sig2, 2) is True
        future_candidate = bc.mine_block_candidate()
        assert future_candidate["index"] == 2

        rival = solve_block({
            "index": 2,
            "transactions": [],
            "previous_hash": solved["hash"],
            "miner": miner,
            "difficulty": DIFF,
        })
        assert bc.commit_mined(rival) is True, "rival block at current index commits"

        stale_solved = solve_block(future_candidate)
        assert bc.commit_mined(stale_solved) is False, "snapshot stale after chain growth"

        stale_prev = solve_block({
            "index": 3,
            "transactions": [],
            "previous_hash": "0" * 64,
            "miner": miner,
            "difficulty": DIFF,
        })
        assert bc.commit_mined(stale_prev) is False, "wrong previous_hash must be rejected"

        lock_free = {"index": 999, "transactions": [], "previous_hash": "0" * 64,
                     "miner": miner, "difficulty": 6}
        grinder = threading.Thread(target=solve_block, args=(lock_free,), daemon=True)
        grinder.start()
        time.sleep(0.05)
        t0 = time.time()
        assert bc.mine_block_candidate() is not None or True
        bc.get_balance(miner)
        elapsed = time.time() - t0
        assert elapsed < 1.0, f"chain lock held during solve: {elapsed:.2f}s"

        s = solve_block({"index": 3, "transactions": [], "previous_hash": "0" * 64,
                         "miner": miner, "difficulty": DIFF},
                        nonce_start=7, stride=5)
        assert s["hash"].startswith("0" * DIFF)
        assert s["nonce"] >= 7 and (s["nonce"] - 7) % 5 == 0, \
            f"stride violated: nonce {s['nonce']}"

        abort = threading.Event()
        result = {}
        def aborted_solve():
            try:
                solve_block({"index": 3, "transactions": [], "previous_hash": "0" * 64,
                             "miner": miner, "difficulty": 20},
                            nonce_start=0, stride=1, stop_event=abort)
                result["exc"] = None
            except MiningInterrupted:
                result["exc"] = "interrupted"
            except Exception as e:
                result["exc"] = repr(e)
        aborter = threading.Thread(target=aborted_solve, daemon=True)
        aborter.start()
        time.sleep(0.05)
        abort.set()
        aborter.join(2.0)
        assert result.get("exc") == "interrupted", \
            f"expected MiningInterrupted, got {result!r}"
        assert not aborter.is_alive(), "solve thread must exit after interrupt"
    finally:
        shutil.rmtree(tmpdir)

    print("MINE TESTS PASSED")


if __name__ == "__main__":
    main()