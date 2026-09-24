import shutil
import tempfile
from pathlib import Path

import core
import config
from core import (Block, Blockchain, network_id, solve_block, load_key_address)


def fresh(tmpdir, name):
    return Blockchain(chain_file=Path(tmpdir) / name)


def main():
    tmpdir = tempfile.mkdtemp()
    try:
        a = fresh(tmpdir, "a.pkl")
        b = fresh(tmpdir, "b.pkl")

        assert a.chain[0].to_dict() == b.chain[0].to_dict(), \
            "default instances must share an identical deterministic genesis"
        assert len(a.chain) == 1 and a.chain[0].is_mined()
        assert a.chain[0].miner == config.GENESIS["miner"]
        founder = config.GENESIS["miner"]
        assert a.get_balance(founder) == a.reward, "founder receives genesis reward"

        # strictly longer chain on a shared genesis must be adopted
        base = {
            "index": 1,
            "transactions": [],
            "previous_hash": a.last_block.hash,
            "miner": load_key_address(),
            "difficulty": a.difficulty_at_next(),
            "timestamp": None,
        }
        solved = solve_block(base)
        assert a.add_block(solved) is True
        assert a.height == 2
        adopted = b.adopt_chain([blk.to_dict() for blk in a.chain])
        assert adopted is True, "longer chain on shared genesis must be adopted"
        assert b.height == 2
        assert b.last_block.hash == a.last_block.hash

        # adopt own identical chain is still rejected
        assert b.adopt_chain([blk.to_dict() for blk in a.chain]) is False

        # network_id is stable and sensitive to consensus constants
        before = network_id()
        tmp_fee = core.TRANSACTION_FEE
        core.TRANSACTION_FEE = 2.0
        try:
            assert network_id() != before, "network_id must change with consensus"
        finally:
            core.TRANSACTION_FEE = tmp_fee
        assert network_id() == before

        # load() self-heals a corrupt stored chain to deterministic genesis
        c = fresh(tmpdir, "bad.pkl")
        g = c.chain[0]
        broken = Block(0, [], "0", miner=None, difficulty=g.difficulty,
                       timestamp=g.timestamp, nonce=g.nonce)
        c.chain = [broken]
        c.save()
        healed = Blockchain.load(Path(tmpdir) / "bad.pkl")
        assert healed.height == 1
        assert healed.chain[0].miner == config.GENESIS["miner"], \
            "invalid stored chain must reset to the deterministic genesis"
    finally:
        shutil.rmtree(tmpdir)

    print("NETWORK TESTS PASSED")


if __name__ == "__main__":
    main()