import shutil
import tempfile
from pathlib import Path

from core import Block, Blockchain

HEIGHT = 3
DIFF = 3


def build(miner, tmpdir):
    bc = Blockchain(difficulty=DIFF, miner_address=miner,
                    chain_file=Path(tmpdir) / f"{miner}.pkl")
    for i in range(1, HEIGHT):
        b = Block(index=i, transactions=[], previous_hash=bc.last_block.hash,
                  miner=miner, difficulty=bc.difficulty_at_next())
        b.mine()
        bc.chain.append(b)
    return bc


def rival_block(prefix, miner, extra_timestamp):
    return Block(index=len(prefix), transactions=[],
                 previous_hash=prefix[-1].hash, miner=miner,
                 difficulty=prefix[-1].difficulty,
                 timestamp=prefix[-1].timestamp + extra_timestamp)


def to_dicts(chain):
    return [b.to_dict() for b in chain]


def main():
    tmpdir = tempfile.mkdtemp()
    try:
        a = build("minerA", tmpdir)
        prefix = a.chain[:2]
        rival = rival_block(prefix, "minerB", 123.4)
        rival.mine()

        tip_a = a.chain[-1].hash
        tip_b = rival.hash
        assert tip_a != tip_b, "rival block should differ from A tip"

        candidate_b = to_dicts(prefix) + [rival.to_dict()]
        candidate_a = to_dicts(a.chain)

        adopt_ab = a.adopt_chain(candidate_b)
        assert adopt_ab is False or tip_b < tip_a, "A adopting B requires B tip smaller"

        b = build("minerB", tmpdir)
        b.chain = prefix + [rival]
        adopt_ba = b.adopt_chain(candidate_a)
        assert adopt_ba is False or tip_a < tip_b, "B adopting A requires A tip smaller"

        assert adopt_ab != adopt_ba, "equal-height adoption must resolve one way"

        if tip_b < tip_a:
            assert adopt_ab, "smaller-tip rival must be adopted"
            assert b.chain[-1].hash == tip_b, "B unchanged after failed adoption"
        else:
            assert adopt_ba, "smaller-tip rival must be adopted"
            assert a.chain[-1].hash == tip_a, "A unchanged after failed adoption"

        same_tip = a.adopt_chain(candidate_a)
        assert same_tip is False, "adopting own identical chain must be rejected"

        short = a.adopt_chain(to_dicts(prefix))
        assert short is False, "shorter chain must be rejected"

        longer = a.chain + [rival_block(a.chain, "minerA", 999.0)]
        longer[-1].mine()
        grows = b.adopt_chain(to_dicts(longer))
        assert grows, "strictly longer chain must be adopted"
        assert b.height == HEIGHT + 1
    finally:
        shutil.rmtree(tmpdir)

    print("TIEBREAK TESTS PASSED")


if __name__ == "__main__":
    main()