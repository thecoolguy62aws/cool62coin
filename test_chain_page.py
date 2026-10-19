import shutil
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import main as node
import p2p
from p2p import PeerNetwork
from core import Block, Blockchain

DIFF = 1


def build(miner, height, tmpdir, name):
    bc = Blockchain(difficulty=DIFF, miner_address=miner,
                    chain_file=Path(tmpdir) / name)
    for i in range(1, height):
        b = Block(index=i, transactions=[], previous_hash=bc.last_block.hash,
                  miner=miner, difficulty=bc.difficulty_at_next())
        b.mine()
        bc.chain.append(b)
    return bc


def make_peer(bc, legacy=False, tamper=None):
    def on_peer(onion, method, path, body=None, timeout=15):
        parsed = urlparse(path)
        if parsed.path != "/chain":
            return None

        height = len(bc.chain)

        def dump():
            out = []
            for block in bc.chain:
                block_dict = block.to_dict()
                if tamper:
                    tamper(block_dict)
                out.append(block_dict)
            return out

        qs = parse_qs(parsed.query)
        if legacy or "from_index" not in qs:
            return {"success": True, "height": height, "blocks": dump()}
        start = int(qs["from_index"][0])
        limit = int(qs["limit"][0])
        end = min(height, start + limit)
        blocks = dump()[start:end]
        has_more = end < height
        return {"success": True, "height": height, "from_index": start,
                "count": len(blocks), "blocks": blocks,
                "genesis": bc.chain[0].hash, "tip": bc.chain[-1].hash,
                "has_more": has_more, "next_from": end if has_more else None}
    return on_peer


def test_chain_page(tmpdir):
    bc = build("minerA", 5, tmpdir, "page.pkl")

    full = bc.chain_page()
    assert full["height"] == 5 and full["from_index"] == 0
    assert full["count"] == 5 and full["has_more"] is False
    assert full["next_from"] is None
    assert full["genesis"] == bc.chain[0].hash
    assert full["tip"] == bc.last_block.hash
    assert full["blocks"] == [b.to_dict() for b in bc.chain]

    page = bc.chain_page(1, 2)
    assert page["from_index"] == 1 and page["count"] == 2
    assert page["has_more"] is True and page["next_from"] == 3
    assert page["blocks"] == [b.to_dict() for b in bc.chain[1:3]]

    end = bc.chain_page(4, 10)
    assert end["count"] == 1 and end["has_more"] is False

    past = bc.chain_page(99, 10)
    assert past["from_index"] == 5 and past["count"] == 0
    assert past["has_more"] is False


def test_http_endpoint(tmpdir):
    bc = build("minerA", 5, tmpdir, "http.pkl")
    node.blockchain = bc
    client = node.app.test_client()

    legacy = client.get("/chain").get_json()
    assert legacy["success"] is True and legacy["height"] == 5
    assert "from_index" not in legacy
    assert [b["hash"] for b in legacy["blocks"]] == [b.hash for b in bc.chain]

    paged = client.get("/chain?from_index=1&limit=2").get_json()
    assert paged["from_index"] == 1 and paged["count"] == 2
    assert paged["has_more"] is True and paged["next_from"] == 3
    assert [b["hash"] for b in paged["blocks"]] == \
        [b.hash for b in bc.chain[1:3]]

    default_limit = client.get("/chain?from_index=0").get_json()
    assert default_limit["count"] == 5
    assert default_limit["has_more"] is False

    assert client.get("/chain?from_index=-1").status_code == 400
    assert client.get("/chain?limit=0").status_code == 400
    assert client.get("/chain?from_index=abc").status_code == 400


def test_p2p_range_sync(tmpdir):
    remote = build("minerX", 5, tmpdir, "remote.pkl")
    local = build("minerX", 2, tmpdir, "local.pkl")

    pn = PeerNetwork(blockchain=local,
                     peers_file=Path(tmpdir) / "peers.txt",
                     my_onion="local.onion")
    pn.on_peer = make_peer(remote)

    old_limit = p2p.CHAIN_PAGE_LIMIT
    p2p.CHAIN_PAGE_LIMIT = 2
    try:
        candidate = pn._fetch_candidate("peer.onion", len(remote.chain),
                                        remote.chain[0].hash)
    finally:
        p2p.CHAIN_PAGE_LIMIT = old_limit

    assert candidate is not None
    assert [b["hash"] for b in candidate] == [b.hash for b in remote.chain]
    assert local.adopt_chain(candidate) is True
    assert local.height == 5
    assert local.last_block.hash == remote.last_block.hash


def test_p2p_rejects_invalid_chunk(tmpdir):
    remote = build("minerX", 5, tmpdir, "remote2.pkl")
    local = build("minerX", 2, tmpdir, "local2.pkl")

    def tamper(block_dict):
        if block_dict["index"] == 3:
            block_dict["transactions"] = [
                {"sender": "forged", "receiver": "attacker",
                 "amount": 10 ** 9, "nonce": 0, "signature": "00"}
            ]

    pn = PeerNetwork(blockchain=local,
                     peers_file=Path(tmpdir) / "peers.txt",
                     my_onion="local.onion")
    pn.on_peer = make_peer(remote, tamper=tamper)

    candidate = pn._fetch_candidate("peer.onion", len(remote.chain),
                                    remote.chain[0].hash)
    assert candidate is not None
    assert local.adopt_chain(candidate) is False, \
        "chunk with forged transactions must not be adopted"
    assert local.height == 2, "local chain must be untouched on rejection"


def test_p2p_legacy_fallback(tmpdir):
    remote = build("minerX", 4, tmpdir, "remote3.pkl")
    local = build("minerX", 2, tmpdir, "local3.pkl")

    pn = PeerNetwork(blockchain=local,
                     peers_file=Path(tmpdir) / "peers.txt",
                     my_onion="local.onion")
    pn.on_peer = make_peer(remote, legacy=True)

    candidate = pn._fetch_candidate("peer.onion", len(remote.chain),
                                    remote.chain[0].hash)
    assert candidate is not None
    assert [b["hash"] for b in candidate] == [b.hash for b in remote.chain]
    assert local.adopt_chain(candidate) is True
    assert local.height == 4


def main():
    tmpdir = tempfile.mkdtemp()
    try:
        test_chain_page(tmpdir)
        test_http_endpoint(tmpdir)
        test_p2p_range_sync(tmpdir)
        test_p2p_rejects_invalid_chunk(tmpdir)
        test_p2p_legacy_fallback(tmpdir)
    finally:
        shutil.rmtree(tmpdir)

    print("CHAIN PAGE TESTS PASSED")


if __name__ == "__main__":
    main()
