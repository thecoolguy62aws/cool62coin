import argparse
import hashlib
import json
import threading
import time
from pathlib import Path

from flask import Flask, request, jsonify

import config
from core import Blockchain, network_id
from p2p import PeerNetwork
from torlaunch import TorDaemon

app = Flask(__name__)
blockchain = None

my_onion = ""
peer_net = None


@app.get("/")
def index():
    return jsonify(
        success=True,
        onion=my_onion,
        endpoints={
            "POST /transaction": "{sender, receiver, amount, signature, nonce}",
            "GET /balance": "?address=<hex public key>",
            "POST /block": "submit a fully-mined block",
            "GET /chain": "full serialized chain",
            "POST /chain": "adopt a full serialized chain",
            "GET /txpool": "unconfirmed transactions",
            "GET|POST /peers": "list or announce onion peers",
            "GET /info": "node info",
            "GET /p2p": "per-peer sync diagnostics",
        },
    )


@app.post("/transaction")
def transaction():
    data = request.get_json(silent=True) or {}
    sender = data.get("sender")
    receiver = data.get("receiver")
    amount = data.get("amount")
    signature = data.get("signature")
    nonce = data.get("nonce", 0)

    if not all(isinstance(v, str) and v for v in (sender, receiver, signature)):
        return jsonify(success=False, error="sender, receiver and signature must be non-empty strings"), 400

    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        return jsonify(success=False, error="amount must be a number"), 400

    if isinstance(nonce, bool) or not isinstance(nonce, int):
        return jsonify(success=False, error="nonce must be an integer"), 400

    tx = {
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "nonce": nonce,
        "signature": signature,
    }
    already = blockchain.mempool_has(tx)
    if not blockchain.add_transaction(sender, receiver, amount, signature, nonce):
        return jsonify(success=False, error="transaction rejected: bad signature, invalid address or insufficient funds"), 400
    if not already:
        threading.Thread(target=peer_net.on_local_tx, args=(tx,), daemon=True).start()
    return jsonify(success=True), 201


@app.get("/balance")
def balance():
    address = request.args.get("address")
    if not address:
        return jsonify(success=False, error="missing 'address' query parameter"), 400

    return jsonify(success=True, address=address, balance=blockchain.get_balance(address))


@app.post("/block")
def block():
    data = request.get_json(silent=True) or {}
    if blockchain.add_block(data):
        threading.Thread(target=peer_net.broadcast_block, args=(data,),
                         daemon=True).start()
        return jsonify(success=True), 200
    return jsonify(success=False, error="block rejected"), 400


@app.get("/chain")
def chain():
    return jsonify(
        success=True,
        height=len(blockchain.chain),
        blocks=[b.to_dict() for b in blockchain.chain],
    )


@app.post("/chain")
def upload_chain():
    data = request.get_json(silent=True) or {}
    blocks = data.get("blocks")
    if not isinstance(blocks, list) or not blocks:
        return jsonify(success=False, error="missing blocks"), 400
    if blockchain.adopt_chain(blocks):
        threading.Thread(target=peer_net.broadcast_chain, args=(blocks,),
                         daemon=True).start()
        return jsonify(success=True), 200
    return jsonify(success=False, error="blockchain rejected"), 400


@app.get("/txpool")
def txpool():
    return jsonify(success=True, transactions=blockchain.unconfirmed_transactions)


@app.get("/peers")
def peers():
    return jsonify(success=True, peers=peer_net.peer_list())


@app.post("/peers")
def announce_peers():
    data = request.get_json(silent=True) or {}
    for onion in data.get("peers", []):
        peer_net.add_peer(onion)
    return jsonify(success=True)


@app.get("/info")
def info():
    return jsonify(
        success=True,
        onion=my_onion,
        height=len(blockchain.chain),
        difficulty=blockchain.difficulty_at_next(),
        reward=blockchain.reward,
        network_id=network_id(),
        genesis=blockchain.chain[0].hash,
        tip=blockchain.last_block.hash,
    )


@app.get("/p2p")
def p2p():
    return jsonify(
        success=True,
        onion=my_onion,
        peers=[
            {"onion": onion, **state}
            for onion, state in sorted(peer_net.peer_status().items())
        ],
    )


_work_memo_lock = threading.Lock()
_work_memo = {"key": None, "template": None}


@app.get("/work")
def work():
    tip = blockchain.last_block
    index = len(blockchain.chain)
    transactions = list(blockchain.unconfirmed_transactions)
    tx_ids = tuple(sorted(blockchain.tx_id(tx) for tx in transactions))
    difficulty = blockchain.difficulty_at_next()
    key = (index, tip.hash, difficulty, tx_ids)
    with _work_memo_lock:
        if _work_memo["key"] != key:
            _work_memo["key"] = key
            _work_memo["template"] = {
                "index": index,
                "previous_hash": tip.hash,
                "transactions": transactions,
                "difficulty": difficulty,
                "timestamp": int(time.time()),
            }
        template = _work_memo["template"]
    template_id = hashlib.sha256(
        json.dumps(template, sort_keys=True).encode()
    ).hexdigest()
    return jsonify(
        success=True,
        pending=bool(template["transactions"]),
        template_id=template_id,
        **template,
    )


def main():
    parser = argparse.ArgumentParser(description="Tor blockchain node")
    parser.add_argument("--port", type=int, default=config.INTERNAL_PORT)
    parser.add_argument("--socks", type=int, default=config.SOCKS_PORT)
    parser.add_argument("--data", default=str(config.DATA_DIR))
    parser.add_argument("--peers", default=str(config.PEERS_FILE))
    parser.add_argument("--tor", default=str(config.TOR_BIN))
    parser.add_argument("--chain", default=None)
    parser.add_argument("--sync-interval", type=int, default=config.SYNC_INTERVAL)
    args = parser.parse_args()

    global my_onion, peer_net, blockchain
    blockchain = Blockchain.load(args.chain)

    tor = TorDaemon(
        data_dir=args.data,
        socks_port=args.socks,
        server_port=args.port,
        tor_bin=args.tor,
    )
    my_onion = tor.start()

    peer_net = PeerNetwork(
        blockchain=blockchain,
        peers_file=args.peers,
        my_onion=my_onion,
        socks_port=args.socks,
        sync_interval=args.sync_interval,
    )

    threading.Thread(target=peer_net.run, daemon=True).start()

    try:
        app.run(host="127.0.0.1", port=args.port)
    except KeyboardInterrupt:
        print("\nshutting down...")
    finally:
        tor.stop()


if __name__ == "__main__":
    main()