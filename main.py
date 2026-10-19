import argparse
import hashlib
import json
import logging
import sys
import threading
import time
from pathlib import Path

from waitress import serve
from flask import Flask, request, jsonify, g

import config
from core import Blockchain, network_id, CHAIN_FILE, is_valid_address
from p2p import PeerNetwork
from torlaunch import TorDaemon

logger = logging.getLogger(__name__)

app = Flask(__name__)
blockchain = None

my_onion = ""
peer_net = None

CHAIN_PAGE_MAX = getattr(config, "CHAIN_PAGE_MAX", 1000)
TX_MEMO_MAX = getattr(config, "TX_MEMO_MAX", 512)


@app.before_request
def _request_started():
    g._started_at = time.monotonic()


@app.after_request
def _log_request(response):
    if request.method == "GET" and response.status_code < 400:
        return response
    started = getattr(g, "_started_at", None)
    elapsed_ms = (time.monotonic() - started) * 1000 if started else 0.0
    target = request.full_path if request.query_string else request.path
    level = logging.WARNING if response.status_code >= 400 else logging.INFO
    logger.log(level, "%s %s -> %s (%.1fms)", request.method, target,
               response.status_code, elapsed_ms)
    return response


@app.get("/")
def index():
    return jsonify(
        success=True,
        onion=my_onion,
        endpoints={
            "POST /transaction": "{sender, receiver, amount, signature, nonce, memo?}",
            "GET /balance": "?address=<hex public key>",
            "POST /block": "submit a fully-mined block",
            "GET /chain": "serialized chain (?from_index=&limit= pages, else full)",
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
    memo = data.get("memo")

    if not all(isinstance(v, str) and v for v in (sender, receiver, signature)):
        return jsonify(success=False, error="sender, receiver and signature must be non-empty strings"), 400

    if not is_valid_address(sender):
        return jsonify(success=False, error="sender is not a valid address"), 400

    if not is_valid_address(receiver):
        return jsonify(success=False, error="receiver is not a valid address"), 400

    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        return jsonify(success=False, error="amount must be a number"), 400

    if isinstance(nonce, bool) or not isinstance(nonce, int):
        return jsonify(success=False, error="nonce must be an integer"), 400

    if memo is not None and not isinstance(memo, str):
        return jsonify(success=False, error="memo must be a string"), 400
    if memo and len(memo.encode("utf-8")) > TX_MEMO_MAX:
        return jsonify(success=False, error=f"memo exceeds {TX_MEMO_MAX} bytes"), 400

    tx = {
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "nonce": nonce,
        "signature": signature,
    }
    if memo:
        tx["memo"] = memo
    already = blockchain.mempool_has(tx)
    if not blockchain.add_transaction(sender, receiver, amount, signature, nonce, memo):
        return jsonify(success=False, error="transaction rejected: bad signature, invalid address or insufficient funds"), 400
    logger.info("accepted tx %s %s->%s amount=%s",
                blockchain.tx_id(tx)[:8], sender[:8], receiver[:8], amount)
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
        logger.info("accepted block #%s %s (txs=%d)",
                    data.get("index"), str(data.get("hash"))[:8],
                    len(data.get("transactions") or []))
        threading.Thread(target=peer_net.broadcast_block, args=(data,),
                         daemon=True).start()
        return jsonify(success=True), 200
    return jsonify(success=False, error="block rejected"), 400


@app.get("/chain")
def chain():
    raw_from = request.args.get("from_index")
    raw_limit = request.args.get("limit")

    if raw_from is None and raw_limit is None:
        page = blockchain.chain_page()
        return jsonify(success=True, height=page["height"],
                       blocks=page["blocks"])

    try:
        from_index = int(raw_from) if raw_from is not None else 0
        limit = int(raw_limit) if raw_limit is not None else CHAIN_PAGE_MAX
    except (TypeError, ValueError):
        return jsonify(success=False,
                       error="from_index and limit must be integers"), 400

    if from_index < 0:
        return jsonify(success=False, error="from_index must be >= 0"), 400
    if limit < 1:
        return jsonify(success=False, error="limit must be >= 1"), 400

    limit = min(limit, CHAIN_PAGE_MAX)
    page = blockchain.chain_page(from_index, limit)
    return jsonify(success=True, **page)


@app.post("/chain")
def upload_chain():
    data = request.get_json(silent=True) or {}
    blocks = data.get("blocks")
    if not isinstance(blocks, list) or not blocks:
        return jsonify(success=False, error="missing blocks"), 400
    previous_height = blockchain.height
    if blockchain.adopt_chain(blocks):
        logger.info("adopted chain from peer: height %d -> %d",
                    previous_height, len(blocks))
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
        chain_page_max=CHAIN_PAGE_MAX,
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
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    logging.basicConfig(
        level=args.log_level, stream=sys.stdout,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    global my_onion, peer_net, blockchain
    chain_path = Path(args.chain) if args.chain else CHAIN_FILE
    had_chain = chain_path.exists()
    blockchain = Blockchain.load(args.chain)
    if had_chain:
        logger.info("loaded chain height=%d tip=%s genesis=%s",
                    blockchain.height, blockchain.last_block.hash[:8],
                    blockchain.chain[0].hash[:8])
    else:
        logger.info("no stored chain; mined genesis %s",
                    blockchain.chain[0].hash[:8])

    logger.info("starting Tor hidden service (data=%s, socks=%d, port=%d)",
                args.data, args.socks, args.port)
    tor = TorDaemon(
        data_dir=args.data,
        socks_port=args.socks,
        server_port=args.port,
        tor_bin=args.tor,
    )
    my_onion = tor.start()
    logger.info("hidden service ready: %s", my_onion)

    peer_net = PeerNetwork(
        blockchain=blockchain,
        peers_file=args.peers,
        my_onion=my_onion,
        socks_port=args.socks,
        sync_interval=args.sync_interval,
    )
    logger.info("known peers (%d): %s", len(peer_net.peers),
                ", ".join(sorted(peer_net.peers)) or "-")

    threading.Thread(target=peer_net.run, daemon=True).start()

    try:
        logger.info("listening on 127.0.0.1:%d network_id=%s reward=%s",
                    args.port, network_id()[:8], blockchain.reward)
        serve(app, host="127.0.0.1", port=args.port)
    except KeyboardInterrupt:
        logger.info("shutting down...")
    finally:
        tor.stop()


if __name__ == "__main__":
    main()