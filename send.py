import argparse
import sys
import time

import requests

from core import load_key_address, load_private_key, sign_transaction

DEFAULT_NODE = "http://127.0.0.1:8090"
DEFAULT_KEY = "private_key.pem"


def _node(base, path, method="GET", body=None):
    try:
        resp = requests.request(method, base.rstrip("/") + path, json=body, timeout=30)
    except requests.RequestException as e:
        sys.stderr.write(f"error: cannot reach node ({e})\n")
        sys.exit(1)
    if resp.status_code >= 400:
        data = resp.json() if resp.headers.get("content-type") == "application/json" else {}
        sys.stderr.write(f"error: {resp.status_code} {data.get('error', resp.text)}\n")
        sys.exit(1)
    return resp.json()


def _amount(value):
    try:
        amount = float(value)
    except ValueError:
        sys.exit(f"error: invalid amount '{value}'")
    if amount < 0:
        sys.exit("error: amount must be non-negative")
    return amount


def cmd_address(args):
    print(load_key_address())


def cmd_balance(args):
    address = args.address or load_key_address()
    data = _node(args.node, f"/balance?address={address}")
    print(f"{address}\nbalance: {data['balance']}")


def cmd_send(args):
    receiver = args.receiver
    amount = _amount(args.amount)
    node_url = args.node

    from_address = load_key_address()
    private_key = load_private_key(args.key)
    nonce = int(time.time())

    signature = sign_transaction(private_key, from_address, receiver, amount, nonce)
    tx = {
        "sender": from_address,
        "receiver": receiver,
        "amount": amount,
        "nonce": nonce,
        "signature": signature,
    }

    from_path = args.node.replace("http://", "").replace("https://", "")
    print(f"sending {amount} to {receiver[:16]}... from {from_address[:16]} at {from_path}")
    _node(args.node, "/transaction", method="POST", body=tx)
    print(f"tx accepted (nonce {nonce}); it will enter the next mined block")


HELP_TEXT = """commands:
  address                      print this wallet's address
  balance [address]            show a balance (default: this wallet)
  send <receiver> <amount>     sign and send a transaction
  status                       node height / difficulty / own onion
  help                         show this help
  quit                         exit"""


def cmd_status(args):
    data = _node(args.node, "/info")
    print(f"node:  {args.node}")
    print(f"onion: {data.get('onion', '?')}")
    print(f"height: {data['height']}   difficulty: {data['difficulty']}   reward: {data['reward']}")


def interactive(args):
    print(f"interactive wallet - node {args.node} (type 'help' for commands)")
    while True:
        try:
            line = input("wallet> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        cmd, _, rest = line.partition(" ")
        parts = rest.split()
        try:
            if cmd in ("quit", "exit", "q", "bye"):
                break
            elif cmd in ("help", "h"):
                print(HELP_TEXT)
            elif cmd == "address":
                cmd_address(args)
            elif cmd == "status":
                cmd_status(args)
            elif cmd == "balance":
                args.address = parts[0] if parts else None
                cmd_balance(args)
            elif cmd == "send":
                if len(parts) < 2:
                    print("usage: send <receiver> <amount>")
                    continue
                args.receiver = parts[0]
                args.amount = parts[1]
                args.key = DEFAULT_KEY
                cmd_send(args)
            else:
                print(f"unknown command '{cmd}' - try 'help'")
        except SystemExit:
            pass


def main():
    parser = argparse.ArgumentParser(description="blockchain wallet CLI (interactive by default)")
    parser.add_argument("--node", default=DEFAULT_NODE, help=f"local node API base URL (default {DEFAULT_NODE})")
    parser.add_argument("--key", default=DEFAULT_KEY, help=f"private key file (default {DEFAULT_KEY})")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("address", help="print this node's wallet address")

    p = sub.add_parser("balance", help="show a balance (default: own)")
    p.add_argument("address", nargs="?", default=None, help="address to query (default: wallet key)")

    p = sub.add_parser("send", help="sign and send a transaction")
    p.add_argument("receiver", help="receiver address (hex public key)")
    p.add_argument("amount", help="amount to send")

    args = parser.parse_args()
    if args.command is None:
        interactive(args)
    elif args.command == "address":
        cmd_address(args)
    elif args.command == "balance":
        cmd_balance(args)
    elif args.command == "send":
        cmd_send(args)


if __name__ == "__main__":
    main()