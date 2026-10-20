import argparse
import sys
import os
import time
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import requests

from core import load_key_address, load_private_key, sign_transaction, is_valid_address

DEFAULT_NODE = "http://127.0.0.1:8090"
DEFAULT_KEY = "private_key.pem"

def _wait_for_key(prompt):
    print(prompt, end="", flush=True)
    
    if os.name == 'nt':
        import msvcrt
        char = msvcrt.getwch() 
    else:
        import termios
        import tty
        
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            char = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            
    print("\r" + " " * len(prompt) + "\r", end="", flush=True)
    return char

def _clear_console():
    if os.name == 'nt':
        os.system("cls")
    else:
        os.system("clear")

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
    print(f"{address}\nbalance: {int(data['balance']) if data['balance'].is_integer() else data['balance']}")


def cmd_send(args):
    receiver = args.receiver
    amount = _amount(args.amount)
    memo = getattr(args, "memo", None) or None
    node_url = args.node

    if not is_valid_address(receiver):
        sys.exit("error: receiver is not a valid address")

    from_address = load_key_address()
    private_key = load_private_key(args.key)
    nonce = int(time.time())

    try:
        signature = sign_transaction(private_key, from_address, receiver, amount, nonce, memo)
    except ValueError as e:
        sys.exit(f"error: {e}")
    tx = {
        "sender": from_address,
        "receiver": receiver,
        "amount": amount,
        "nonce": nonce,
        "signature": signature,
    }
    if memo:
        tx["memo"] = memo

    from_path = args.node.replace("http://", "").replace("https://", "")
    print(f"sending {int(amount) if amount.is_integer() else amount} to {receiver[:16]}... from {from_address[:16]} at {from_path}")
    _node(args.node, "/transaction", method="POST", body=tx)
    print(f"tx accepted (nonce {nonce}); it will enter the next mined block")


HELP_TEXT = """commands:
  address                      print this wallet's address
  balance [address]            show a balance (default: this wallet)
  send <receiver> <amount> [memo]  sign and send a transaction
  status                       node height / difficulty / own onion
  help                         show this help
  quit                         exit"""


def cmd_status(args):
    data = _node(args.node, "/info")
    print(f"node:  {args.node}")
    print(f"onion: {data.get('onion', '?')}")
    print(f"height: {data['height']}   difficulty: {data['difficulty']}   reward: {data['reward']}")


def interactive(args):
    if not Path("private_key.pem").is_file():
        _clear_console()
        print("Hello! It looks like you're new here. Lets get cool62coin set up for you.")
        print("By continuing, you agree that this software is provided as is and the creators of this tool are not liable for and provide no warranty for any losses or damages, to the extent permitted by applicable law.")
        _wait_for_key("\n\033[3mPress any key to continue...\033[0m")
        print("First, we'll generate a key pair for you. Your keys will be saved in private_key.pem and public_key.pem. \033[1mNEVER\033[0m share your private key with \033[1mANYONE\033[0m.")
        _wait_for_key("\n\033[3mPress any key to create a key pair...\033[0m")
        if Path("private_key.pem").is_file() or Path("public_key.pem").is_file():
            if Path("private_key.pem").is_file() and Path("public_key.pem").is_file():
                print("You already have a keypair. You're good to go!")
                _wait_for_key("\n\033[3mPress any key to continue...\033[0m")
                _clear_console()
            elif Path("public_key.pem").is_file():
                print("It seems you already have a public key saved. Since removing it could cause loss of data, I'll stop and let you choose how to continue.")
                _wait_for_key("\n\033[3mPress any key to continue...\033[0m")
                _clear_console()
                sys.exit(1)
            elif Path("private_key.pem").is_file():
                print("I found a private key already existing here. I'll let you choose how to continue.")
                _wait_for_key("\n\033[3mPress any key to continue...\033[0m")
                _clear_console()
                sys.exit(1)
        else:
            print("Creating your keys now... ", end='')
            new_private_key = ed25519.Ed25519PrivateKey.generate()
            new_public_key = new_private_key.public_key()
            with open("private_key.pem", "wb") as priv_file:
                priv_file.write(
                    new_private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                )
            with open("public_key.pem", "wb") as pub_file:
                pub_file.write(
                    new_public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                )
            print("Done!")
            _wait_for_key("\n\033[3mPress any key to continue...\033[0m")
            print("You're almost all set up to use cool62coin. Now, we'll send you to the interactive wallet, where you can type 'help' to learn the commands.")
            _wait_for_key("\n\033[3mPress any key to continue...\033[0m")
    print(f"interactive cool62coin wallet - node {args.node} (type 'help' for commands)")
    while True:
        try:
            line = input("C62> ").strip()
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
                    print("usage: send <receiver> <amount> [memo]")
                    continue
                args.receiver = parts[0]
                args.amount = parts[1]
                args.memo = " ".join(parts[2:]) if len(parts) > 2 else None
                args.key = DEFAULT_KEY
                cmd_send(args)
            else:
                print(f"unknown command '{cmd}' - try 'help'")
        except SystemExit:
            pass


def main():
    parser = argparse.ArgumentParser(description="blockchain wallet CLI (interactive by default)")
    parser.add_argument("--node", default=DEFAULT_NODE, help=f"local node API base URL (default {DEFAULT_NODE})")

    args = parser.parse_args()
    interactive(args)

if __name__ == "__main__":
    main()