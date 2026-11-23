# SPDX-FileCopyrightText: © 2026 thecoolguy62aws
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Roll back a saved Blockchain pickle by removing its last N blocks.

Stop main.py and miner.py before running this. Peers holding a longer valid
chain can still re-sync the removed blocks afterwards.
"""

import argparse
import pickle
import shutil
from datetime import datetime, timezone
from pathlib import Path

from core import Blockchain


def inspect(path):
    with path.open("rb") as handle:
        chain = pickle.load(handle)
    if not isinstance(chain, Blockchain):
        raise ValueError(f"{path} is not a Blockchain pickle")
    blocks = getattr(chain, "chain", None)
    if not isinstance(blocks, list) or not blocks:
        raise ValueError(f"{path} contains no blocks")
    chain.chain_file = path
    return chain


def confirm(prompt):
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def main():
    parser = argparse.ArgumentParser(
        description="remove the last N blocks from a saved blockchain")
    parser.add_argument("--file", type=Path, default=Path("blockchain.pkl"),
                        help="chain pickle to trim (default blockchain.pkl)")
    parser.add_argument("--blocks", type=int, default=5,
                        help="number of tip blocks to remove (default 5)")
    parser.add_argument("--yes", action="store_true",
                        help="do not ask for confirmation")
    parser.add_argument("--dry-run", action="store_true",
                        help="show what would be removed without writing")
    parser.add_argument("--no-backup", action="store_true",
                        help="do not create a timestamped .bak copy")
    args = parser.parse_args()

    if args.blocks < 1:
        parser.error("--blocks must be at least 1")
    if not args.file.exists():
        parser.error(f"{args.file} does not exist")

    chain = inspect(args.file)
    before = len(chain.chain)
    if before <= args.blocks:
        parser.error(f"chain has {before} blocks; cannot remove {args.blocks}")
    if not chain.is_chain_valid():
        parser.error("stored chain is invalid; refusing to trim it")

    new_height = before - args.blocks
    removed = chain.chain[-args.blocks:]
    print(f"file:     {args.file}")
    print(f"height:   {before} -> {new_height}")
    print("removing:")
    for block in removed:
        print(f"  #{block.index:<7} {block.hash}")
    print(f"new tip:  {chain.chain[new_height - 1].hash}")
    if args.dry_run:
        print("dry run; nothing written")
        return

    if not args.yes and not confirm("trim this chain? [y/N] "):
        print("cancelled")
        return

    backup = None
    if not args.no_backup:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = args.file.with_name(f"{args.file.name}.bak.{stamp}")
        shutil.copy2(args.file, backup)
        print(f"backup:   {backup}")

    chain.chain = chain.chain[:new_height]
    chain.unconfirmed_transactions = []
    chain.pending_debits = {}
    if not chain.is_chain_valid():
        parser.error("truncated chain failed validation; nothing was saved")

    try:
        chain.save(args.file)
        saved = inspect(args.file)
        if len(saved.chain) != new_height or \
                saved.chain[-1].hash != chain.chain[-1].hash:
            raise RuntimeError("saved chain does not match the trimmed chain")
    except Exception as exc:
        if backup is not None:
            shutil.copy2(backup, args.file)
            raise RuntimeError(f"trim failed, restored {backup}: {exc}") from exc
        raise RuntimeError(f"trim failed and no backup was made: {exc}") from exc

    print(f"trimmed:  {len(removed)} block(s) removed; mempool cleared")


if __name__ == "__main__":
    main()
