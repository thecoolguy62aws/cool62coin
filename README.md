# cool62coin

## About

cool62coin is a decentralized proof-of-work cryptocurrency that uses SHA-256.

## Setup

### Windows/NT

1. Clone this repo onto your machine.
2. Install dependencies: `pip install requests PySocks flask cryptography pyopencl waitress mnemonic`.
3. Put a copy of `tor.exe` in the root directory. You can get this file from [the official site](https://download.torproject.org/tor/).
4. Place a known bootstrap onion in `peers.txt`. A good one to start is `7gmhrcj6agxizusdua6pceus3izrbcqb2dkloow2c3vzo5adqqruxcad.onion`.

### Linux, Darwin, and other Unix-like kernels.

1. Clone this repo onto your machine.
2. Install dependencies: either `sudo apt install python3-pip python3-requests python3-socks python3-flask python3-cryptography tor python3-pyopencl opencl-icd python3-waitress python3-mnemonic` or `pip install requests PySocks flask cryptography pyopencl waitress mnemonic`.
3. Place a known bootstrap onion in `peers.txt`. A good one to start is `7gmhrcj6agxizusdua6pceus3izrbcqb2dkloow2c3vzo5adqqruxcad.onion`.

## Basic Usage

`send.py` is an interactive CLI that can be used to make transactions and check your balance. When you run it the first time, it will help you set up cool62coin.

Running a node is **not** required to use `send.py`, although it is strongly encouraged for multiple reasons. If you run a local node, you help keep the network more secure and decentralized, while gaining increased privacy. On the other hand, using a remote node (default) can be better because the blockchain is not downloaded to your computer, saving storage space.

To use a remote node, change nothing. To use a local node, run `main.py` in a separate terminal window from `send.py`. **Note**: Restarting `send.py` is required after starting your local node. 

## Addresses

cool62coin supports two address encodings for the same Ed25519 key:

- **Hex** (legacy): the original `1...` address format.
- **Bech32m**: a `c62...` address using the BIP350 checksum.

Both forms refer to the same account, so funds are shared: any address can receive or spend using either encoding. Wallets show Bech32m once the connected node reaches the activation height; before that they show the legacy hex form so addresses remain usable (`address bech32` forces the BIP-350 form). The network accepts Bech32 addresses starting at block height 1500; before that height only hex addresses are valid.

## Hard fork at block 8000

Block **8000** activates the atomic-amount fork. Every node must upgrade before
the network reaches that height. Nodes on the old release advertise a different
`network_id`, so upgraded and old nodes refuse to sync with each other instead
of silently splitting later.

What changes at block 8000:

- **Amounts are integer atoms.** One coin is `100,000,000` atoms, so amounts
  have 8 decimal places. Balances reported by `/balance` include both
  `balance` (coins, for compatibility) and `balance_atoms` (the exact value).
- **Transactions are versioned.** Version 1 stored coin amounts and is still
  accepted before block 8000. Version 2 stores an integer number of atoms,
  includes `"version": 2` in the signed payload, and is required at and after
  block 8000. Historical version 1 signatures are still verified using their
  original coin amounts.
- **The reward and fee are configured in atoms.**
  `REWARD = 10_000_000_000` is 100 coins and
  `TRANSACTION_FEE = 100_000_000` is 1 coin.
- **Zero-amount transactions remain valid**, so on-chain mail continues to
  work.
- **Consensus hardening:** chain adoption is anchored to the genesis block,
  duplicate transaction IDs are rejected, malformed blocks and transactions
  are rejected without raising, block timestamps must beat the median of the
  previous 11 blocks and stay within 2 hours of wall time, and miners must use
  a valid address once the fork is active.

Run `python test_hardfork.py` to exercise the activation boundary, duplicate
transactions, alternate genesis chains, malformed input, timestamp rules, and
replay of the existing chain.

**Do not downgrade a node after it has saved the upgraded chain format.** Older
releases cannot load it and will start over from genesis.

## Advanced Usage (mining)

**A local node is required to mine; before doing anything below, make sure `main.py` is running in another window.**

To mine cool62coin, you can run `miner.py`. This will run on your GPU if available, otherwise your CPU. If pending transactions are found, the miner will immediately start trying to mine the block. This helps to secure the network from 51% attacks, where attackers can overrule the entire network. As an incentive, you will receive a 100 coin reward if you successfully mine a block!
