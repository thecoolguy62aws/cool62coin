# cool62coin

## Setup

### Windows/NT

1. Clone this repo onto your machine.
2. Install dependancies: `pip install requests flask cryptography pyopencl waitress mnemonic`.
3. Put a copy of `tor.exe` in the root directory.
4. Place a known bootstrap onion in `peers.txt`. A good one to start is `7gmhrcj6agxizusdua6pceus3izrbcqb2dkloow2c3vzo5adqqruxcad.onion`.

### Linux, Darwin, and other Unix-like kernels.

1. Clone this repo onto your machine.
2. Install dependancies: either `sudo apt install python3-pip python3-requests python3-flask python3-cryptography tor python3-pyopencl opencl-icd python3-waitress python3-mnemonic` or `pip install requests flask cryptography pyopencl waitress mnemonic`.
3. Place a known bootstrap onion in `peers.txt`. A good one to start is `7gmhrcj6agxizusdua6pceus3izrbcqb2dkloow2c3vzo5adqqruxcad.onion`.

## Basic Usage

`send.py` is an interactive CLI that can be used to make transactions and check your balance. When you run it the first time, it will help you set up cool62coin.

Running a node is **not** required to use `send.py`, although it is strongly encouraged for multiple reasons. If you run a local node, you help keep the network more secure and decentralized, while gaining increased privacy. On the other hand, using a remote node (default) can be better because the blockchain is not downloaded to your computer, saving storage space.

To use a remote node, change nothing. To use a local node, run `main.py` in a seperate terminal window from `send.py`. **Note**: Restarting `send.py` is required after starting your local node. 

## Advanced Usage (mining)

**A local node is required to mine; before doing anything below, make sure `main.py` is running in another window.**

To mine cool62coin, you can run `miner.py`. This will run on your GPU if available, otherwise your CPU. If pending transactions are found, the miner will immediately start trying to mine the block. This helps to secure the network from 51% attacks, where attackers can overrule the entire network. As an incentive, you will receive a 100 coin reward if you successfully mine a block!
