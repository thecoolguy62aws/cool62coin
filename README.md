# Cool62Coin

## Setup

### Windows/NT

1. Clone this repo onto your machine.
2. Install dependencies: `pip install requests flask cryptography pyopencl waitress`.
3. Put a copy of `tor.exe` in the root directory.
4. Place a known bootstrap onion in `peers.txt`.
5. Run `main.py` to start your node. On the first startup it will mine the genesis block. This will be nearly instant. Wait for some logs to start printing before continuing.

### Linux, Darwin, and other Unix-like kernels.

1. Clone this repo onto your machine.
2. Install dependancies: either `sudo apt install python3-pip python3-requests python3-flask python3-cryptography tor python3-pyopencl opencl-icd python3-waitress` or `pip install requests flask cryptography pyopencl waitress`.
3. Place a known bootstrap onion in `peers.txt`.
4. Run `main.py` to start your node. On the first startup it will mine the genesis block. This will be nearly instant. Wait for some logs to start printing before continuing. 

## Basic Usage

**`main.py` MUST be running for any of this to work!**

`send.py` is an interactive CLI that can be used to make transactions and check your balance. When you run it the first time, it will help you set up cool62coin.

## Advanced Usage (mining)

To mine Cool62Coin, you can run `miner.py`. This will run on your GPU if available, otherwise your CPU. If pending transactions are found, the miner will immediately start trying to mine the block. This helps to secure the network from 51% attacks, where attackers can overrule the entire network. As an extra bonus, there is even a chance for you to get a 100 coin reward if you successfully mine a block!
