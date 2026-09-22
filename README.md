# Cool62Coin

## Setup

### Windows/NT

1. Clone this repo onto your machine.
2. Install dependancies: `pip install requests flask cryptography pyopencl`.
3. Move `config.py` in `config_example/` to the root directory.
4. Put a copy of `tor.exe` in the root directory.
5. Run `gen_keys.py` to generate your wallet address.
6. Place a known bootstrap onion in `peers.txt`.
7. Run `main.py` to start your node. On the first startup it will mine the genesis block. This will take a while. Wait for some logs to start printing before continuing. 

### Linux, Darwin, and other Unix-like kernals.

1. Clone this repo onto your machine.
2. Install dependancies: either `sudo apt install python3-pip python3-requests python3-flask python3-cryptography tor python3-pyopencl opencl-icd` or `pip install requests flask cryptography pyopencl`.
3. Move `config.py` in `config_example/` to the root directory.
4. Change `TOR_BIN = BASE_DIR / "tor.exe"` to `TOR_BIN = "/usr/bin/tor"` in `config.py` (your copy in the root directory).
5. Run `gen_keys.py` to generate your wallet address.
6. Place a known bootstrap onion in `peers.txt`.
7. Run `main.py` to start your node. On the first startup it will mine the genesis block. This will take a while. Wait for some logs to start printing before continuing. 

## Basic Usage

**`main.py` MUST be running for any of this to work!**

`send.py` is an interactive CLI that can be used to make transactions and check your balance.

## Advanced Usage (mining)

To mine Cool62Coin, you can run `miner.py`. This will run on your GPU if avalible, otherwise your CPU. If pending transactions are found, the miner will immediately start trying to mine the block. This helps to secure the network from 51% attacks, where attackers can overrule the entire netwrok. As an extra bonus, there is even a chance for you to get a 100 coin reward if you successfully mine a block!
