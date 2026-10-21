from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from mnemonic import Mnemonic

with open("private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

private_bytes = private_key.private_bytes_raw()

mnemo = Mnemonic("english")

mnemonic_phrase = mnemo.to_mnemonic(private_bytes)

confirm = input("type 'showmemyseedphrase' without the quotes to show your seed phrase>")

if confirm == "showmemyseedphrase":
    print(mnemonic_phrase)
