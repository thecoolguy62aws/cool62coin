import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
from pathlib import Path
import sys

PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"

if Path(PRIVATE_KEY_FILE).is_file() or Path(PUBLIC_KEY_FILE).is_file():
    print("Keys already exist. If you delete them, you will lose all the coins stored on your addresss!")
    sys.exit(1)

print("Generating 2048-bit RSA keypair...")
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

with open(PRIVATE_KEY_FILE, "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

with open(PUBLIC_KEY_FILE, "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
print("Keys successfully generated and saved to file.")
