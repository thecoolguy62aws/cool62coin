from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pathlib import Path
import sys

if Path("private_key.pem").is_file() or Path("public_key.pem").is_file():
    print("Keys already exist. If you delete them, you will lose all the coins stored on your addresss!")
    sys.exit(1)

private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

with open("private_key.pem", "wb") as priv_file:
    priv_file.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

with open("public_key.pem", "wb") as pub_file:
    pub_file.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("Keys successfully generated and saved to file.")
