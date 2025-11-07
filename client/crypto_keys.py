import json
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def load_private_key_from_hex(priv_hex: str):
    priv_hex = priv_hex.strip()
    if priv_hex.startswith("0x"):
        priv_hex = priv_hex[2:]
    priv_bytes = bytes.fromhex(priv_hex)
    if len(priv_bytes) == 64:
        priv_bytes = priv_bytes[:32]
    if len(priv_bytes) != 32:
        raise ValueError("Private key must be 32 bytes")
    return ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)

def derive_pubhex_from_private(private_key):
    pub = private_key.public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()

def sign_message_hex(private_key, message_obj):
    msg_bytes = json.dumps(message_obj, sort_keys=True, separators=(",", ":")).encode()
    return private_key.sign(msg_bytes).hex()
