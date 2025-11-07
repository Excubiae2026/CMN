import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from typing import Union, Tuple

def load_private_key_from_hex(priv_hex: str) -> ed25519.Ed25519PrivateKey:
    """
    Load an Ed25519 private key from hex string.
    Accepts 64-character hex (32 bytes) or 128-character hex (64 bytes, trims to 32).
    """
    priv_hex = priv_hex.strip().lower()
    if priv_hex.startswith("0x"):
        priv_hex = priv_hex[2:]
    priv_bytes = bytes.fromhex(priv_hex)
    if len(priv_bytes) == 64:
        priv_bytes = priv_bytes[:32]
    if len(priv_bytes) != 32:
        raise ValueError("Private key must be 32 bytes (hex length 64).")
    return ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)

def derive_pubhex_from_private(private_key: ed25519.Ed25519PrivateKey) -> str:
    """
    Derive the hex representation of the Ed25519 public key from a private key.
    """
    pub = private_key.public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()

def sign_message_hex(private_key: ed25519.Ed25519PrivateKey, message_obj: Union[dict, str]) -> str:
    """
    Sign a JSON-serializable object or string using Ed25519 and return the hex signature.
    """
    if isinstance(message_obj, str):
        msg_bytes = message_obj.encode()
    else:
        msg_bytes = json.dumps(message_obj, sort_keys=True, separators=(",", ":")).encode()
    return private_key.sign(msg_bytes).hex()

def verify_message_hex(public_hex: str, message_obj: Union[dict, str], signature_hex: str) -> bool:
    """
    Verify an Ed25519 signature for a given message and public key (both in hex).
    Returns True if signature is valid, False otherwise.
    """
    pub_bytes = bytes.fromhex(public_hex)
    pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)

    if isinstance(message_obj, str):
        msg_bytes = message_obj.encode()
    else:
        msg_bytes = json.dumps(message_obj, sort_keys=True, separators=(",", ":")).encode()

    try:
        pub_key.verify(bytes.fromhex(signature_hex), msg_bytes)
        return True
    except InvalidSignature:
        return False

def derive_eth_key_from_ed25519(priv_hex: str) -> Tuple[str, str]:
    """
    Derive a deterministic Ethereum private key and address from an Ed25519 private key hex.
    Returns (eth_private_hex, eth_address).
    """
    from eth_account import Account
    priv_hex = priv_hex.strip().replace("0x", "")
    priv_bytes = bytes.fromhex(priv_hex)
    if len(priv_bytes) > 32:
        priv_bytes = priv_bytes[:32]

    # SHA256 hash of Ed25519 bytes to use as Ethereum private key
    eth_priv_bytes = hashlib.sha256(priv_bytes).digest()
    acct = Account.from_key(eth_priv_bytes)
    return eth_priv_bytes.hex(), acct.address

