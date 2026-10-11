"""
Token Wallet Deployment Script
Planted Vulnerability #4: Classical python eth_account message signing
"""
from eth_account import Account
from eth_account.messages import encode_defunct


def generate_admin_signature(private_key_hex: str, payload: str):
    # VULNERABILITY #4: Python Account.sign_message over secp256k1
    account = Account.from_key(private_key_hex)
    msg = encode_defunct(text=payload)
    signed = Account.sign_message(msg, private_key=private_key_hex)
    return {
        "address": account.address,
        "signature": signed.signature.hex()
    }
