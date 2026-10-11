"""Toy ledger: every transaction carries the sender's raw public key and an
ECDSA signature. INTENTIONALLY QUANTUM-VULNERABLE (demo target for Q-Chain)."""
import hashlib
import json
import time
from dataclasses import asdict, dataclass

from wallet import Wallet, address_of, verify


@dataclass
class Transaction:
    # FINDING 3: the raw public key is published with every transaction, so an
    # attacker with a quantum computer can derive the private key from chain data.
    sender_pub: str
    recipient: str
    amount: int
    nonce: int
    signature: str = ""

    @property
    def sender(self) -> str:
        return address_of(bytes.fromhex(self.sender_pub))

    def payload(self) -> bytes:
        body = {
            "sender_pub": self.sender_pub,
            "recipient": self.recipient,
            "amount": self.amount,
            "nonce": self.nonce,
        }
        return json.dumps(body, sort_keys=True).encode()

    def sign(self, wallet: Wallet) -> None:
        self.signature = wallet.sign(self.payload()).hex()

    def is_valid(self) -> bool:
        if not self.signature:
            return False
        return verify(
            bytes.fromhex(self.sender_pub),
            self.payload(),
            bytes.fromhex(self.signature),
        )


def hash_block(index, prev_hash, txs, timestamp) -> str:
    # DECOY (not quantum-vulnerable): SHA-256 hash chaining.
    raw = json.dumps(
        {"index": index, "prev_hash": prev_hash, "txs": txs, "timestamp": timestamp},
        sort_keys=True,
    ).encode()
    return hashlib.sha256(raw).hexdigest()


class Chain:
    def __init__(self):
        self.blocks = []
        self.balances = {}
        self.nonces = {}
        self._append([], 0.0)  # genesis block

    def _append(self, txs, timestamp=None):
        ts = time.time() if timestamp is None else timestamp
        prev = self.blocks[-1]["hash"] if self.blocks else "0" * 64
        idx = len(self.blocks)
        tx_dicts = [asdict(t) for t in txs]
        self.blocks.append(
            {
                "index": idx,
                "prev_hash": prev,
                "txs": tx_dicts,
                "timestamp": ts,
                "hash": hash_block(idx, prev, tx_dicts, ts),
            }
        )

    def credit(self, address: str, amount: int) -> None:
        self.balances[address] = self.balances.get(address, 0) + amount

    def add_block(self, txs) -> None:
        balances = dict(self.balances)
        nonces = dict(self.nonces)
        for tx in txs:
            if not tx.is_valid():
                raise ValueError("invalid signature")
            if tx.nonce != nonces.get(tx.sender, 0):
                raise ValueError("bad nonce")
            if balances.get(tx.sender, 0) < tx.amount:
                raise ValueError("insufficient funds")
            balances[tx.sender] -= tx.amount
            balances[tx.recipient] = balances.get(tx.recipient, 0) + tx.amount
            nonces[tx.sender] = tx.nonce + 1
        self.balances, self.nonces = balances, nonces
        self._append(txs)

    def verify_chain(self):
        """Recompute every block hash and re-verify every transaction signature."""
        for i, b in enumerate(self.blocks):
            if b["hash"] != hash_block(b["index"], b["prev_hash"], b["txs"], b["timestamp"]):
                return False, f"block {i}: hash mismatch"
            if i > 0 and b["prev_hash"] != self.blocks[i - 1]["hash"]:
                return False, f"block {i}: broken link to previous block"
            for t in b["txs"]:
                if not Transaction(**t).is_valid():
                    return False, f"block {i}: invalid transaction signature"
        return True, "ok"
