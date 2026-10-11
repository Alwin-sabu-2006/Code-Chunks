"""End-to-end demo and ECDSA baseline numbers for Q-Chain to compare PQC against."""
import copy
import time

from ledger import Chain, Transaction
from node_identity import NodeIdentity, handshake
from wallet import Wallet


def baseline(n=200):
    w = Wallet()
    msg = b"q-chain baseline message"
    t0 = time.perf_counter()
    sigs = [w.sign(msg) for _ in range(n)]
    sign_ms = (time.perf_counter() - t0) / n * 1000
    from wallet import verify

    t0 = time.perf_counter()
    for s in sigs:
        verify(w.public_bytes, msg, s)
    verify_ms = (time.perf_counter() - t0) / n * 1000
    return {
        "algorithm": "ECDSA secp256k1 + SHA-256",
        "public_key_bytes": len(w.public_bytes),
        "signature_bytes_avg": round(sum(len(s) for s in sigs) / n, 1),
        "sign_ms": round(sign_ms, 3),
        "verify_ms": round(verify_ms, 3),
    }


def main():
    chain = Chain()
    alice, bob = Wallet(), Wallet()
    chain.credit(alice.address, 100)

    tx = Transaction(alice.public_bytes.hex(), bob.address, 25, nonce=0)
    tx.sign(alice)
    chain.add_block([tx])
    print("1. valid chain:", chain.verify_chain())

    # Tamper 1: change the amount only -> block hash no longer matches
    t1 = copy.deepcopy(chain)
    t1.blocks[1]["txs"][0]["amount"] = 99
    print("2. amount edited:", t1.verify_chain())

    # Tamper 2: edit the amount AND recompute the block hash -> signature check catches it
    from ledger import hash_block

    t2 = copy.deepcopy(chain)
    b = t2.blocks[1]
    b["txs"][0]["amount"] = 99
    b["hash"] = hash_block(b["index"], b["prev_hash"], b["txs"], b["timestamp"])
    print("3. amount edited + hash recomputed:", t2.verify_chain())

    print("4. node handshake (RSA + ECDH):", handshake(NodeIdentity("n1"), NodeIdentity("n2")))
    print("5. ECDSA baseline:", baseline())


if __name__ == "__main__":
    main()
