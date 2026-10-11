import copy
import unittest

from ledger import Chain, Transaction, hash_block
from node_identity import NodeIdentity, handshake
from wallet import Wallet


def make_chain():
    chain = Chain()
    a, b = Wallet(), Wallet()
    chain.credit(a.address, 100)
    tx = Transaction(a.public_bytes.hex(), b.address, 25, nonce=0)
    tx.sign(a)
    chain.add_block([tx])
    return chain, a, b


class VulnChainTests(unittest.TestCase):
    def test_valid_chain_verifies(self):
        chain, _, _ = make_chain()
        self.assertTrue(chain.verify_chain()[0])

    def test_wrong_key_signature_rejected(self):
        chain, a, b = make_chain()
        tx = Transaction(a.public_bytes.hex(), b.address, 5, nonce=1)
        tx.sign(Wallet())  # signed by someone else
        with self.assertRaises(ValueError):
            chain.add_block([tx])

    def test_amount_tamper_detected(self):
        chain, _, _ = make_chain()
        chain.blocks[1]["txs"][0]["amount"] = 99
        self.assertFalse(chain.verify_chain()[0])

    def test_tamper_with_rehash_caught_by_signature(self):
        chain, _, _ = make_chain()
        blk = chain.blocks[1]
        blk["txs"][0]["amount"] = 99
        blk["hash"] = hash_block(blk["index"], blk["prev_hash"], blk["txs"], blk["timestamp"])
        ok, detail = chain.verify_chain()
        self.assertFalse(ok)
        self.assertIn("signature", detail)

    def test_overspend_rejected(self):
        chain, a, b = make_chain()
        tx = Transaction(a.public_bytes.hex(), b.address, 10_000, nonce=1)
        tx.sign(a)
        with self.assertRaises(ValueError):
            chain.add_block([tx])

    def test_handshake(self):
        self.assertTrue(handshake(NodeIdentity("n1"), NodeIdentity("n2")))


if __name__ == "__main__":
    unittest.main()
