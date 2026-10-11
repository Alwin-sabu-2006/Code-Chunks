"""VulnChain HTTP API (demo only, binds to localhost).

  POST /wallet            create a wallet (server-side custody, demo only), gets 100 coins
  POST /tx                {"wallet_id","recipient","amount"}  sign and queue a transaction
  POST /mine              put queued transactions into a new block
  GET  /chain             full chain
  GET  /verify            recompute hashes and re-verify every signature
  POST /tamper            {"block","tx","amount"}  alter stored data to test detection
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

from ledger import Chain, Transaction
from wallet import Wallet

chain = Chain()
wallets = {}
pending = []


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        if self.path == "/chain":
            self._send(200, {"blocks": chain.blocks, "balances": chain.balances})
        elif self.path == "/verify":
            ok, msg = chain.verify_chain()
            self._send(200, {"valid": ok, "detail": msg})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        try:
            body = self._body()
            if self.path == "/wallet":
                w = Wallet()
                wid = str(len(wallets) + 1)
                wallets[wid] = w
                chain.credit(w.address, 100)
                self._send(200, {"wallet_id": wid, "address": w.address})
            elif self.path == "/tx":
                w = wallets[body["wallet_id"]]
                queued = sum(1 for t in pending if t.sender == w.address)
                tx = Transaction(
                    sender_pub=w.public_bytes.hex(),
                    recipient=body["recipient"],
                    amount=int(body["amount"]),
                    nonce=chain.nonces.get(w.address, 0) + queued,
                )
                tx.sign(w)
                pending.append(tx)
                self._send(200, {"queued": len(pending), "signature_bytes": len(tx.signature) // 2})
            elif self.path == "/mine":
                chain.add_block(list(pending))
                pending.clear()
                self._send(200, {"height": len(chain.blocks)})
            elif self.path == "/tamper":
                chain.blocks[body["block"]]["txs"][body["tx"]]["amount"] = int(body["amount"])
                self._send(200, {"tampered": True})
            else:
                self._send(404, {"error": "not found"})
        except (KeyError, IndexError, ValueError) as e:
            self._send(400, {"error": str(e)})


if __name__ == "__main__":
    print("VulnChain demo API on http://127.0.0.1:8000")
    HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
