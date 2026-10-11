"""
Sample App 2: Voting dApp Python Client
Demonstrates voter key management, ballot signing, and local verification.
"""

from eth_account import Account
from eth_account.messages import encode_defunct

class VoterClient:
    def __init__(self, private_key: str = None):
        if private_key:
            # Planted Pattern 3: eth_account key instantiation
            self.account = Account.from_key(private_key)
        else:
            # Planted Pattern 4: eth_account random key generation
            self.account = Account.create()

    @property
    def voter_address(self) -> str:
        return self.account.address

    def sign_ballot(self, proposal_id: int, vote_yes: bool, nonce: int) -> dict:
        # Planted Pattern 5: encode_defunct hash-and-sign framing
        message_text = f"Vote on Proposal {proposal_id}: {'YES' if vote_yes else 'NO'} [Nonce: {nonce}]"
        signable_message = encode_defunct(text=message_text)

        # Planted Pattern 6: eth_account message signing
        signed_message = self.account.sign_message(signable_message)

        return {
            "voter": self.voter_address,
            "proposal_id": proposal_id,
            "vote_yes": vote_yes,
            "nonce": nonce,
            "signature": signed_message.signature.hex(),
            "v": signed_message.v,
            "r": hex(signed_message.r),
            "s": hex(signed_message.s),
        }

    @staticmethod
    def verify_ballot(proposal_id: int, vote_yes: bool, nonce: int, signature_hex: str) -> str:
        message_text = f"Vote on Proposal {proposal_id}: {'YES' if vote_yes else 'NO'} [Nonce: {nonce}]"
        signable_message = encode_defunct(text=message_text)

        # Planted Pattern 7: eth_account recover_message
        recovered_address = Account.recover_message(signable_message, signature=bytes.fromhex(signature_hex))
        return recovered_address
