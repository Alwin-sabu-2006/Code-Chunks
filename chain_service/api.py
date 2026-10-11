import os
import json
import logging
from web3 import Web3
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any

# Assuming Hardhat local node for demo
RPC_URL = os.environ.get("RPC_URL", "http://127.0.0.1:8545")
w3 = Web3(Web3.HTTPProvider(RPC_URL))

# Load contract artifact (Wait for Member 3/Docker deployment)
DEPLOYMENTS_FILE = os.path.join(os.path.dirname(__file__), "..", "deployments", "ReportRegistry.json")
if os.path.exists(DEPLOYMENTS_FILE):
    with open(DEPLOYMENTS_FILE, "r") as f:
        deployment = json.load(f)
        CONTRACT_ADDRESS = deployment["address"]
        CONTRACT_ABI = deployment["abi"]
        contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
else:
    logging.warning("ReportRegistry.json not found. Deploy contract first!")
    contract = None

app = FastAPI(title="Q-Chain Anchoring Service")

class ReportAnchorRequest(BaseModel):
    report_hash: str
    
class VerifyResponse(BaseModel):
    anchored: bool
    report_hash: str
    submitter: str | None = None
    timestamp: int | None = None
    block_number: int | None = None
    status: str

@app.post("/anchor")
def anchor_report(req: ReportAnchorRequest):
    if not contract:
        raise HTTPException(status_code=500, detail="Contract not configured")
    
    # In a real environment, you'd use a private key to sign the TX. 
    # For local hardhat demo, we use the first unlocked account.
    accounts = w3.eth.accounts
    if not accounts:
        raise HTTPException(status_code=500, detail="No accounts available on RPC")
    
    sender = accounts[0]
    
    try:
        report_hash_bytes = w3.to_bytes(hexstr=req.report_hash)
        if len(report_hash_bytes) != 32:
            raise ValueError("Report hash must be exactly 32 bytes")
            
        tx_hash = contract.functions.anchor(report_hash_bytes).transact({'from': sender})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        return {
            "success": True,
            "report_hash": req.report_hash,
            "tx_hash": receipt.transactionHash.hex(),
            "block_number": receipt.blockNumber,
            "submitter": sender
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/verify/{report_hash}")
def verify_hash(report_hash: str):
    if not contract:
        raise HTTPException(status_code=500, detail="Contract not configured")
        
    try:
        report_hash_bytes = w3.to_bytes(hexstr=report_hash)
        record = contract.functions.getRecord(report_hash_bytes).call()
        # record: (submitter, timestamp, blockNumber, exists)
        submitter, timestamp, block_number, exists = record
        
        if exists:
            return VerifyResponse(
                anchored=True,
                report_hash=report_hash,
                submitter=submitter,
                timestamp=timestamp,
                block_number=block_number,
                status="MATCH"
            )
        else:
            return VerifyResponse(
                anchored=False,
                report_hash=report_hash,
                status="NOT_FOUND_OR_TAMPERED"
            )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
