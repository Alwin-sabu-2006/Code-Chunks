"""
MCP Server: Blockchain Anchoring & Registry
===========================================
Model Context Protocol tools for smart contract anchoring on Anvil/Hardhat/Sepolia.

Owner: Member 3 & Member 4
"""

import json
import time
import uuid
from typing import Dict, Any
from mcp.server.mcpserver import MCPServer

from shared.models import AnchorRecord, McpCallLog
from shared.crypto_utils import verify_canonical_integrity
from backend.services.anchoring_service import anchoring_service

server = MCPServer("qchain-blockchain")


@server.tool()
def anchor_report_hash(report_hash: str, network: str = "anvil") -> str:
    """
    Submits a canonical report hash to the ReportRegistry smart contract.
    
    Args:
        report_hash: 0x-prefixed SHA-256 or Keccak-256 hash string.
        network: Target blockchain network ('anvil', 'hardhat', 'sepolia').
        
    Returns:
        JSON string containing the AnchorRecord transaction receipt.
    """
    t0 = time.perf_counter()
    record = anchoring_service.anchor_hash(report_hash=report_hash, network=network)
    duration_ms = (time.perf_counter() - t0) * 1000.0

    call_log = McpCallLog(
        call_id=f"CALL-{uuid.uuid4().hex[:8]}",
        server_name="blockchain",
        tool_name="anchor_report_hash",
        arguments={"report_hash": report_hash, "network": network},
        result_summary=f"Report hash {report_hash[:16]}... anchored on {network}. Tx: {record.tx_hash[:16]}...",
        duration_ms=round(duration_ms, 2),
        status="success",
    )

    return json.dumps({
        "record": record.model_dump(mode="json"),
        "call_log": call_log.model_dump(mode="json"),
    }, indent=2)


@server.tool()
def get_anchor_record(report_hash: str) -> str:
    """
    Queries ReportRegistry smart contract state for an existing anchor record.
    """
    record = anchoring_service.get_anchor_record(report_hash)
    if record:
        return json.dumps({"status": "found", "record": record.model_dump(mode="json")}, indent=2)
    return json.dumps({"status": "not_found", "report_hash": report_hash}, indent=2)


@server.tool()
def verify_document_integrity(report_hash: str, canonical_json: str) -> str:
    """
    Demonstrates live tamper detection by recalculating hash of canonical_json
    and matching against the registered blockchain hash.
    """
    res = anchoring_service.verify_report(report_hash=report_hash, canonical_json=canonical_json)
    return json.dumps(res.model_dump(mode="json"), indent=2)


def main():
    server.run()


if __name__ == "__main__":
    main()
