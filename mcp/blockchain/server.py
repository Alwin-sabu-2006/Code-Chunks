"""
Entrypoint for MCP Blockchain Server
"""
from mcp_servers.blockchain.server import server, main, anchor_report_hash, get_anchor_record, verify_document_integrity

__all__ = ["server", "main", "anchor_report_hash", "get_anchor_record", "verify_document_integrity"]

if __name__ == "__main__":
    main()
