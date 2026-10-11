"""
Entrypoint for MCP Crypto Test Server
"""
from mcp_servers.crypto_test.server import server, main, run_tamper_tests, verify_signature

__all__ = ["server", "main", "run_tamper_tests", "verify_signature"]

if __name__ == "__main__":
    main()
