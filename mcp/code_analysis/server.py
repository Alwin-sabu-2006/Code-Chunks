"""
Entrypoint for MCP Code Analysis Server
Delegates to mcp_servers.code_analysis.server
"""
from mcp_servers.code_analysis.server import (
    server,
    main,
    scan_directory,
    scan_file,
    list_detection_rules,
    set_allowed_root,
)

__all__ = [
    "server",
    "main",
    "scan_directory",
    "scan_file",
    "list_detection_rules",
    "set_allowed_root",
]

if __name__ == "__main__":
    main()
