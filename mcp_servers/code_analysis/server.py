"""
MCP Server: Code Analysis
"""
import json
from mcp.server.mcpserver import MCPServer
from mcp_servers.code_analysis.scanner import CodeScanner
from mcp_servers.code_analysis.rules import RULES

server = MCPServer("qchain-code-analysis")
_scanner = CodeScanner(allowed_root_path=".")


def set_allowed_root(root_path: str):
    global _scanner
    _scanner = CodeScanner(allowed_root_path=root_path)


@server.tool()
def scan_directory(directory_path: str) -> str:
    findings, duration_ms, call_log = _scanner.scan_directory(directory_path)
    result = {
        "status": call_log.status,
        "directory": directory_path,
        "findings_count": len(findings),
        "duration_ms": duration_ms,
        "findings": [f.model_dump(mode="json") for f in findings],
        "call_log": call_log.model_dump(mode="json"),
    }
    return json.dumps(result, indent=2)


@server.tool()
def scan_file(file_path: str) -> str:
    findings, duration_ms = _scanner.scan_file(file_path)
    result = {
        "status": "success",
        "file": file_path,
        "findings_count": len(findings),
        "duration_ms": duration_ms,
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    return json.dumps(result, indent=2)


@server.tool()
def list_detection_rules() -> str:
    summary = [
        {
            "id": r["id"],
            "name": r["name"],
            "algorithm": r["algorithm"],
            "quantum_risk": r["quantum_risk"].value,
            "extensions": r["file_extensions"],
        }
        for r in RULES
    ]
    return json.dumps(summary, indent=2)


def main():
    server.run()


if __name__ == "__main__":
    main()
