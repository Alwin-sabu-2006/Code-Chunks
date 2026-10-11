"""
Q-Chain Backend Launcher Script
===============================
Starts the FastAPI application and displays active endpoints & WebSocket feed.
"""

import sys
import uvicorn

BANNER = """
========================================================================
   ____           ____ _           _       
  / __ \         / ___| |__   __ _(_)_ __  
 / / _` | _____ | |   | '_ \ / _` | | '_ \ 
| | (_| ||_____|| |___| | | | (_| | | | | |
 \ \__,_|        \____|_| |_|\__,_|_|_| |_|
  \____/  AI-Assisted Quantum-Safe Migration Platform

  Role: Member 3 (Backend & MCP Engineer)
========================================================================
 [REST API]      http://localhost:8000
 [Swagger Docs]  http://localhost:8000/docs
 [WebSocket WS]  ws://localhost:8000/ws/events
 [Health Check]  http://localhost:8000/health
========================================================================
"""


def main():
    print(BANNER)
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=["backend/routers", "backend/services", "backend/pqc_testing", "crypto", "scanner", "mcp_servers"],
        reload_excludes=["*.zip", "*.tar.gz", "*.tar", "*.tgz", "*.json", "*uploads*", "*reports*", "*cache*", "*artifacts*", "*__pycache__*"],
    )


if __name__ == "__main__":
    main()
