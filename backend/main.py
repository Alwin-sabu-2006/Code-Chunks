"""
Q-Chain Backend Application
===========================
Main FastAPI application entrypoint.
Coordinates Multi-Agent Orchestrator, MCP Servers, and Frontend WebSocket Stream.
Includes comprehensive input validation and global exception handlers.

Owner: Member 3 (Backend and MCP Engineer)
"""

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from backend.routers import health, scan, websocket, anchor, report
from backend.pqc_testing import pqc_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("qchain.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing Q-Chain Backend Service...")
    logger.info("Local edge runtime ready. All operations executed in-process/locally.")
    yield
    logger.info("Shutting down Q-Chain Backend Service.")


app = FastAPI(
    title="Q-Chain API",
    description="AI-Assisted Quantum-Safe Migration Assessment and Verification Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for Next.js / React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Global Exception Handlers (Security & Robustness)
# ============================================================================

@app.exception_handler(PermissionError)
async def permission_error_handler(request: Request, exc: PermissionError):
    logger.warning(f"Permission Sandbox Violation at {request.url.path}: {exc}")
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={
            "error": "SecuritySandboxViolation",
            "detail": str(exc),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": "InvalidInputError",
            "detail": str(exc),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


@app.exception_handler(FileNotFoundError)
async def not_found_error_handler(request: Request, exc: FileNotFoundError):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "error": "ResourceNotFoundError",
            "detail": str(exc),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


# Register route modules
app.include_router(health.router)
app.include_router(scan.router)
app.include_router(websocket.router)
app.include_router(anchor.router)
app.include_router(anchor.root_anchor_router)
app.include_router(report.router)
app.include_router(pqc_router)

# Mount compiled React/Vite frontend if available
import os
from fastapi.staticfiles import StaticFiles

frontend_dist = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.exists(frontend_dist):
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")
elif os.path.exists("frontend/dist"):
    app.mount("/", StaticFiles(directory="frontend/dist", html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=["backend/routers", "backend/services", "backend/pqc_testing", "crypto", "scanner", "mcp_servers"],
        reload_excludes=["*.zip", "*.tar.gz", "*.tar", "*.tgz", "*.json", "*uploads*", "*reports*", "*cache*", "*artifacts*", "*__pycache__*"],
    )
