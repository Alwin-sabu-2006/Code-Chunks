"""
Health & System Status Router
"""

from fastapi import APIRouter
from typing import Dict, Any

router = APIRouter(tags=["Health"])


@router.get("/health")
@router.get("/api/health")
def health_check() -> Dict[str, str]:
    """Basic service health check."""
    return {"status": "ok", "service": "qchain-backend", "version": "1.0.0"}


@router.get("/api/system/status")
def system_status() -> Dict[str, Any]:
    """Detailed platform status for dashboard header badges."""
    return {
        "status": "operational",
        "mode": "local_edge",
        "runs_locally": True,
        "supported_pqc_algorithms": [
            "ML-DSA-44",
            "ML-DSA-65",
            "ML-DSA-87",
            "Falcon-512",
            "Falcon-1024",
            "SLH-DSA-SHAKE-128s"
        ],
        "mcp_servers": {
            "code-analysis": "online",
            "crypto-test": "online",
            "benchmark": "online",
            "blockchain": "online"
        },
        "blockchain_network": "anvil"
    }
