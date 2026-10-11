"""
Q-Chain Multi-Agent System
==========================
Coordinates the 5 specialized domain agents for post-quantum migration:
1. AnalysisAgent (Codebase scanner & AST pattern recognition)
2. BenchmarkAgent (liboqs & NIST PQC performance characterization)
3. VerificationAgent (4-scenario cryptographic tamper resistance testing)
4. DecisionAgent (System One risk triage & PQC algorithm recommendation)
5. ReportAgent (Canonical deterministic hashing & on-chain anchoring)
"""

from backend.services.pipeline_coordinator import PipelineCoordinator, pipeline_coordinator

__all__ = [
    "PipelineCoordinator",
    "pipeline_coordinator",
]
