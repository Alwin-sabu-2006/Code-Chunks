"""
Multi-Agent Orchestrator
Coordinates the 5-stage assessment workflow:
Analysis -> Benchmark -> Verification -> Decision -> Reporting
"""

from typing import Optional
from backend.services.pipeline_coordinator import pipeline_coordinator


class AgentOrchestrator:
    """Coordinates execution across all specialized domain agents."""

    def __init__(self):
        self.coordinator = pipeline_coordinator

    async def run_assessment(self, target_path: Optional[str] = None, app_id: Optional[str] = None):
        scan_id = await self.coordinator.start_scan(target_path=target_path, sample_app_id=app_id)
        return scan_id

    def get_status(self, scan_id: str):
        return self.coordinator.get_scan_status(scan_id)

    def get_report(self, scan_id: str):
        return self.coordinator.get_report(scan_id)


orchestrator = AgentOrchestrator()
