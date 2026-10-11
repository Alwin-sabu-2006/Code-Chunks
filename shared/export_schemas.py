"""
Schema Exporter Script
======================
Generates shared/schema.json from the Pydantic models in shared/models.py.
Ensures non-Python members (frontend, contracts, documentation) have a single source of truth.
"""

import json
from pathlib import Path
from pydantic.json_schema import models_json_schema

from shared.models import (
    Finding,
    BenchmarkResult,
    VerificationResult,
    DecisionResult,
    Report,
    AgentEvent,
    McpCallLog,
    AnchorRecord,
    ScanStartRequest,
    ScanStartResponse,
    ScanStatusResponse,
    VerifyHashResponse,
)


def export_all_schemas():
    models = [
        (Finding, "validation"),
        (BenchmarkResult, "validation"),
        (VerificationResult, "validation"),
        (DecisionResult, "validation"),
        (Report, "validation"),
        (AgentEvent, "validation"),
        (McpCallLog, "validation"),
        (AnchorRecord, "validation"),
        (ScanStartRequest, "validation"),
        (ScanStartResponse, "validation"),
        (ScanStatusResponse, "validation"),
        (VerifyHashResponse, "validation"),
    ]

    _, top_level_schema = models_json_schema(models, title="Q-Chain Unified Schemas")

    output_path = Path(__file__).parent / "schema.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(top_level_schema, f, indent=2)

    print(f"Successfully exported schemas to {output_path}")


if __name__ == "__main__":
    export_all_schemas()
