"""
PDF Report Generator Service
============================
Renders high-fidelity cryptographic migration assessment PDF reports.

Owner: Member 3 (Backend Engineer)
"""

import io
from typing import BinaryIO
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)

from shared.models import Report


def generate_pdf_report(report: Report) -> bytes:
    """Generates a binary PDF report for a given assessment."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0f172a"),
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#64748b"),
        leading=14,
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=14,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155"),
    )
    code_style = ParagraphStyle(
        "CodeStyle",
        parent=styles["Code"],
        fontSize=8,
        leading=10,
        fontName="Courier",
        textColor=colors.HexColor("#0284c7"),
    )

    elements = []

    # Title & Header
    elements.append(Paragraph("Q-Chain: Post-Quantum Migration Assessment", title_style))
    elements.append(Paragraph(f"Target App: <b>{report.target_app_name}</b> | Generated: {report.timestamp}", subtitle_style))
    if report.canonical_hash:
        elements.append(Paragraph(f"Canonical Report SHA-256 Anchor: <font color='#0284c7'>{report.canonical_hash}</font>", subtitle_style))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=12))

    # Executive Summary & Decision
    elements.append(Paragraph("Executive Summary & System One Decision", h2_style))
    summary_text = (
        f"<b>Overall Quantum Risk Score:</b> {report.decision.overall_risk_score:.1f}/100<br/>"
        f"<b>Recommended Algorithm:</b> <font color='#059669'><b>{report.decision.recommended_algorithm}</b></font><br/>"
        f"<b>Decision Latency:</b> {report.decision.decision_latency_ms:.2f} ms<br/>"
        f"<b>Rationale:</b> {report.decision.recommendation_rationale}"
    )
    elements.append(Paragraph(summary_text, body_style))
    elements.append(Spacer(1, 12))

    # Vulnerability Findings Table
    elements.append(Paragraph(f"Cryptographic Vulnerability Findings ({len(report.findings)} detected)", h2_style))
    if report.findings:
        findings_data = [["ID", "File & Line", "Primitive", "Risk", "Replacement"]]
        for f in report.findings:
            findings_data.append([
                f.id,
                f"{f.file}:{f.line}",
                f.algorithm,
                f.quantum_risk.value,
                f.suggested_replacement or "NIST PQC",
            ])
        t_findings = Table(findings_data, colWidths=[65, 150, 130, 65, 120])
        t_findings.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ]))
        elements.append(t_findings)
    else:
        elements.append(Paragraph("No classical cryptographic vulnerabilities detected.", body_style))

    elements.append(Spacer(1, 14))

    # PQC Benchmarks Table
    elements.append(Paragraph("NIST PQC vs Classical Baseline Benchmarks", h2_style))
    if report.benchmarks:
        bench_data = [["Algorithm", "Category", "Pubkey (B)", "Sig (B)", "Sign (µs)", "Verify (µs)", "Gas Est."]]
        for b in report.benchmarks:
            bench_data.append([
                b.algorithm,
                b.category.value,
                str(b.public_key_size_bytes),
                str(b.signature_size_bytes),
                f"{b.sign_metrics.mean_us:.1f}",
                f"{b.verify_metrics.mean_us:.1f}",
                str(b.estimated_onchain_gas or "N/A"),
            ])
        t_bench = Table(bench_data, colWidths=[130, 75, 65, 65, 65, 65, 65])
        t_bench.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ]))
        elements.append(t_bench)

    elements.append(Spacer(1, 14))

    # Scope & Disclaimer
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceBefore=10, spaceAfter=8))
    disclaimer = (
        "<b>Scope Statement:</b> Q-Chain assesses and verifies migration readiness. It does not claim that off-chain "
        "PQC signatures make existing on-chain transaction authorization quantum-safe, and the anchoring transaction itself "
        "relies on the host chain's classical signatures."
    )
    elements.append(Paragraph(disclaimer, subtitle_style))

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()
