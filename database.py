"""
Q-Chain Database Manager
Stores and retrieves scan histories and security audits in SQLite.
"""
import sqlite3
import json
import uuid
import datetime
from config import DATABASE_PATH

def get_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            scan_type TEXT NOT NULL,
            target_name TEXT NOT NULL,
            summary TEXT,
            risk_score INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'INFORMATIONAL',
            findings_count INTEGER DEFAULT 0,
            raw_input TEXT,
            report_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_scan_id ON scans(scan_id);
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_scan_type ON scans(scan_type);
    """)
    conn.commit()
    conn.close()

def save_scan(scan_type: str, target_name: str, risk_score: int, risk_level: str, findings: list, raw_input: str, summary: str = None) -> str:
    conn = get_connection()
    cursor = conn.cursor()
    scan_id = f"QC-{datetime.datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    
    findings_count = len(findings)
    report_data = {
        "scan_id": scan_id,
        "scan_type": scan_type,
        "target_name": target_name,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "summary": summary or f"Completed {scan_type} security analysis with {findings_count} finding(s).",
        "findings_count": findings_count,
        "findings": findings,
        "created_at": datetime.datetime.now().isoformat()
    }

    cursor.execute("""
        INSERT INTO scans (scan_id, scan_type, target_name, summary, risk_score, risk_level, findings_count, raw_input, report_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        scan_type,
        target_name,
        report_data["summary"],
        risk_score,
        risk_level,
        findings_count,
        raw_input,
        json.dumps(report_data)
    ))
    conn.commit()
    conn.close()
    return scan_id

def get_scan(scan_id: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    data = dict(row)
    data["report"] = json.loads(data["report_json"])
    return data

def list_scans(limit=50, offset=0, scan_type=None):
    conn = get_connection()
    cursor = conn.cursor()
    if scan_type:
        cursor.execute("SELECT id, scan_id, scan_type, target_name, summary, risk_score, risk_level, findings_count, created_at FROM scans WHERE scan_type = ? ORDER BY id DESC LIMIT ? OFFSET ?", (scan_type, limit, offset))
    else:
        cursor.execute("SELECT id, scan_id, scan_type, target_name, summary, risk_score, risk_level, findings_count, created_at FROM scans ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_stats():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as total FROM scans")
    total_scans = cursor.fetchone()["total"]
    
    cursor.execute("SELECT COUNT(*) as cnt FROM scans WHERE scan_type = 'TRANSACTION'")
    tx_scans = cursor.fetchone()["cnt"]

    cursor.execute("SELECT COUNT(*) as cnt FROM scans WHERE scan_type = 'SOLIDITY_CONTRACT'")
    contract_scans = cursor.fetchone()["cnt"]

    cursor.execute("SELECT COUNT(*) as cnt FROM scans WHERE risk_level IN ('CRITICAL', 'HIGH')")
    high_risk_scans = cursor.fetchone()["cnt"]

    conn.close()
    return {
        "total_scans": total_scans,
        "tx_scans": tx_scans,
        "contract_scans": contract_scans,
        "high_risk_scans": high_risk_scans
    }
