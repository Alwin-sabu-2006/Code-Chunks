import re
from pathlib import Path

rules = [
    {
        "id": "RULE-PY-001",
        "name": "Classical EC Key Generation (SECP256K1)",
        "pattern": r"\bec\.SECP256K1\s*\(|\bec\.generate_private_key\s*\([^)]*SECP256K1|\becdsa\.SigningKey\b",
        "algorithm": "ec_SECP256K1_KeyGen",
        "file_extensions": [".py"],
    },
    {
        "id": "RULE-PY-002",
        "name": "ECDSA Signature Verification / Signing",
        "pattern": r"\bec\.ECDSA\s*\(",
        "algorithm": "ec_ECDSA_Signature",
        "file_extensions": [".py"],
    },
    {
        "id": "RULE-PY-003",
        "name": "On-Chain Raw Public Key Exposure",
        "pattern": r"\bsender_pub\s*:\s*str\b",
        "algorithm": "Exposed_Raw_PublicKey",
        "file_extensions": [".py"],
    },
    {
        "id": "RULE-PY-004",
        "name": "RSA Keygen & PKCS#1 v1.5 / OAEP",
        "pattern": r"\brsa\.generate_private_key\s*\(|\bpadding\.PKCS1v15\s*\(|\bpadding\.OAEP\s*\(",
        "algorithm": "RSA_PKCS1v15",
        "file_extensions": [".py"],
    },
    {
        "id": "RULE-PY-005",
        "name": "ECDH Key Agreement",
        "pattern": r"\bec\.ECDH\s*\(",
        "algorithm": "ECDH_Key_Agreement",
        "file_extensions": [".py"],
    },
]

for r in rules:
    r["regex"] = re.compile(r["pattern"], re.IGNORECASE | re.MULTILINE)

vulnchain_files = [
    "wallet.py", "ledger.py", "node_identity.py", "app.py", "demo.py", "test_vulnchain.py"
]

all_findings = []
for fname in vulnchain_files:
    fpath = Path("samples/vulnchain") / fname
    with open(fpath, "r", encoding="utf-8") as f:
        lines = f.readlines()
    
    matched_rules_in_file = set()
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for r in rules:
            if r["regex"].search(line):
                rule_key = (fname, r["id"])
                if rule_key not in matched_rules_in_file:
                    matched_rules_in_file.add(rule_key)
                    all_findings.append({
                        "file": fname,
                        "line": idx,
                        "rule": r["id"],
                        "algo": r["algorithm"],
                        "snippet": stripped
                    })

print(f"Total Findings Found: {len(all_findings)}")
for item in all_findings:
    print(f"[{item['rule']}] {item['file']}:{item['line']} - {item['algo']} -> {item['snippet']}")
