"""
Q-Chain Initial Demo Data Seeder
Populates initial scans for demonstration
"""
import database
from analyzers.transaction_analyzer import TransactionRiskAnalyzer
from analyzers.access_control import AccessControlScanner
from analyzers.reentrancy import ReentrancyDetector

def seed():
    database.init_db()
    
    # 1. Threat 1 Unlimited Approval Scan
    tx_analyzer = TransactionRiskAnalyzer()
    res1 = tx_analyzer.analyze({
        "to": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "raw_data": "0x095ea7b30000000000000000000000001111111254fb6c44bac0bed2854e76f90643097dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    })
    database.save_scan(
        scan_type="TRANSACTION",
        target_name="USDC approve(1inch, uint256.max)",
        risk_score=res1["risk_score"],
        risk_level=res1["risk_level"],
        findings=res1["findings"],
        raw_input="0x095ea7b30000000000000000000000001111111254fb6c44bac0bed2854e76f90643097dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        summary=res1["summary"]
    )

    # 2. Threat 2 VulnerableToken Scan
    ac_scanner = AccessControlScanner()
    code_vuln_token = """contract VulnerableToken {
    uint256 public totalSupply;
    function mint(uint256 amount) public {
        totalSupply += amount;
    }
}"""
    res2 = ac_scanner.analyze(code_vuln_token, "VulnerableToken.sol")
    database.save_scan(
        scan_type="SOLIDITY_CONTRACT",
        target_name="VulnerableToken.sol",
        risk_score=res2["risk_score"],
        risk_level=res2["risk_level"],
        findings=res2["findings"],
        raw_input=code_vuln_token,
        summary=res2["summary"]
    )

    # 3. Threat 3 VulnerableVault Scan
    re_detector = ReentrancyDetector()
    code_vuln_vault = """contract VulnerableVault {
    mapping(address => uint256) public balances;
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0;
    }
}"""
    res3 = re_detector.analyze(code_vuln_vault, "VulnerableVault.sol")
    database.save_scan(
        scan_type="SOLIDITY_CONTRACT",
        target_name="VulnerableVault.sol",
        risk_score=res3["risk_score"],
        risk_level=res3["risk_level"],
        findings=res3["findings"],
        raw_input=code_vuln_vault,
        summary=res3["summary"]
    )

    print("Successfully seeded initial demo scans in SQLite database.")

if __name__ == "__main__":
    seed()
