"""
Q-Chain Configuration & Protocol Registries
Phase 1: Blockchain Security Analysis and Vulnerability Detection Platform
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "qchain.db")

# Solc compiler configuration
SOLC_BIN_PATH = r"C:\Users\LENOVO\.solcx\solc-v0.8.20\solc.exe"
DEFAULT_SOLC_VERSION = "0.8.20"

# Public EVM RPC endpoints for on-chain lookups (fallback to simulation if offline)
DEFAULT_RPC_ENDPOINTS = {
    "ethereum": "https://eth.llamarpc.com",
    "sepolia": "https://rpc.sepolia.org",
    "arbitrum": "https://arb1.arbitrum.io/rpc",
    "polygon": "https://polygon-rpc.com"
}

# 2^256 - 1 max uint256 constant
UINT256_MAX = 2**256 - 1
UNLIMITED_ALLOWANCE_THRESHOLD = 2**128  # Practically unlimited for any normal token decimal

# ERC-20 Standard function selectors (4 bytes)
ERC20_SELECTORS = {
    "0x095ea7b3": "approve(address,uint256)",
    "0xa9059cbb": "transfer(address,uint256)",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0x39509351": "increaseAllowance(address,uint256)",
    "0xa457c2d7": "decreaseAllowance(address,uint256)",
    "0xd5054bf8": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)"
}

# Curated registry of known legitimate protocols & high-reputation spenders
KNOWN_PROTOCOLS = {
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": {
        "name": "Uniswap V3 SwapRouter02",
        "category": "DEX Aggregator",
        "reputation": "VERIFIED_HIGH_TRUST",
        "description": "Official Uniswap V3 and V2 unified router contract."
    },
    "0x000000000022d473030f116ddee9f6b43ac78ba3": {
        "name": "Uniswap Permit2",
        "category": "Token Approval Hub",
        "reputation": "VERIFIED_HIGH_TRUST",
        "description": "Next-gen token approval management contract by Uniswap Labs."
    },
    "0x1111111254fb6c44bac0bed2854e76f90643097d": {
        "name": "1inch Aggregation Router V5",
        "category": "DEX Aggregator",
        "reputation": "VERIFIED_HIGH_TRUST",
        "description": "Official 1inch exchange route finder and aggregator contract."
    },
    "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2": {
        "name": "Aave V3 Lending Pool",
        "category": "Lending Protocol",
        "reputation": "VERIFIED_HIGH_TRUST",
        "description": "Aave Version 3 decentralized non-custodial liquidity market."
    },
    "0x00000000000000adc04c56bf30ac9d3c0aaf14dc": {
        "name": "OpenSea Seaport 1.5",
        "category": "NFT Marketplace",
        "reputation": "VERIFIED_HIGH_TRUST",
        "description": "Seaport marketplace protocol for trading NFT and ERC-20 assets."
    },
    "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": {
        "name": "SushiSwap Router",
        "category": "DEX",
        "reputation": "VERIFIED_HIGH_TRUST",
        "description": "Automated Market Maker Router for SushiSwap."
    }
}

# Flagged suspicious / phishing addresses commonly seen in scams
FLAGGED_SUSPICIOUS_SPENDERS = {
    "0x0000000000000000000000000000000000000000": {
        "name": "Zero Address (Burn / Invalid)",
        "risk": "CRITICAL",
        "reason": "Approving the null address will lock tokens or indicates malformed transaction."
    },
    "0x9999999999999999999999999999999999999999": {
        "name": "Inferno / Pink Drainer Contract Simulation",
        "risk": "CRITICAL",
        "reason": "Known malicious phishing drainer contract reported across Web3 blacklists."
    },
    "0xdead000000000000000042069420694206942069": {
        "name": "Phishing Token Stealer (Test Pattern)",
        "risk": "CRITICAL",
        "reason": "Flagged phishing spender mimicking legitimate dApp interfaces."
    }
}
