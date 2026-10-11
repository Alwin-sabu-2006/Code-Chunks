"""
EVM Blockchain Gas & On-Chain Storage Cost Estimator for PQC Migration.
Calculates calldata gas, SSTORE storage slots, L1 costs, and L2 rollup economics
for classical vs post-quantum signature schemes.
"""

import math
from typing import Dict, List
from crypto.registry import CryptoRegistry
from schemas.crypto_schemas import GasEstimateComparison


class EVMGasEstimator:
    """Estimates on-chain gas overhead and economic cost for PQC signatures."""

    # EVM Constants (Ethereum London / Cancun)
    GAS_CALLDATA_NONZERO_BYTE = 16  # EIP-2028
    GAS_CALLDATA_ZERO_BYTE = 4
    GAS_SSTORE_INIT = 20000        # First write to empty storage slot
    GAS_SSTORE_UPDATE = 5000       # Subsequent update write
    GAS_COLD_SLOAD = 2100          # Cold account access
    BYTES_PER_STORAGE_SLOT = 32

    def __init__(self, eth_price_usd: float = 3000.0, gas_price_gwei: float = 30.0):
        self.eth_price_usd = eth_price_usd
        self.gas_price_gwei = gas_price_gwei

    def estimate_algorithm_gas(self, algorithm_id: str) -> GasEstimateComparison:
        """Calculate detailed gas and storage footprint for a specific algorithm."""
        signer = CryptoRegistry.get_signer(algorithm_id)
        sig_bytes = signer.signature_len
        pk_bytes = signer.public_key_len

        # Typical calldata: 16 gas per byte
        calldata_gas = sig_bytes * self.GAS_CALLDATA_NONZERO_BYTE
        
        # Storage slots required to store signature on-chain
        slots = math.ceil(sig_bytes / self.BYTES_PER_STORAGE_SLOT)
        storage_gas_new = slots * self.GAS_SSTORE_INIT
        storage_gas_update = slots * self.GAS_SSTORE_UPDATE

        # ECDSA baseline: 64 bytes signature -> 64 * 16 = 1024 gas
        baseline_calldata = 64 * self.GAS_CALLDATA_NONZERO_BYTE
        multiplier = round(calldata_gas / baseline_calldata, 2)

        # L1 Transaction total gas estimation = 21000 base + calldata
        total_tx_gas = 21000 + calldata_gas
        cost_eth = (total_tx_gas * self.gas_price_gwei) / 1e9
        cost_usd = round(cost_eth * self.eth_price_usd, 4)

        return GasEstimateComparison(
            algorithm=signer.algorithm_id,
            signature_bytes=sig_bytes,
            public_key_bytes=pk_bytes,
            calldata_gas_cost=calldata_gas,
            storage_slots_32b=slots,
            storage_gas_sstore_new=storage_gas_new,
            storage_gas_sstore_update=storage_gas_update,
            cost_multiplier_vs_ecdsa=multiplier,
            l1_tx_cost_usd_at_30gwei=cost_usd,
        )

    def compare_all_algorithms(self) -> List[GasEstimateComparison]:
        """Generate comparison table for all supported algorithms."""
        algos = CryptoRegistry.list_algorithms()
        return [self.estimate_algorithm_gas(aid) for aid in algos]

    def get_breakdown_dict(self) -> Dict:
        """Returns serializable dictionary comparison."""
        estimates = self.compare_all_algorithms()
        return {
            "eth_price_usd": self.eth_price_usd,
            "gas_price_gwei": self.gas_price_gwei,
            "comparisons": [e.model_dump() for e in estimates],
        }
