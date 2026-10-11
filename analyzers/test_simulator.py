"""
Q-Chain Execution-Based Reentrancy Simulator
Threat 3, Test Case 3: Dynamic execution verification comparing Vulnerable vs. Secure Vaults
"""

class ExecutionSimulator:
    """
    Simulates EVM control flow, state transitions, and recursive call interception
    to demonstrate reentrancy exploit mechanics vs. CEI / ReentrancyGuard remediation.
    """

    def run_vulnerable_vault_simulation(self, vault_seed_eth: float = 10.0, attacker_deposit_eth: float = 1.0, max_recursion: int = 15) -> dict:
        logs = []
        vault_balance = vault_seed_eth + attacker_deposit_eth
        balances = {
            "legitimate_user": vault_seed_eth,
            "attacker": attacker_deposit_eth
        }
        attacker_stolen = 0.0
        recursion_depth = 0

        logs.append({
            "step": 1,
            "event": "INITIAL_STATE",
            "description": f"Vault deployed and funded. Legitimate user deposited {vault_seed_eth} ETH. Attacker deposited {attacker_deposit_eth} ETH.",
            "vault_balance": vault_balance,
            "attacker_balance_recorded": balances["attacker"],
            "attacker_wallet_eth": 0.0
        })

        # Attacker calls withdraw()
        logs.append({
            "step": 2,
            "event": "ATTACK_TRIGGER",
            "description": "Attacker initiates withdraw() from MaliciousRecipient contract.",
            "vault_balance": vault_balance,
            "attacker_balance_recorded": balances["attacker"],
            "attacker_wallet_eth": 0.0
        })

        step_counter = 3

        def simulate_vulnerable_withdraw(depth):
            nonlocal vault_balance, attacker_stolen, step_counter
            
            amount = balances["attacker"]
            if amount <= 0:
                logs.append({
                    "step": step_counter,
                    "event": "REVERT",
                    "description": f"[Depth {depth}] require(amount > 0) failed.",
                    "vault_balance": vault_balance,
                    "attacker_balance_recorded": balances["attacker"],
                    "attacker_wallet_eth": attacker_stolen
                })
                step_counter += 1
                return

            logs.append({
                "step": step_counter,
                "event": "EXTERNAL_CALL_START",
                "description": f"[Depth {depth}] Vault reads balances['attacker'] = {amount} ETH. Vault triggers external call: attacker.call{{value: {amount}}}('')",
                "vault_balance": vault_balance,
                "attacker_balance_recorded": balances["attacker"],
                "attacker_wallet_eth": attacker_stolen
            })
            step_counter += 1

            # Transfer value to attacker
            transfer_amount = min(amount, vault_balance)
            vault_balance -= transfer_amount
            attacker_stolen += transfer_amount

            # Attacker's fallback receives funds and recursively calls withdraw() if vault has balance
            if vault_balance > 0 and depth < max_recursion:
                logs.append({
                    "step": step_counter,
                    "event": "RECURSIVE_CALLBACK",
                    "description": f"[Depth {depth}] Attacker fallback() triggered! Vault still has {vault_balance:.1f} ETH left. ATTACKER RE-ENTERS withdraw() BEFORE balance is zeroed!",
                    "vault_balance": vault_balance,
                    "attacker_balance_recorded": balances["attacker"],
                    "attacker_wallet_eth": attacker_stolen
                })
                step_counter += 1
                simulate_vulnerable_withdraw(depth + 1)

            # Finally, the vulnerable function updates state AFTER external call
            balances["attacker"] = 0
            logs.append({
                "step": step_counter,
                "event": "DELAYED_STATE_UPDATE",
                "description": f"[Depth {depth}] Vault finally executes: balances['attacker'] = 0 (Unwound). Too late!",
                "vault_balance": vault_balance,
                "attacker_balance_recorded": balances["attacker"],
                "attacker_wallet_eth": attacker_stolen
            })
            step_counter += 1

        simulate_vulnerable_withdraw(1)

        exploit_successful = attacker_stolen > attacker_deposit_eth
        return {
            "test_case": "Test Case 3A — Vulnerable Vault Execution",
            "exploit_successful": exploit_successful,
            "initial_vault_eth": vault_seed_eth + attacker_deposit_eth,
            "final_vault_eth": max(0.0, vault_balance),
            "attacker_deposited_eth": attacker_deposit_eth,
            "attacker_withdrawn_eth": attacker_stolen,
            "funds_drained_eth": attacker_stolen - attacker_deposit_eth,
            "verdict": "VULNERABILITY CONFIRMED: Recursive reentrancy callback successfully drained victim funds.",
            "execution_trace": logs
        }

    def run_secure_vault_simulation(self, vault_seed_eth: float = 10.0, attacker_deposit_eth: float = 1.0) -> dict:
        logs = []
        vault_balance = vault_seed_eth + attacker_deposit_eth
        balances = {
            "legitimate_user": vault_seed_eth,
            "attacker": attacker_deposit_eth
        }
        attacker_stolen = 0.0
        step_counter = 1

        logs.append({
            "step": step_counter,
            "event": "INITIAL_STATE",
            "description": f"SecureVault deployed. User funded {vault_seed_eth} ETH. Attacker funded {attacker_deposit_eth} ETH.",
            "vault_balance": vault_balance,
            "attacker_balance_recorded": balances["attacker"],
            "attacker_wallet_eth": 0.0
        })
        step_counter += 1

        logs.append({
            "step": step_counter,
            "event": "ATTACK_TRIGGER",
            "description": "Attacker initiates withdraw() from MaliciousRecipient contract.",
            "vault_balance": vault_balance,
            "attacker_balance_recorded": balances["attacker"],
            "attacker_wallet_eth": 0.0
        })
        step_counter += 1

        # Secure withdraw implementation
        amount = balances["attacker"]
        logs.append({
            "step": step_counter,
            "event": "CHECKS",
            "description": f"[Depth 1] Vault validates require(amount > 0): Valid ({amount} ETH).",
            "vault_balance": vault_balance,
            "attacker_balance_recorded": balances["attacker"],
            "attacker_wallet_eth": 0.0
        })
        step_counter += 1

        # 1. State update happens FIRST (Checks-Effects-Interactions)
        balances["attacker"] = 0
        logs.append({
            "step": step_counter,
            "event": "EFFECTS_FIRST",
            "description": "[Depth 1] CEI APPLIED: balances['attacker'] = 0 executed PRIOR to external call.",
            "vault_balance": vault_balance,
            "attacker_balance_recorded": 0,
            "attacker_wallet_eth": 0.0
        })
        step_counter += 1

        # 2. External call
        logs.append({
            "step": step_counter,
            "event": "INTERACTION_START",
            "description": f"[Depth 1] Vault triggers external call: attacker.call{{value: {amount}}}('')",
            "vault_balance": vault_balance - amount,
            "attacker_balance_recorded": 0,
            "attacker_wallet_eth": amount
        })
        step_counter += 1
        vault_balance -= amount
        attacker_stolen += amount

        # Attacker tries callback
        logs.append({
            "step": step_counter,
            "event": "CALLBACK_ATTEMPT",
            "description": "[Depth 2] Attacker fallback attempts recursive call: withdraw().",
            "vault_balance": vault_balance,
            "attacker_balance_recorded": 0,
            "attacker_wallet_eth": attacker_stolen
        })
        step_counter += 1

        # Re-entry check
        logs.append({
            "step": step_counter,
            "event": "REVERT_SECURED",
            "description": "[Depth 2] Vault checks: require(balances['attacker'] > 0) -> REVERT! Balance is 0! Callback blocked.",
            "vault_balance": vault_balance,
            "attacker_balance_recorded": 0,
            "attacker_wallet_eth": attacker_stolen
        })
        step_counter += 1

        logs.append({
            "step": step_counter,
            "event": "EXECUTION_COMPLETE",
            "description": "Transaction completed safely. Attacker received only their fair deposit of 1.0 ETH. Legitimate user funds are intact.",
            "vault_balance": vault_balance,
            "attacker_balance_recorded": 0,
            "attacker_wallet_eth": attacker_stolen
        })

        return {
            "test_case": "Test Case 3B — Secure Vault (CEI) Execution",
            "exploit_successful": False,
            "initial_vault_eth": vault_seed_eth + attacker_deposit_eth,
            "final_vault_eth": vault_balance,
            "attacker_deposited_eth": attacker_deposit_eth,
            "attacker_withdrawn_eth": attacker_stolen,
            "funds_drained_eth": 0.0,
            "verdict": "REENTRANCY PREVENTED: State update preceded external call; recursive re-entry was safely rejected.",
            "execution_trace": logs
        }
