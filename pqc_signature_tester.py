"""
Convenience entry point for Q-Chain Post-Quantum Cryptography Signature Testing Module (Member 2).
"""

import sys
from pathlib import Path

# Ensure root directory is on Python path
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from backend.pqc_testing.cli import main

if __name__ == "__main__":
    main()
