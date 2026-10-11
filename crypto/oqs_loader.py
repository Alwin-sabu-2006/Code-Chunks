"""
Safe loader for liboqs C library.
Prevents unprompted background build attempts on Windows environments
while seamlessly enabling hardware-accelerated liboqs C library on Linux/Docker.
"""

import os
import sys

# Prevent liboqs-python from auto-running git clone / cmake on unsupported hosts
os.environ["OQS_INSTALL"] = "0"

_LIBOQS_LOADED = False
_ENABLED_SIGS = set()

def try_load_oqs():
    global _LIBOQS_LOADED, _ENABLED_SIGS
    try:
        # Check if oqs is importable without triggering installer
        import oqs
        if hasattr(oqs, "get_enabled_sig_mechanisms"):
            _ENABLED_SIGS = set(oqs.get_enabled_sig_mechanisms())
            _LIBOQS_LOADED = True
    except Exception:
        _LIBOQS_LOADED = False
        _ENABLED_SIGS = set()

try_load_oqs()

def is_oqs_available() -> bool:
    return _LIBOQS_LOADED

def get_enabled_signatures() -> set:
    return _ENABLED_SIGS
