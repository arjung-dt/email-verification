"""Standalone email-existence verifier.

Public API:
  - `is_verified(email)` -> bool       — simple integration interface
  - `verify(email)` -> Verdict          — full structured result
  - `Verdict`                           — orchestrator output type
  - `ProviderReading`                   — per-provider result type
  - `api_keys_from_env()` -> dict       — convenience env-var reader
"""

__version__ = "0.1.0"

from .providers import ProviderReading
from .verifier import Verdict, api_keys_from_env, is_verified, verify

__all__ = [
    "is_verified",
    "verify",
    "Verdict",
    "ProviderReading",
    "api_keys_from_env",
]
