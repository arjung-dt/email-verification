"""Combined email-existence verifier.

Pipeline (each step short-circuits when it gets a definitive answer):

  1. **Syntax** — `local@domain` shape.
  2. **DNS MX lookup** — does the domain accept mail at all? (Definitive "no" if absent.)
  3. **Disposable check** — known throwaway providers.
  4. **HTTPS provider chain** — QEV → MyEmailVerifier → Abstract → Mailboxlayer → Hunter.
     Each is HTTPS (port 443), free tier, no card. Combined free capacity:
     ~6300 verifications/month. The chain runs in priority order — daily-reset
     providers first, monthly-reset second — and stops at the first definitive
     answer.

Each provider is independently configured via env var; the chain skips any
whose key isn't set, so partial configurations are valid.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional

import dns.exception
import dns.resolver

from .disposable import is_disposable as _is_disposable_domain
from .providers import (
    PROVIDERS,
    ProviderReading,
    run_chain,
)


DNS_LIFETIME = 5.0
log = logging.getLogger(__name__)


# Outcomes that count as "verified" for the simple boolean integration API.
# - "yes":    a provider confirmed the specific mailbox accepts mail.
# - "likely": a provider confirmed the address is acceptable but the server is
#             catch-all (mail will arrive at *some* mailbox at that domain).
# Everything else (likely_no = disposable, no = invalid/no MX, or a "likely"
# that came from the fallback path because no provider was configured) is
# explicitly NOT counted as verified.
_VERIFIED_EXISTS = frozenset({"yes", "likely"})
_FALLBACK_DECISION = "fallback"


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Verdict:
    email: str
    domain: str
    exists: str  # "yes" | "likely" | "likely_no" | "no"
    reason: str
    decided_by: str  # "syntax" | "mx" | "disposable" | "<provider_id>" | "fallback"
    domain_has_mx: bool
    mx_records: list[str] = field(default_factory=list)
    is_disposable: bool = False
    provider_readings: list[ProviderReading] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "email": self.email,
            "domain": self.domain,
            "exists": self.exists,
            "reason": self.reason,
            "decided_by": self.decided_by,
            "domain_has_mx": self.domain_has_mx,
            "mx_records": self.mx_records,
            "is_disposable": self.is_disposable,
            "providers": [_pr_to_dict(p) for p in self.provider_readings],
        }


def _pr_to_dict(p: ProviderReading) -> dict[str, Any]:
    return {
        "provider": p.provider,
        "result": p.result,
        "catch_all": p.catch_all,
        "disposable": p.disposable,
        "role": p.role,
        "free": p.free,
        "score": p.score,
        "raw_status": p.raw_status,
        "error": p.error,
    }


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def lookup_mx(domain: str) -> list[str]:
    """Return MX hostnames sorted by priority (lowest first). Empty list = no MX."""
    if not domain:
        return []
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=DNS_LIFETIME)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException as exc:
        log.debug("MX lookup failed for %s: %s", domain, exc)
        return []
    by_pref = sorted(answers, key=lambda r: getattr(r, "preference", 0))
    return [str(r.exchange).rstrip(".") for r in by_pref]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Public integration API
# ---------------------------------------------------------------------------

def api_keys_from_env() -> dict[str, str]:
    """Convenience: collect all configured provider keys from environment.

    Each provider's key is read from its declared env var (see PROVIDERS).
    Missing keys are simply absent from the result.
    """
    keys: dict[str, str] = {}
    for provider_id, _fn, env_var, _quota, _reset in PROVIDERS:
        val = os.environ.get(env_var)
        if val:
            keys[provider_id] = val
    return keys


def is_verified(
    email: str,
    *,
    api_keys: Optional[dict[str, str]] = None,
) -> bool:
    """Simple boolean integration API: True iff the email is verified.

    Mapping:
      - "yes"        → True   (mailbox confirmed by a provider)
      - "likely"     → True   (catch-all domain — mail arrives somewhere)
      - "likely_no"  → False  (disposable / throwaway provider)
      - "no"         → False  (invalid syntax, no MX, or provider rejected)
      - fallback     → False  (no providers configured / all providers errored)

    If `api_keys` is omitted, the function reads them from environment
    variables (QEV_API_KEY, MEV_API_KEY, ABSTRACT_API_KEY,
    MAILBOXLAYER_API_KEY, HUNTER_API_KEY).

    For the full structured result (provider trail, reasons, MX records, etc.)
    use `verify()` directly.
    """
    if api_keys is None:
        api_keys = api_keys_from_env()
    verdict = verify(email, api_keys=api_keys)
    if verdict.decided_by == _FALLBACK_DECISION:
        return False
    return verdict.exists in _VERIFIED_EXISTS


def verify(
    email: str,
    *,
    api_keys: Optional[dict[str, str]] = None,
) -> Verdict:
    """Run the full verification chain.

    `api_keys` is a dict like `{"qev": "...", "hunter": "...", ...}`. Each key
    is looked up by provider id (see `providers.PROVIDERS`). Any provider whose
    key is missing is skipped silently, so partial configs are fine.
    """
    api_keys = api_keys or {}
    email = (email or "").strip()

    # Step 1: syntax — must be local@domain with non-empty local and domain
    if "@" not in email:
        return Verdict(
            email=email, domain="", exists="no", decided_by="syntax",
            reason="Email is malformed (missing '@').",
            domain_has_mx=False,
        )

    # rsplit handles addresses with multiple @ — only the last one is the separator
    local, domain = email.rsplit("@", 1)
    domain = domain.lower().strip(". ")  # normalize: lowercase + strip trailing dot/whitespace
    local = local.strip()
    if not local or not domain:
        return Verdict(
            email=email, domain=domain, exists="no", decided_by="syntax",
            reason="Email is malformed (empty local part or domain).",
            domain_has_mx=False,
        )

    # Step 2: MX lookup
    mx_records = lookup_mx(domain)
    if not mx_records:
        return Verdict(
            email=email, domain=domain, exists="no", decided_by="mx",
            reason=f"{domain} has no MX records — mail cannot be delivered to this domain.",
            domain_has_mx=False,
        )

    # Step 3: disposable check (recorded even when chain returns valid — full signal trail)
    disposable = _is_disposable_domain(domain)

    # Step 4: HTTPS provider chain
    provider_readings = run_chain(email, api_keys=api_keys)

    return _decide(
        email=email,
        domain=domain,
        mx_records=mx_records,
        disposable=disposable,
        provider_readings=provider_readings,
    )


def _decide(
    *,
    email: str,
    domain: str,
    mx_records: list[str],
    disposable: bool,
    provider_readings: list[ProviderReading],
) -> Verdict:
    base = dict(
        email=email,
        domain=domain,
        domain_has_mx=True,
        mx_records=mx_records,
        is_disposable=disposable,
        provider_readings=provider_readings,
    )

    # Disposable wins over deliverability — even if mail lands somewhere, the
    # address is throwaway by definition and shouldn't be trusted as identity.
    if disposable:
        return Verdict(
            **base, exists="likely_no", decided_by="disposable",
            reason=(
                f"{domain} is a known disposable / throwaway email provider. "
                "The mailbox may technically exist, but treat this address as not real."
            ),
        )

    # Walk the chain in order; first definitive reading decides
    for r in provider_readings:
        if r.result == "valid":
            if r.catch_all is True:
                return Verdict(
                    **base, exists="likely", decided_by=r.provider,
                    reason=(
                        f"{r.provider} reports the address as valid, but the domain is "
                        "catch-all (accepts everything). Per-mailbox existence cannot "
                        "be confirmed."
                    ),
                )
            return Verdict(
                **base, exists="yes", decided_by=r.provider,
                reason=(
                    f"{r.provider} confirmed the mailbox is valid"
                    + (f" (status: {r.raw_status})" if r.raw_status else "")
                    + "."
                ),
            )
        if r.result == "invalid":
            return Verdict(
                **base, exists="no", decided_by=r.provider,
                reason=(
                    f"{r.provider} reports the mailbox is invalid"
                    + (f" (status: {r.raw_status})" if r.raw_status else "")
                    + "."
                ),
            )

    # Nothing definitive — fallback
    if not provider_readings:
        return Verdict(
            **base, exists="likely", decided_by="fallback",
            reason=(
                "Domain accepts mail (MX records exist) but no provider was configured. "
                "Set at least one of QEV_API_KEY / MEV_API_KEY / ABSTRACT_API_KEY / "
                "MAILBOXLAYER_API_KEY / HUNTER_API_KEY for per-mailbox verification."
            ),
        )

    notes = ", ".join(
        f"{r.provider}={r.error or r.result}" for r in provider_readings
    )
    return Verdict(
        **base, exists="likely", decided_by="fallback",
        reason=(
            "Domain accepts mail (MX records exist) but per-mailbox could not be "
            f"definitively verified. Provider results: {notes}."
        ),
    )
