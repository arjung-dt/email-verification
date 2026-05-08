"""HTTPS email-verification providers.

Each provider has its own query function and a normalized `ProviderReading`
result. The verifier orchestrator iterates them in declaration order, taking
the first definitive answer (valid / invalid). Inconclusive / error results
fall through to the next provider.

All providers here:
  - Have a free tier with no credit card required at signup
  - Reset their free tier automatically (daily or monthly)
  - Are accessed via HTTPS / port 443 — no port 25 needed

Security notes:
  - API keys are passed through `httpx.get(..., params=...)`, which
    URL-encodes them safely. They never appear in our log statements.
  - Error fields are run through `_sanitize` to strip any `?key=value`
    query strings that might appear in third-party exception messages —
    a defense-in-depth measure against future SDK behavior changes.
"""
from __future__ import annotations

import json as _json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import httpx


HTTP_TIMEOUT = 15.0

log = logging.getLogger(__name__)


# Strip "?key=value..." segments from error strings (defense-in-depth against
# any future SDK or network library that might surface URLs containing API keys
# in exception messages). httpx today doesn't, but we redact regardless.
_QUERY_STRING_RE = re.compile(r"\?[^\s'\"]*")


def _sanitize(text: object, *, max_len: int = 200) -> str:
    s = str(text)
    s = _QUERY_STRING_RE.sub("?[redacted]", s)
    if len(s) > max_len:
        s = s[:max_len] + "..."
    return s


# ---------------------------------------------------------------------------
# Shared normalized reading
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProviderReading:
    """Normalized email-verification result from any provider.

    `result`:
      - "valid"      → provider says the mailbox exists and is deliverable
      - "invalid"    → provider says the mailbox does not exist
      - "unknown"    → provider couldn't tell (risky / unknown / accept-all)
      - "error"      → request failed (HTTP error, timeout, bad key)
    """

    provider: str
    result: str
    catch_all: Optional[bool] = None
    disposable: Optional[bool] = None
    role: Optional[bool] = None
    free: Optional[bool] = None
    score: Optional[float] = None
    raw_status: Optional[str] = None  # Provider-specific status field, free-form
    error: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)

    def is_definitive(self) -> bool:
        return self.result in ("valid", "invalid")


def _truthy(v: Any) -> Optional[bool]:
    """Booleans-or-strings → real bool (or None for absent/unknown)."""
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("true", "yes", "1"):
        return True
    if s in ("false", "no", "0"):
        return False
    return None


def _safe_json(response: httpx.Response, provider_id: str):
    """Decode response body. Returns dict on success, ProviderReading on failure."""
    if not response.content:
        return {}
    try:
        return response.json()
    except (_json.JSONDecodeError, ValueError) as exc:
        return ProviderReading(
            provider=provider_id, result="error",
            error=f"malformed JSON response: {_sanitize(exc)}",
        )


# ---------------------------------------------------------------------------
# Hunter.io   (50 credits/month → ~100 verifications/month, monthly reset)
# ---------------------------------------------------------------------------

def query_hunter(email: str, api_key: str) -> ProviderReading:
    try:
        response = httpx.get(
            "https://api.hunter.io/v2/email-verifier",
            params={"email": email, "api_key": api_key},
            timeout=HTTP_TIMEOUT,
        )
    except httpx.HTTPError as exc:
        return ProviderReading(provider="hunter", result="error", error=_sanitize(exc))

    if response.status_code != 200:
        return ProviderReading(
            provider="hunter", result="error",
            error=f"HTTP {response.status_code}: {_sanitize(response.text)}",
        )

    body = _safe_json(response, "hunter")
    if isinstance(body, ProviderReading):
        return body
    data = body.get("data") or {}
    raw = (data.get("result") or "").lower()
    if raw == "deliverable":
        result = "valid"
    elif raw == "undeliverable":
        result = "invalid"
    else:
        result = "unknown"

    return ProviderReading(
        provider="hunter",
        result=result,
        catch_all=_truthy(data.get("accept_all")),
        disposable=_truthy(data.get("disposable")),
        role=_truthy(data.get("role")),
        free=None,  # not directly exposed
        score=data.get("score"),
        raw_status=data.get("status"),
        raw=data,
    )


# ---------------------------------------------------------------------------
# QuickEmailVerification (100/day → ~3000/month, DAILY reset)
# ---------------------------------------------------------------------------

def query_qev(email: str, api_key: str) -> ProviderReading:
    try:
        response = httpx.get(
            "https://api.quickemailverification.com/v1/verify",
            params={"email": email, "apikey": api_key},
            timeout=HTTP_TIMEOUT,
        )
    except httpx.HTTPError as exc:
        return ProviderReading(provider="qev", result="error", error=_sanitize(exc))

    if response.status_code != 200:
        return ProviderReading(
            provider="qev", result="error",
            error=f"HTTP {response.status_code}: {_sanitize(response.text)}",
        )

    body = _safe_json(response, "qev")
    if isinstance(body, ProviderReading):
        return body
    raw = (body.get("result") or "").lower()
    if raw == "valid":
        result = "valid"
    elif raw == "invalid":
        result = "invalid"
    else:
        result = "unknown"

    return ProviderReading(
        provider="qev",
        result=result,
        catch_all=_truthy(body.get("accept_all")),
        disposable=_truthy(body.get("disposable")),
        role=_truthy(body.get("role")),
        free=_truthy(body.get("free")),
        raw_status=body.get("reason"),
        raw=body,
    )


# ---------------------------------------------------------------------------
# MyEmailVerifier (100/day → ~3000/month, DAILY reset)
# ---------------------------------------------------------------------------

def query_mev(email: str, api_key: str) -> ProviderReading:
    try:
        response = httpx.get(
            "https://api.myemailverifier.com/api/validate_single.php",
            params={"apikey": api_key, "email": email},
            timeout=HTTP_TIMEOUT,
        )
    except httpx.HTTPError as exc:
        return ProviderReading(provider="mev", result="error", error=_sanitize(exc))

    if response.status_code != 200:
        return ProviderReading(
            provider="mev", result="error",
            error=f"HTTP {response.status_code}: {_sanitize(response.text)}",
        )

    body = _safe_json(response, "mev")
    if isinstance(body, ProviderReading):
        return body
    status = (body.get("Status") or "").lower()
    catch_all_field = _truthy(body.get("catch_all"))

    # Status semantics observed live from MEV:
    #   "Valid"     → mailbox confirmed
    #   "Invalid"   → mailbox does not exist
    #   "Catch-all" → domain accepts everything; mailbox can't be uniquely confirmed
    #                 We treat this as "valid + catch_all=True" so the verdict
    #                 layer renders it as "likely" (matches QEV's accept_all flag).
    #   "Greylisted" / "Unknown" / "Disposable" / "Role" → unknown
    if status == "valid":
        result = "valid"
        catch_all = catch_all_field if catch_all_field is not None else False
    elif status in ("invalid", "undeliverable"):
        result = "invalid"
        catch_all = catch_all_field
    elif status == "catch-all":
        result = "valid"
        catch_all = True
    else:
        result = "unknown"
        catch_all = catch_all_field

    return ProviderReading(
        provider="mev",
        result=result,
        catch_all=catch_all,
        disposable=_truthy(body.get("Disposable_Domain")),
        role=_truthy(body.get("Role_Based")),
        free=_truthy(body.get("Free_Domain")),
        raw_status=body.get("Diagnosis") or body.get("Status"),
        raw=body,
    )


# ---------------------------------------------------------------------------
# Abstract API (100/month, MONTHLY reset)
# ---------------------------------------------------------------------------

def query_abstract(email: str, api_key: str) -> ProviderReading:
    try:
        response = httpx.get(
            "https://emailvalidation.abstractapi.com/v1/",
            params={"api_key": api_key, "email": email},
            timeout=HTTP_TIMEOUT,
        )
    except httpx.HTTPError as exc:
        return ProviderReading(provider="abstract", result="error", error=_sanitize(exc))

    if response.status_code != 200:
        return ProviderReading(
            provider="abstract", result="error",
            error=f"HTTP {response.status_code}: {_sanitize(response.text)}",
        )

    body = _safe_json(response, "abstract")
    if isinstance(body, ProviderReading):
        return body
    raw = (body.get("deliverability") or "").upper()
    if raw == "DELIVERABLE":
        result = "valid"
    elif raw == "UNDELIVERABLE":
        result = "invalid"
    else:
        result = "unknown"

    quality = body.get("quality_score")
    try:
        score = float(quality) if quality is not None else None
    except (TypeError, ValueError):
        score = None

    return ProviderReading(
        provider="abstract",
        result=result,
        catch_all=_extract_abstract_bool(body, "is_catchall_email"),
        disposable=_extract_abstract_bool(body, "is_disposable_email"),
        role=_extract_abstract_bool(body, "is_role_email"),
        free=_extract_abstract_bool(body, "is_free_email"),
        score=score,
        raw_status=raw or None,
        raw=body,
    )


def _extract_abstract_bool(body: dict[str, Any], key: str) -> Optional[bool]:
    """Abstract returns booleans wrapped in `{value, text}` objects sometimes."""
    val = body.get(key)
    if isinstance(val, dict):
        return _truthy(val.get("value"))
    return _truthy(val)


# ---------------------------------------------------------------------------
# Mailboxlayer (100/month, MONTHLY reset; apilayer family)
# ---------------------------------------------------------------------------

def query_mailboxlayer(email: str, api_key: str) -> ProviderReading:
    try:
        response = httpx.get(
            "https://apilayer.net/api/check",
            params={"access_key": api_key, "email": email, "smtp": "1", "format": "1"},
            timeout=HTTP_TIMEOUT,
        )
    except httpx.HTTPError as exc:
        return ProviderReading(provider="mailboxlayer", result="error", error=_sanitize(exc))

    if response.status_code != 200:
        return ProviderReading(
            provider="mailboxlayer", result="error",
            error=f"HTTP {response.status_code}: {_sanitize(response.text)}",
        )

    body = _safe_json(response, "mailboxlayer")
    if isinstance(body, ProviderReading):
        return body
    if "success" in body and body["success"] is False:
        err = body.get("error", {})
        return ProviderReading(
            provider="mailboxlayer", result="error",
            error=f"{err.get('code')}: {err.get('info', 'unknown')}",
            raw=body,
        )

    smtp_check = _truthy(body.get("smtp_check"))
    format_valid = _truthy(body.get("format_valid"))
    mx_found = _truthy(body.get("mx_found"))

    if format_valid is False or mx_found is False:
        result = "invalid"
    elif smtp_check is True:
        result = "valid"
    elif smtp_check is False:
        result = "invalid"
    else:
        result = "unknown"

    return ProviderReading(
        provider="mailboxlayer",
        result=result,
        catch_all=_truthy(body.get("catch_all")),
        disposable=_truthy(body.get("disposable")),
        role=_truthy(body.get("role")),
        free=_truthy(body.get("free")),
        score=body.get("score"),
        raw_status=str(body.get("did_you_mean") or "") or None,
        raw=body,
    )


# ---------------------------------------------------------------------------
# Provider chain — ordered by free-tier capacity (most generous first)
# ---------------------------------------------------------------------------

# Each entry: (provider_id, query_function, env_var_name, monthly_quota, reset_period)
ProviderSpec = tuple[str, Callable[[str, str], ProviderReading], str, int, str]

PROVIDERS: list[ProviderSpec] = [
    ("qev", query_qev, "QEV_API_KEY", 3000, "daily"),
    ("mev", query_mev, "MEV_API_KEY", 3000, "daily"),
    ("abstract", query_abstract, "ABSTRACT_API_KEY", 100, "monthly"),
    ("mailboxlayer", query_mailboxlayer, "MAILBOXLAYER_API_KEY", 100, "monthly"),
    ("hunter", query_hunter, "HUNTER_API_KEY", 100, "monthly"),
]


def run_chain(
    email: str,
    *,
    api_keys: dict[str, str],
) -> list[ProviderReading]:
    """Run providers in PROVIDERS order, stopping at first definitive result.

    Returns the list of readings actually obtained (in call order). The last
    reading in the list is what the verdict is built from. Inconclusive /
    error readings are still included so callers can debug.
    """
    readings: list[ProviderReading] = []
    for provider_id, fn, _env, _quota, _reset in PROVIDERS:
        key = api_keys.get(provider_id)
        if not key:
            continue
        try:
            reading = fn(email, key)
        except Exception as exc:
            # Defensive: query_X functions catch their own httpx errors, but log
            # any uncaught exception by *type* only — never include the message,
            # which could conceivably embed a URL with the API key.
            log.warning("provider %s raised %s", provider_id, type(exc).__name__)
            reading = ProviderReading(
                provider=provider_id, result="error",
                error=f"unexpected {type(exc).__name__}",
            )
        readings.append(reading)
        if reading.is_definitive():
            return readings
    return readings
