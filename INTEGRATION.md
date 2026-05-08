# Integration guide

Drop-in instructions for integrating `email-verifier` into an existing Python project.

## TL;DR

```python
from email_verifier import is_verified

if is_verified("user@example.com"):
    # mailbox accepts mail (real or catch-all) → proceed
    create_account(...)
else:
    # disposable, malformed, no MX, or rejected by every provider → block
    return reject("Please use a valid corporate or personal email.")
```

That's it. One function, one boolean, no setup beyond environment variables.

---

## Install

### Option 1 — clone and install with uv (recommended)

```bash
git clone git@github.com:arjung-dt/email-verification.git
cd email-verification
uv sync
```

If your existing project uses `uv`, add it as a path dependency:

```toml
# in your project's pyproject.toml
[project]
dependencies = [
    "email-verifier",
]

[tool.uv.sources]
email-verifier = { path = "../email-verification", editable = false }
```

### Option 2 — pip-install the cloned dir

```bash
git clone git@github.com:arjung-dt/email-verification.git
pip install ./email-verification
```

### Option 3 — vendor the package

If your project doesn't manage external Git deps cleanly, just copy the
`email_verifier/` directory into your project and `pip install dnspython httpx`.
The package has no other runtime dependencies.

---

## Configure

Set the API keys as environment variables in your prod environment. **At least one** is required; configure as many as you want for redundancy.

```bash
export QEV_API_KEY=...
export MEV_API_KEY=...
export ABSTRACT_API_KEY=...
export MAILBOXLAYER_API_KEY=...
export HUNTER_API_KEY=...
```

Free-tier signup links are in `.env.example`. None require a credit card; all reset automatically.

If you already use `python-dotenv` or similar, just add these to your existing `.env` file alongside your other secrets.

---

## The two integration entry points

### `is_verified(email)` → bool

Use this when you want a simple yes/no.

```python
from email_verifier import is_verified

if is_verified("user@example.com"):
    ...
```

Mapping:

| Underlying verdict | `is_verified()` returns | Meaning |
|---|---|---|
| `yes` (mailbox confirmed) | **True** | Provider directly confirmed the address |
| `likely` (catch-all) | **True** | Domain accepts everything; mail will arrive at *some* mailbox |
| `likely_no` (disposable) | **False** | Mailinator / 10minutemail / etc. — throwaway providers |
| `no` (invalid) | **False** | Malformed, no MX records, or provider rejected |
| `likely` from fallback path | **False** | No providers configured, or every provider returned unknown — we couldn't actually verify |

`api_keys` is read from environment variables automatically. To override per-call (e.g. for testing):

```python
is_verified("user@example.com", api_keys={"qev": "key1", "hunter": "key2"})
```

### `verify(email)` → Verdict

Use this when you want the full structured result for logging, audit trails, or downstream decision-making.

```python
from email_verifier import verify, api_keys_from_env

v = verify("user@example.com", api_keys=api_keys_from_env())

print(v.exists)          # "yes" | "likely" | "likely_no" | "no"
print(v.decided_by)      # "syntax" | "mx" | "disposable" | "qev" | ... | "fallback"
print(v.reason)          # human-readable explanation
print(v.domain_has_mx)   # bool
print(v.is_disposable)   # bool
print(v.mx_records)      # list[str]

for r in v.provider_readings:
    print(f"  {r.provider}: {r.result}, catch_all={r.catch_all}, error={r.error}")
```

The full `Verdict` is also `model_dump_json`-able via `.to_dict()`:

```python
import json
log.info("email verification", extra={"verdict": json.dumps(v.to_dict())})
```

---

## Common integration patterns

### Pattern 1: User signup flow

```python
from email_verifier import is_verified

def register_user(email: str, password: str) -> Response:
    if not is_verified(email):
        return BadRequest("This email address can't receive mail. Please use a different one.")
    # email passed verification — continue normal flow
    user = User.create(email=email, password=password)
    send_welcome(user)
    return Created(user)
```

### Pattern 2: Audit logging with structured data

```python
from email_verifier import verify, api_keys_from_env
import logging

log = logging.getLogger(__name__)

def register_user(email: str, password: str) -> Response:
    v = verify(email, api_keys=api_keys_from_env())

    log.info(
        "email_verification",
        extra={
            "email": email,
            "verdict": v.exists,
            "decided_by": v.decided_by,
            "is_disposable": v.is_disposable,
            "reason": v.reason,
        },
    )

    is_ok = v.exists in ("yes", "likely") and v.decided_by != "fallback"
    if not is_ok:
        return BadRequest(v.reason)

    return Created(User.create(email=email, password=password))
```

### Pattern 3: Async / FastAPI

The verifier itself is synchronous (each provider call is a blocking `httpx.get`). To use from an async handler, wrap in a thread:

```python
import asyncio
from email_verifier import is_verified

async def signup(email: str) -> bool:
    return await asyncio.to_thread(is_verified, email)
```

A single verification typically takes <1 second when the first provider answers; up to ~5 seconds if the chain has to walk past several timed-out providers.

### Pattern 4: Batch verification

```python
from email_verifier import is_verified, api_keys_from_env

keys = api_keys_from_env()  # read once

results: list[tuple[str, bool]] = []
for email in emails:
    results.append((email, is_verified(email, api_keys=keys)))
```

For high-throughput batches, parallelize with a thread pool — but watch the per-day rate limits on each provider (QEV: 100/day; MEV: 100/day; etc.).

### Pattern 5: Soft warning vs hard reject

If you'd rather warn than block on certain outcomes (e.g. accept catch-all but flag for human review):

```python
from email_verifier import verify, api_keys_from_env

v = verify(email, api_keys=api_keys_from_env())

if v.exists == "no" or v.is_disposable:
    return reject("Invalid email")

if v.exists == "likely" and v.decided_by != "fallback":
    # catch-all — accept but mark for review
    user.email_needs_review = True

create_user(...)
```

---

## Error handling

The verifier never raises on user-facing errors:

- Malformed email → `Verdict(exists="no", decided_by="syntax")`
- Network failure to one provider → that provider's `ProviderReading.result == "error"`, chain walks to the next
- All providers fail → `Verdict(exists="likely", decided_by="fallback")` — `is_verified` returns False
- DNS lookup fails → `Verdict(exists="no", decided_by="mx")` (treated same as no MX records)

You don't need a `try/except` around `is_verified()` or `verify()` for normal operation.

The only exceptions that *could* leak out are programmer errors (e.g. passing `None` for email). Wrap in `try` if you're paranoid about defensive coding:

```python
try:
    ok = is_verified(email)
except Exception:
    log.exception("verification failed")
    ok = False
```

---

## Quotas and rate limits

| Provider | Free quota | Reset |
|---|---|---|
| QuickEmailVerification | 100/day | Daily (UTC midnight) |
| MyEmailVerifier | 100/day | Daily |
| Abstract API | 100/month | Monthly (signup anniversary) |
| Mailboxlayer | 100/month | Monthly |
| Hunter.io | ~100/month | Monthly |
| **Combined** | **~6300/month** | (auto) |

The chain runs providers in priority order (largest quota first), so most verifications consume just one QEV credit. The other providers are fallbacks consulted only when QEV times out, returns "unknown", or is rate-limited.

Caching: the verifier does **not** cache results. If you verify the same email twice in a short window, you'll consume two credits. If your prod system has a database, persist the verdict for ~24 hours next to the user record to avoid re-checking.

```python
def verify_with_cache(email: str, db) -> bool:
    cached = db.email_verifications.find_recent(email, max_age_hours=24)
    if cached:
        return cached.is_verified
    ok = is_verified(email)
    db.email_verifications.insert(email=email, is_verified=ok, ts=now())
    return ok
```

---

## Security

- API keys are passed only as `params={...}` to httpx — never spliced into URLs by hand. They're URL-encoded by httpx and never appear in our log statements.
- Error messages from third-party libraries are sanitized with `_sanitize()` to strip any `?key=value` query strings before being surfaced — defense-in-depth in case a future SDK behavior leaks URLs.
- Uncaught exceptions in the chain are logged by **type only** (e.g. `RuntimeError`), never by message.
- Test mocks use `monkeypatch` against `httpx`/`dns.resolver` — no test makes a live network call.

If you turn on Python's `logging` at DEBUG level, the only thing that surfaces from `email_verifier` is `MX lookup failed for <domain>: <reason>` — no API keys involved.

---

## What if my team adds another provider later?

To add a sixth provider:

1. Add a `query_<name>(email, api_key) -> ProviderReading` function in `providers.py`. Map the upstream response to one of `valid` / `invalid` / `unknown` / `error`.
2. Register it in the `PROVIDERS` list with the right priority slot. The chain order matters — daily-reset providers go before monthly-reset.
3. Add tests in `tests/test_providers.py` for the response mapping (use `_mock_httpx` or `_mock_httpx_raw`).
4. Document the env var in `.env.example`.

The orchestrator and `is_verified()` automatically pick up new providers — they iterate over `PROVIDERS` rather than referencing each by name.

---

## Questions / debugging

If a verification produces an unexpected verdict, run the CLI with `-v` (debug logs) or use the structured output:

```python
v = verify(email, api_keys=...)
print(v.to_dict())   # full JSON-able dict — provider trail, MX records, reasons
```

The `decided_by` field tells you *which step* produced the verdict — the most useful debugging signal.
