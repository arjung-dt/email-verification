# email-verifier

Free, no-credit-card-required email-existence verifier. Asks five HTTPS-based providers in priority order; stops at the first definitive answer.

```
exists: YES        → confirmed real (mailbox accepts mail and is not catch-all)
exists: LIKELY     → domain accepts mail but server is catch-all
exists: LIKELY_NO  → known disposable / throwaway provider
exists: NO         → no MX records, OR a provider explicitly rejected the address
```

The verification chain is layered and short-circuiting:

```
1. Syntax check                  (local, instant, free)
2. DNS MX lookup                 (free, unlimited; definitive "no" if no MX)
3. Disposable-domain list        (free, unlimited; ~80 known providers)
4. HTTPS provider chain          (port 443; works on AWS / GCP / Azure / anywhere)
   QuickEmailVerification → MyEmailVerifier → Abstract → Mailboxlayer → Hunter
5. Fall back to "likely"
```

You only spend an API credit when steps 1–3 don't resolve the case. Most "definitive no" verdicts (no MX, disposable) cost zero quota.

## Free-tier capacity (combined ~6300 verifications/month)

| Provider | Free tier | Reset | Card? | Signup |
|---|---|---|---|---|
| **QuickEmailVerification** | 100/day = ~3000/month | Daily | No | [quickemailverification.com](https://quickemailverification.com) |
| **MyEmailVerifier**        | 100/day = ~3000/month | Daily | No | [myemailverifier.com](https://myemailverifier.com) |
| **Abstract API**           | 100/month             | Monthly | No | [abstractapi.com](https://www.abstractapi.com/api/email-verification-validation-api) |
| **Mailboxlayer**           | 100/month             | Monthly | No | [mailboxlayer.com](https://mailboxlayer.com) |
| **Hunter.io**              | ~100/month            | Monthly | No | [hunter.io](https://hunter.io) |
| **TOTAL**                  | **~6300 / month**     | (auto) | **None required** | — |

All five providers reset their free tier automatically with no payment ever required. Only an API key is needed.

## Setup

Requires Python 3.12+ and [`uv`](https://docs.astral.sh/uv/).

```bash
# Install uv (one-time)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone + install
git clone <this-repo>
cd email-verifier
uv sync

# Run tests
uv run pytest -q
```

## Configure providers

Copy `.env.example` to `.env` and fill in whichever keys you have. The chain skips any provider whose key is missing — partial configs are fine.

```bash
cp .env.example .env
# edit .env, then:
set -a && source .env && set +a   # exports the keys into the current shell
```

Or just export inline:

```bash
export QEV_API_KEY=your_qev_key
export MEV_API_KEY=your_mev_key
export ABSTRACT_API_KEY=your_abstract_key
export MAILBOXLAYER_API_KEY=your_mailboxlayer_key
export HUNTER_API_KEY=your_hunter_key
```

## Usage

```bash
# Pretty CLI output
uv run email-verify atul@venndata.ai

# Raw JSON
uv run email-verify atul@venndata.ai --json

# Verbose (debug logging)
uv run email-verify atul@venndata.ai -v
```

## Verdict matrix

| Step | Result | Verdict |
|---|---|---|
| Syntax | Malformed | `no` |
| MX lookup | No records | `no` |
| Disposable | Domain on list | `likely_no` |
| Provider says `valid` + not catch-all | — | `yes` |
| Provider says `valid` + catch-all | — | `likely` |
| Provider says `invalid` | — | `no` |
| All providers `unknown` / no providers configured | — | `likely` |

The `Verdict.decided_by` field tells you which step decided: `syntax` / `mx` / `disposable` / `qev` / `mev` / `abstract` / `mailboxlayer` / `hunter` / `fallback`.

## Provider chain order + failure behavior

The chain runs in priority order, **stopping at the first definitive answer**. Order is intentional — providers with the largest daily / monthly quota go first so we burn the cheapest credit before falling back.

```
1. QEV          (3000/mo, daily reset)   ← primary
2. MEV          (3000/mo, daily reset)
3. Abstract     (100/mo,  monthly reset)
4. Mailboxlayer (100/mo,  monthly reset)
5. Hunter       (~100/mo, monthly reset)
```

**If a provider fails** (HTTP 401 bad key / network timeout / 5xx / malformed JSON), it's recorded as `provider:error` and the chain walks to the next one. A failure never breaks verification — only changes which provider answered.

## What "likely" means in practice

`likely` means the **domain accepts mail but per-mailbox confirmation isn't possible** — usually because the mail server is catch-all (Google Workspace catch-all, Microsoft 365 catch-all). In real-world terms: mail will arrive at someone's inbox, but we can't distinguish a real mailbox from a typo at this domain.

Practical handling for KYC / signup flows:
1. Send a confirmation email with a magic-link / OTP (gold-standard regardless).
2. Treat `likely` as "passed but flag for human review."
3. Trust it (mail will be delivered).

## Library use (integrating into another project)

The simple boolean interface — recommended for production integrations:

```python
from email_verifier import is_verified

if is_verified("user@example.com"):
    # mailbox is real (or catch-all) — accept
    create_account(...)
else:
    # disposable / malformed / rejected / not verifiable — reject
    return error("Please use a valid email address.")
```

API keys are read from environment variables automatically. For the full structured result (per-provider trail, reasons, MX records, etc.) use `verify()` directly.

**See [INTEGRATION.md](./INTEGRATION.md) for full integration patterns** — signup flows, async, batch, error handling, caching, and security notes.

```python
from email_verifier import verify, api_keys_from_env

v = verify("officer@bigbank.com", api_keys=api_keys_from_env())
print(v.exists, "decided by", v.decided_by)
print(v.reason)
for r in v.provider_readings:
    print(f"  {r.provider}: {r.result}", r.error or "")
```

## Layout

```
email_verifier/
  email_verifier/
    __init__.py
    disposable.py    # vendored throwaway-provider list (~80 domains)
    providers.py     # 5 HTTPS provider integrations + run_chain
    verifier.py      # syntax + MX + disposable + chain orchestrator + Verdict
    cli.py           # `email-verify <addr>`
  tests/
    test_verifier.py     # orchestrator + edge-case tests
    test_providers.py    # per-provider response mapping + security hardening
  pyproject.toml
  .env.example
  README.md
```

## Security

- API keys are passed via `httpx`'s `params=` (URL-encoded), never spliced into URLs by hand. They never appear in our log statements.
- Error messages from third-party libraries are run through `_sanitize()` which strips `?key=value` query strings — defense-in-depth in case any future SDK behavior surfaces a URL with credentials.
- Uncaught exceptions in the provider chain are logged by **type only** (e.g. `RuntimeError`), never by message — same reason.
- 4xx/5xx response bodies from providers are sanitized before being included in error fields.
- All test mocks use `monkeypatch` against `httpx`/`dns.resolver`; no test makes a live network call.

## Limitations

- **Catch-all domains** — fundamental SMTP-protocol limit; affects every email-verification service. Verdict will be `likely`, not `yes`.
- **Provider disagreements** — when two providers contradict on edge-case mailboxes (rare), we trust the *first* definitive answer. Order is intentional: largest-quota services first.
- **Rate-limit responses** — if a provider returns HTTP 429 (rate-limited), it's treated as an error and the chain walks past it. Verdict shifts to whichever provider answers next.
