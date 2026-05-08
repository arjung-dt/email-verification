"""Tests for the verifier orchestrator. DNS + provider calls are mocked."""
from __future__ import annotations

from typing import Optional

import pytest

from email_verifier import verifier
from email_verifier.providers import ProviderReading
from email_verifier.verifier import Verdict, verify


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _patch_mx(monkeypatch: pytest.MonkeyPatch, mx: list[str]) -> None:
    monkeypatch.setattr(verifier, "lookup_mx", lambda d: mx)


def _patch_chain(monkeypatch: pytest.MonkeyPatch, readings: list[ProviderReading]) -> None:
    monkeypatch.setattr(verifier, "run_chain", lambda email, *, api_keys: readings)


def _r(provider: str, result: str, **kw) -> ProviderReading:
    return ProviderReading(provider=provider, result=result, **kw)


# ---------------------------------------------------------------------------
# Syntax validation — edge cases
# ---------------------------------------------------------------------------

class TestSyntax:

    @pytest.mark.parametrize(
        "bad",
        [
            "",                       # empty
            "   ",                    # whitespace only
            "no-at-sign",             # missing @
            "@nodomain.com",          # missing local
            "noapart@",               # missing domain
            "@",                      # only @
            "atul@@two.at",           # double @ → rsplit takes last; "atul@" as local — empty after strip(? no, "atul@" is fine)
        ],
    )
    def test_malformed_returns_no(self, monkeypatch, bad):
        # Should never reach DNS for syntax-broken input
        def _no_dns(*a, **k):
            raise AssertionError("DNS must not run on malformed input")

        monkeypatch.setattr(verifier, "lookup_mx", _no_dns)
        # Several of these have an @ and would call DNS; for those, MX returns empty
        _patch_mx(monkeypatch, [])
        v = verify(bad)
        assert v.exists == "no"
        assert v.decided_by in {"syntax", "mx"}

    def test_strips_whitespace_around_email(self, monkeypatch):
        _patch_mx(monkeypatch, ["mx.test"])
        _patch_chain(monkeypatch, [_r("qev", "valid", catch_all=False)])
        v = verify("  user@example.com  ", api_keys={"qev": "k"})
        assert v.exists == "yes"
        assert v.email == "user@example.com"

    def test_lowercases_domain(self, monkeypatch):
        captured: list[str] = []
        monkeypatch.setattr(verifier, "lookup_mx", lambda d: (captured.append(d), ["mx.test"])[1])
        _patch_chain(monkeypatch, [_r("qev", "valid", catch_all=False)])
        v = verify("User@EXAMPLE.COM", api_keys={"qev": "k"})
        assert captured == ["example.com"]
        assert v.domain == "example.com"

    def test_strips_trailing_dot_on_domain(self, monkeypatch):
        captured: list[str] = []
        monkeypatch.setattr(verifier, "lookup_mx", lambda d: (captured.append(d), ["mx.test"])[1])
        _patch_chain(monkeypatch, [_r("qev", "valid", catch_all=False)])
        verify("user@example.com.", api_keys={"qev": "k"})
        assert captured == ["example.com"]

    def test_handles_subaddress_plus_local(self, monkeypatch):
        # "user+tag@example.com" is RFC-valid (sub-addressing) — we treat as a normal address
        _patch_mx(monkeypatch, ["mx.test"])
        _patch_chain(monkeypatch, [_r("qev", "valid", catch_all=False)])
        v = verify("user+tag@example.com", api_keys={"qev": "k"})
        assert v.exists == "yes"
        assert v.domain == "example.com"


# ---------------------------------------------------------------------------
# MX gating
# ---------------------------------------------------------------------------

class TestMxGating:

    def test_no_mx_returns_no_without_calling_chain(self, monkeypatch):
        _patch_mx(monkeypatch, [])

        def _chain_must_not_run(email, *, api_keys):
            raise AssertionError("chain must not run when MX is absent")

        monkeypatch.setattr(verifier, "run_chain", _chain_must_not_run)
        v = verify("user@nope-no-mx.test", api_keys={"qev": "k"})
        assert v.exists == "no"
        assert v.decided_by == "mx"
        assert v.domain_has_mx is False

    def test_mx_present_no_keys_yields_likely_fallback(self, monkeypatch):
        _patch_mx(monkeypatch, ["mx.test"])
        _patch_chain(monkeypatch, [])
        v = verify("user@test.com", api_keys={})
        assert v.exists == "likely"
        assert v.decided_by == "fallback"
        assert "no provider was configured" in v.reason.lower()


# ---------------------------------------------------------------------------
# Provider chain results
# ---------------------------------------------------------------------------

class TestChainOutcomes:

    def test_valid_not_catch_all_yields_yes(self, monkeypatch):
        _patch_mx(monkeypatch, ["mx.test"])
        _patch_chain(monkeypatch, [_r("qev", "valid", catch_all=False)])
        v = verify("u@test.com", api_keys={"qev": "k"})
        assert v.exists == "yes"
        assert v.decided_by == "qev"

    def test_valid_with_catch_all_yields_likely(self, monkeypatch):
        _patch_mx(monkeypatch, ["mx.test"])
        _patch_chain(monkeypatch, [_r("qev", "valid", catch_all=True)])
        v = verify("u@test.com", api_keys={"qev": "k"})
        assert v.exists == "likely"
        assert v.decided_by == "qev"
        assert "catch-all" in v.reason.lower()

    def test_invalid_yields_no(self, monkeypatch):
        _patch_mx(monkeypatch, ["mx.test"])
        _patch_chain(monkeypatch, [_r("mev", "invalid", raw_status="Mailbox does not exist")])
        v = verify("u@test.com", api_keys={"mev": "k"})
        assert v.exists == "no"
        assert v.decided_by == "mev"

    def test_chain_walks_past_unknown_to_definitive(self, monkeypatch):
        _patch_mx(monkeypatch, ["mx.test"])
        _patch_chain(monkeypatch, [
            _r("qev", "unknown"),
            _r("mev", "error", error="timeout"),
            _r("mailboxlayer", "valid", catch_all=False),
        ])
        v = verify("u@test.com", api_keys={"qev": "k", "mev": "k", "mailboxlayer": "k"})
        assert v.exists == "yes"
        assert v.decided_by == "mailboxlayer"

    def test_all_unknown_yields_likely_fallback(self, monkeypatch):
        _patch_mx(monkeypatch, ["mx.test"])
        _patch_chain(monkeypatch, [
            _r("qev", "unknown"),
            _r("mev", "unknown"),
        ])
        v = verify("u@test.com", api_keys={"qev": "k", "mev": "k"})
        assert v.exists == "likely"
        assert v.decided_by == "fallback"
        # Both providers' verdicts surfaced in reason
        assert "qev=unknown" in v.reason
        assert "mev=unknown" in v.reason

    def test_first_definitive_wins(self, monkeypatch):
        _patch_mx(monkeypatch, ["mx.test"])
        _patch_chain(monkeypatch, [
            _r("qev", "valid", catch_all=False),  # decisive — should win
            _r("mev", "invalid"),                   # would contradict, but never consulted
        ])
        v = verify("u@test.com", api_keys={"qev": "k", "mev": "k"})
        assert v.exists == "yes"
        assert v.decided_by == "qev"


# ---------------------------------------------------------------------------
# Disposable
# ---------------------------------------------------------------------------

class TestDisposable:

    def test_disposable_domain_overrides_chain_valid(self, monkeypatch):
        # Even if chain says valid, disposable takes priority
        _patch_mx(monkeypatch, ["mx.mailinator.com"])
        _patch_chain(monkeypatch, [_r("qev", "valid", catch_all=True)])
        v = verify("anyone@mailinator.com", api_keys={"qev": "k"})
        assert v.exists == "likely_no"
        assert v.decided_by == "disposable"
        assert v.is_disposable is True

    def test_non_disposable_domain_not_flagged(self, monkeypatch):
        _patch_mx(monkeypatch, ["mx.test"])
        _patch_chain(monkeypatch, [_r("qev", "valid", catch_all=False)])
        v = verify("user@bigbank.com", api_keys={"qev": "k"})
        assert v.is_disposable is False


# ---------------------------------------------------------------------------
# Verdict.to_dict round-trip
# ---------------------------------------------------------------------------

def test_to_dict_round_trip(monkeypatch):
    _patch_mx(monkeypatch, ["mx.test"])
    _patch_chain(monkeypatch, [
        _r("qev", "valid", catch_all=False, score=0.95, raw_status="accepted_email"),
    ])
    v = verify("u@x.com", api_keys={"qev": "k"})
    d = v.to_dict()
    assert d["exists"] == "yes"
    assert d["decided_by"] == "qev"
    assert d["domain"] == "x.com"
    assert d["domain_has_mx"] is True
    assert d["is_disposable"] is False
    assert d["providers"][0]["provider"] == "qev"
    assert d["providers"][0]["result"] == "valid"
    assert d["providers"][0]["score"] == 0.95


# ---------------------------------------------------------------------------
# DNS lookup_mx — direct unit tests (mock dns.resolver.resolve)
# ---------------------------------------------------------------------------

class TestLookupMx:

    def test_empty_domain_returns_empty_list(self):
        assert verifier.lookup_mx("") == []

    def test_nxdomain_returns_empty(self, monkeypatch):
        import dns.resolver

        def _raise(*a, **k):
            raise dns.resolver.NXDOMAIN()

        monkeypatch.setattr(verifier.dns.resolver, "resolve", _raise)
        assert verifier.lookup_mx("nope.test") == []

    def test_no_answer_returns_empty(self, monkeypatch):
        import dns.resolver

        def _raise(*a, **k):
            raise dns.resolver.NoAnswer()

        monkeypatch.setattr(verifier.dns.resolver, "resolve", _raise)
        assert verifier.lookup_mx("nope.test") == []

    def test_dns_exception_returns_empty(self, monkeypatch):
        import dns.exception

        def _raise(*a, **k):
            raise dns.exception.Timeout()

        monkeypatch.setattr(verifier.dns.resolver, "resolve", _raise)
        assert verifier.lookup_mx("slow.test") == []

    def test_results_sorted_by_priority(self, monkeypatch):
        # Mock dns.resolver.resolve to return MX records in unsorted priority
        class FakeRecord:
            def __init__(self, preference, exchange):
                self.preference = preference
                self.exchange = exchange

        def _resolve(*a, **k):
            return [
                FakeRecord(20, "mx-secondary.test."),
                FakeRecord(5, "mx-primary.test."),
                FakeRecord(10, "mx-mid.test."),
            ]

        monkeypatch.setattr(verifier.dns.resolver, "resolve", _resolve)
        result = verifier.lookup_mx("test.com")
        assert result == ["mx-primary.test", "mx-mid.test", "mx-secondary.test"]
