"""Tests for individual provider response mappings + security hardening."""
from __future__ import annotations

import json

import httpx
import pytest

from email_verifier import providers
from email_verifier.providers import (
    ProviderReading,
    _sanitize,
    query_abstract,
    query_hunter,
    query_mailboxlayer,
    query_mev,
    query_qev,
)


def _mock_httpx_raw(monkeypatch: pytest.MonkeyPatch, content: bytes, status_code: int = 200) -> None:
    """Mock httpx.get returning raw bytes (not necessarily valid JSON)."""
    def _get(url, *, params=None, timeout=None):
        return httpx.Response(
            status_code=status_code,
            content=content,
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(httpx, "get", _get)


def _mock_httpx(monkeypatch: pytest.MonkeyPatch, body: dict, status_code: int = 200) -> None:
    def _get(url, *, params=None, timeout=None):
        return httpx.Response(
            status_code=status_code,
            content=json.dumps(body).encode(),
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(httpx, "get", _get)


# ---------------------------------------------------------------------------
# Hunter
# ---------------------------------------------------------------------------

class TestHunter:

    def test_deliverable_maps_to_valid(self, monkeypatch):
        _mock_httpx(monkeypatch, {"data": {"result": "deliverable", "status": "valid", "score": 95}})
        r = query_hunter("u@x.com", "k")
        assert r.result == "valid"
        assert r.score == 95

    def test_undeliverable_maps_to_invalid(self, monkeypatch):
        _mock_httpx(monkeypatch, {"data": {"result": "undeliverable", "status": "invalid"}})
        assert query_hunter("u@x.com", "k").result == "invalid"

    @pytest.mark.parametrize("hunter_result", ["risky", "unknown", "", None])
    def test_other_results_map_to_unknown(self, monkeypatch, hunter_result):
        _mock_httpx(monkeypatch, {"data": {"result": hunter_result}})
        assert query_hunter("u@x.com", "k").result == "unknown"

    def test_4xx_returns_error(self, monkeypatch):
        _mock_httpx(monkeypatch, {"errors": []}, status_code=401)
        r = query_hunter("u@x.com", "bad")
        assert r.result == "error"

    def test_network_failure_returns_error(self, monkeypatch):
        def _raise(url, *, params=None, timeout=None):
            raise httpx.ConnectTimeout("DNS fail")

        monkeypatch.setattr(httpx, "get", _raise)
        r = query_hunter("u@x.com", "k")
        assert r.result == "error"


# ---------------------------------------------------------------------------
# QEV
# ---------------------------------------------------------------------------

class TestQev:

    def test_valid_with_accept_all(self, monkeypatch):
        _mock_httpx(monkeypatch, {"result": "valid", "accept_all": "true", "disposable": "false"})
        r = query_qev("u@x.com", "k")
        assert r.result == "valid"
        assert r.catch_all is True
        assert r.disposable is False

    def test_invalid(self, monkeypatch):
        _mock_httpx(monkeypatch, {"result": "invalid", "reason": "rejected_email"})
        r = query_qev("u@x.com", "k")
        assert r.result == "invalid"
        assert r.raw_status == "rejected_email"

    @pytest.mark.parametrize("qev_result", ["risky", "unknown", "", None])
    def test_other_results_map_to_unknown(self, monkeypatch, qev_result):
        _mock_httpx(monkeypatch, {"result": qev_result})
        assert query_qev("u@x.com", "k").result == "unknown"


# ---------------------------------------------------------------------------
# MyEmailVerifier
# ---------------------------------------------------------------------------

class TestMev:

    def test_valid(self, monkeypatch):
        _mock_httpx(monkeypatch, {
            "Address": "u@x.com",
            "Status": "Valid",
            "catch_all": "false",
            "Disposable_Domain": "false",
            "Role_Based": "false",
            "Free_Domain": "false",
            "Diagnosis": "Mailbox Exists and Active",
        })
        r = query_mev("u@x.com", "k")
        assert r.result == "valid"
        assert r.catch_all is False
        assert r.role is False
        assert r.raw_status == "Mailbox Exists and Active"

    def test_invalid(self, monkeypatch):
        _mock_httpx(monkeypatch, {"Status": "Invalid", "Diagnosis": "Mailbox Does Not Exist"})
        assert query_mev("u@x.com", "k").result == "invalid"

    def test_catch_all_status_maps_to_valid_with_catch_all_true(self, monkeypatch):
        _mock_httpx(monkeypatch, {
            "Status": "Catch-all",
            "catch_all": 1,
            "Diagnosis": "Catch all (may bounce if it is not known email)",
        })
        r = query_mev("u@x.com", "k")
        assert r.result == "valid"
        assert r.catch_all is True

    @pytest.mark.parametrize("status", ["Greylisted", "Unknown", ""])
    def test_other_statuses_map_to_unknown(self, monkeypatch, status):
        _mock_httpx(monkeypatch, {"Status": status})
        assert query_mev("u@x.com", "k").result == "unknown"


# ---------------------------------------------------------------------------
# Abstract API
# ---------------------------------------------------------------------------

class TestAbstract:

    def test_deliverable_maps_to_valid(self, monkeypatch):
        _mock_httpx(monkeypatch, {
            "deliverability": "DELIVERABLE",
            "is_disposable_email": {"value": False},
            "is_role_email": {"value": False},
            "is_catchall_email": {"value": False},
            "quality_score": "0.95",
        })
        r = query_abstract("u@x.com", "k")
        assert r.result == "valid"
        assert r.catch_all is False
        assert r.score == 0.95

    def test_undeliverable_maps_to_invalid(self, monkeypatch):
        _mock_httpx(monkeypatch, {"deliverability": "UNDELIVERABLE"})
        assert query_abstract("u@x.com", "k").result == "invalid"

    def test_unknown_maps_to_unknown(self, monkeypatch):
        _mock_httpx(monkeypatch, {"deliverability": "UNKNOWN"})
        assert query_abstract("u@x.com", "k").result == "unknown"

    def test_handles_flat_boolean_form(self, monkeypatch):
        # Some tiers return flat booleans instead of {value, text} objects
        _mock_httpx(monkeypatch, {
            "deliverability": "DELIVERABLE",
            "is_catchall_email": True,
        })
        r = query_abstract("u@x.com", "k")
        assert r.catch_all is True


# ---------------------------------------------------------------------------
# Mailboxlayer
# ---------------------------------------------------------------------------

class TestMailboxlayer:

    def test_smtp_check_true_maps_to_valid(self, monkeypatch):
        _mock_httpx(monkeypatch, {
            "format_valid": True, "mx_found": True, "smtp_check": True,
            "catch_all": False, "score": 0.8,
        })
        r = query_mailboxlayer("u@x.com", "k")
        assert r.result == "valid"
        assert r.catch_all is False
        assert r.score == 0.8

    def test_smtp_check_false_maps_to_invalid(self, monkeypatch):
        _mock_httpx(monkeypatch, {
            "format_valid": True, "mx_found": True, "smtp_check": False,
        })
        assert query_mailboxlayer("u@x.com", "k").result == "invalid"

    def test_no_mx_maps_to_invalid(self, monkeypatch):
        _mock_httpx(monkeypatch, {
            "format_valid": True, "mx_found": False, "smtp_check": False,
        })
        assert query_mailboxlayer("u@x.com", "k").result == "invalid"

    def test_format_invalid_maps_to_invalid(self, monkeypatch):
        _mock_httpx(monkeypatch, {
            "format_valid": False, "mx_found": False, "smtp_check": False,
        })
        assert query_mailboxlayer("u@x.com", "k").result == "invalid"

    def test_smtp_check_null_maps_to_unknown(self, monkeypatch):
        _mock_httpx(monkeypatch, {
            "format_valid": True, "mx_found": True, "smtp_check": None,
        })
        assert query_mailboxlayer("u@x.com", "k").result == "unknown"

    def test_apilayer_error_payload(self, monkeypatch):
        _mock_httpx(monkeypatch, {
            "success": False,
            "error": {"code": 101, "info": "invalid access key"},
        })
        r = query_mailboxlayer("u@x.com", "bad")
        assert r.result == "error"
        assert "invalid access key" in (r.error or "")


# ---------------------------------------------------------------------------
# Chain ordering
# ---------------------------------------------------------------------------

def test_run_chain_skips_unconfigured_providers(monkeypatch):
    # Mock every provider function to track calls
    calls: list[str] = []

    def _make(provider_id):
        def _q(email, key):
            calls.append(provider_id)
            return ProviderReading(provider=provider_id, result="unknown")
        return _q

    monkeypatch.setattr(providers, "query_qev", _make("qev"))
    monkeypatch.setattr(providers, "query_mev", _make("mev"))
    monkeypatch.setattr(providers, "query_abstract", _make("abstract"))
    monkeypatch.setattr(providers, "query_mailboxlayer", _make("mailboxlayer"))
    monkeypatch.setattr(providers, "query_hunter", _make("hunter"))

    # Re-build PROVIDERS table to use our mocks
    monkeypatch.setattr(providers, "PROVIDERS", [
        ("qev", _make("qev"), "QEV_API_KEY", 3000, "daily"),
        ("mev", _make("mev"), "MEV_API_KEY", 3000, "daily"),
        ("hunter", _make("hunter"), "HUNTER_API_KEY", 100, "monthly"),
    ])

    readings = providers.run_chain("u@x.com", api_keys={"qev": "k1", "hunter": "k3"})
    assert [r.provider for r in readings] == ["qev", "hunter"]


def test_run_chain_short_circuits_on_definitive(monkeypatch):
    calls: list[str] = []

    def _qev(email, key):
        calls.append("qev")
        return ProviderReading(provider="qev", result="valid", catch_all=False)

    def _hunter(email, key):
        calls.append("hunter")
        return ProviderReading(provider="hunter", result="valid")

    monkeypatch.setattr(providers, "PROVIDERS", [
        ("qev", _qev, "QEV_API_KEY", 3000, "daily"),
        ("hunter", _hunter, "HUNTER_API_KEY", 100, "monthly"),
    ])

    readings = providers.run_chain("u@x.com", api_keys={"qev": "k", "hunter": "k"})
    assert calls == ["qev"]
    assert len(readings) == 1


def test_run_chain_swallows_uncaught_exception_without_leaking(monkeypatch):
    """If a provider's query function raises, run_chain converts to error
    without including the exception message (defense-in-depth: any URL inside
    the message could carry the API key)."""
    def _broken(email, key):
        raise RuntimeError(
            "request failed: GET https://api.example.com/?api_key=SECRET_LEAK"
        )

    monkeypatch.setattr(providers, "PROVIDERS", [
        ("qev", _broken, "QEV_API_KEY", 3000, "daily"),
    ])

    readings = providers.run_chain("u@x.com", api_keys={"qev": "secret_key"})
    assert len(readings) == 1
    err = readings[0].error or ""
    assert readings[0].result == "error"
    assert "SECRET_LEAK" not in err
    assert "secret_key" not in err
    # Should still indicate WHAT type of error happened
    assert "RuntimeError" in err


# ---------------------------------------------------------------------------
# Security hardening
# ---------------------------------------------------------------------------

class TestSanitize:

    def test_strips_query_string(self):
        msg = "Failed: https://api.example.com/v1/check?api_key=ABCD1234&email=x@y.com"
        out = _sanitize(msg)
        assert "ABCD1234" not in out
        assert "?[redacted]" in out

    def test_strips_apikey_param_variants(self):
        for s in [
            "https://x/?apikey=SECRET",
            "https://x/?api_key=SECRET&z=1",
            "https://x/?access_key=SECRET",
        ]:
            assert "SECRET" not in _sanitize(s)

    def test_caps_length(self):
        out = _sanitize("x" * 1000, max_len=100)
        assert len(out) <= 105  # 100 + "..." cushion

    def test_handles_non_string(self):
        # Exception object instead of str — should still work
        exc = ValueError("boom")
        assert "boom" in _sanitize(exc)


class TestMalformedJson:

    @pytest.mark.parametrize("provider_fn", [
        query_hunter, query_qev, query_mev, query_abstract, query_mailboxlayer,
    ])
    def test_garbage_body_returns_error(self, monkeypatch, provider_fn):
        # Non-empty body, but not valid JSON
        _mock_httpx_raw(monkeypatch, content=b"<html>oops a 200 with HTML</html>")
        r = provider_fn("u@x.com", "k")
        assert r.result == "error"
        assert "malformed JSON" in (r.error or "")

    @pytest.mark.parametrize("provider_fn", [
        query_hunter, query_qev, query_mev, query_abstract, query_mailboxlayer,
    ])
    def test_empty_body_does_not_crash(self, monkeypatch, provider_fn):
        # Empty body is permissible — most providers won't return this, but it
        # shouldn't crash. Result depends on the provider's parser.
        _mock_httpx_raw(monkeypatch, content=b"")
        r = provider_fn("u@x.com", "k")
        # No exception is the test — result should be a ProviderReading
        assert isinstance(r, ProviderReading)


class TestErrorBodySanitization:

    def test_4xx_response_text_is_sanitized(self, monkeypatch):
        # Imagine an upstream error page that echoes back the request URL
        # with the API key in the query string.
        leaky = b"500 Server error for url 'https://api.x/?api_key=LEAKED'"
        _mock_httpx_raw(monkeypatch, content=leaky, status_code=500)
        r = query_hunter("u@x.com", "k")
        assert r.result == "error"
        assert "LEAKED" not in (r.error or "")
