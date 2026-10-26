"""Pure-logic tool helpers: param cleaning, nmap trim, and the jwt_test tool."""

import base64
import hashlib
import hmac
import json
import types

import pytest

from redagent import tools
from redagent.scope import Scope


# --- _clean_params: strips hand-typed payloads to a safe baseline ---

def test_clean_params_strips_sql():
    out = tools._clean_params("http://h/s?q=apple' AND '1'='1")
    assert out == "http://h/s?q=apple"


def test_clean_params_strips_xss_to_default():
    out = tools._clean_params("http://h/s?q=<script>alert(1)</script>")
    assert out.endswith("q=1")  # payload stripped, falls back to "1"


def test_clean_params_noop_without_query():
    assert tools._clean_params("http://h/path") == "http://h/path"


# --- _nmap_trim: drops the service-fingerprint noise, keeps the port table ---

def test_nmap_trim_keeps_ports_drops_fingerprints():
    raw = "\n".join([
        "PORT     STATE  SERVICE",
        "3000/tcp open   ppp?",
        "| fingerprint-strings: ",
        "|   GetRequest: ",
        "|     HTTP/1.1 200 OK",
        "|_    noise",
        "3001/tcp open   nessus?",
        "2 services unrecognized despite returning data. ...",
        "SF-Port3000-TCP:V=7.9%...",
        "SF:junkjunkjunk",
    ])
    out = tools._nmap_trim(raw)
    assert "3000/tcp open" in out and "3001/tcp open" in out
    assert "fingerprint-strings" not in out
    assert "SF:" not in out and "SF-Port" not in out


# --- jwt_test: alg:none + weak HMAC secret ---

def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _tools():
    cfg = types.SimpleNamespace(scope=Scope(["localhost"]), workspace="/tmp",
                                tool_timeout=5)
    return tools.build_tools(cfg)


def test_jwt_alg_none_flagged():
    tok = _b64(json.dumps({"alg": "none"}).encode()) + "." + \
        _b64(json.dumps({"u": "admin"}).encode()) + "."
    out = _tools()["jwt_test"](tok)
    assert "alg:none" in out.lower() or "CRITICAL" in out


def test_jwt_weak_secret_cracked():
    h = _b64(json.dumps({"alg": "HS256"}).encode())
    p = _b64(json.dumps({"u": "bob"}).encode())
    sig = _b64(hmac.new(b"secret", f"{h}.{p}".encode(), hashlib.sha256).digest())
    out = _tools()["jwt_test"](f"{h}.{p}.{sig}")
    assert "secret" in out and "weak" in out.lower()


def test_jwt_strong_secret_not_cracked():
    h = _b64(json.dumps({"alg": "HS256"}).encode())
    p = _b64(json.dumps({"u": "bob"}).encode())
    sig = _b64(hmac.new(b"Xq9!longrandom", f"{h}.{p}".encode(), hashlib.sha256).digest())
    out = _tools()["jwt_test"](f"{h}.{p}.{sig}")
    assert "no alg:none" in out.lower() or "no " in out.lower()


def test_jwt_rejects_non_token():
    assert "error" in _tools()["jwt_test"]("not-a-jwt").lower()


def test_no_placeholder_host_in_tool_docstrings():
    # the 7B copies example URLs from tool docstrings — keep placeholder hosts out
    for name, fn in _tools().items():
        doc = (fn.__doc__ or "").lower()
        for ph in ("example.com", "example.org", "example.net", "yourhost", "yourdomain"):
            assert ph not in doc, f"{name} docstring leaks placeholder host {ph!r}"


def test_scan_secrets_detects_high_signal():
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n"
        "aws_key = AKIAIOSFODNN7EXAMPLE\n"
        "api_key: 's3cr3tValue123'\n"
    )
    hits = tools.scan_secrets(text)
    labels = {label for _, label, _ in hits}
    assert "private key" in labels
    assert "AWS access key id" in labels
    assert "credential assignment" in labels
    # samples are redacted, never the raw secret
    assert all("AKIAIOSFODNN7EXAMPLE" not in s for _, _, s in hits)


def test_scan_secrets_clean_text_empty():
    assert tools.scan_secrets("just an ordinary page with no secrets here") == []


def test_naabu_ports_parses_and_dedups():
    out = ("[INF] Running CONNECT scan\n"
           "localhost:443\nlocalhost:80\nlocalhost:3001\nlocalhost:80\n"
           "scanning...\nbadline\n")
    assert tools._naabu_ports(out) == [80, 443, 3001]
    assert tools._naabu_ports("[INF] no ports\n") == []


def test_cors_verdict_reflected_with_credentials_is_critical():
    v = tools._cors_verdict("https://evil.example", "https://evil.example", "true")
    assert v.startswith("CRITICAL:")


def test_cors_verdict_reflected_no_credentials_is_high():
    v = tools._cors_verdict("https://evil.example", "https://evil.example", None)
    assert v.startswith("HIGH:")


def test_cors_verdict_wildcard_and_null():
    assert tools._cors_verdict("https://evil.example", "*", None).startswith("MEDIUM:")
    assert tools._cors_verdict("null", "null", "true").startswith("HIGH:")
    # a properly scoped ACAO (echoes nothing attacker-controlled) is not a finding
    assert tools._cors_verdict("https://evil.example", "https://trusted.site", "true") is None
    assert tools._cors_verdict("https://evil.example", None, None) is None


def test_header_audit_missing_csp_is_medium():
    sev, summary = tools._header_audit("http://h/", {"X-Frame-Options": "DENY"})
    assert sev == "medium" and "CSP" in summary


def test_header_audit_https_flags_hsts_and_leaks():
    sev, summary = tools._header_audit(
        "https://h/", {"Content-Security-Policy": "default-src 'self'",
                       "X-Frame-Options": "DENY", "Server": "nginx/1.0"})
    assert sev == "medium" and "HSTS" in summary and "nginx/1.0" in summary


def test_header_audit_frame_ancestors_satisfies_xfo_and_clean_is_none():
    # CSP frame-ancestors covers X-Frame-Options; a fully-hardened response -> None
    assert tools._header_audit("http://h/", {
        "Content-Security-Policy": "frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer"}) is None


def test_is_graphql_response_distinguishes_from_spa():
    assert tools._is_graphql_response({"data": {"__typename": "Query"}})
    assert tools._is_graphql_response({"errors": [{"message": "bad query"}]})
    # an HTML SPA 200 (not JSON) or an empty/odd body is NOT GraphQL
    assert not tools._is_graphql_response("<!doctype html>...")
    assert not tools._is_graphql_response(None)
    assert not tools._is_graphql_response({"data": {"products": []}})


def test_graphql_type_count():
    resp = {"data": {"__schema": {"types": [{"name": "Query"}, {"name": "User"}]}}}
    assert tools._graphql_type_count(resp) == 2
    assert tools._graphql_type_count({"data": {}}) is None
    assert tools._graphql_type_count(None) is None


def test_vary_id_path_and_query():
    varied, oid = tools._vary_id("http://h/api/Users/5")
    assert oid == 5 and ("http://h/api/Users/6" in [u for _, u in varied])
    varied2, oid2 = tools._vary_id("http://h/rest/basket?id=3&x=a")
    assert oid2 == 3 and any("id=4" in u for _, u in varied2)
    assert tools._vary_id("http://h/api/Users/me") == (None, 0)


def test_idor_verdict_sensitive_is_high_public_is_low():
    sensitive = [(1, 200, '{"email":"a@x"}'), (2, 200, '{"email":"b@x"}')]
    assert tools._idor_verdict(sensitive)[0] == "high"
    public = [(1, 200, '{"name":"Apple"}'), (2, 200, '{"name":"Banana"}')]
    assert tools._idor_verdict(public)[0] == "low"
    # identical bodies or 401s -> no indicator
    assert tools._idor_verdict([(1, 200, "same"), (2, 200, "same")]) is None
    assert tools._idor_verdict([(1, 401, ""), (2, 401, "")]) is None
