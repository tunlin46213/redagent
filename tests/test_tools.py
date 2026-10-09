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
