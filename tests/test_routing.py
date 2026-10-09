"""Exploit-intent detection + target extraction (chat/TUI -> hunt routing)."""

from redagent import modes


def test_exploit_intent_detects():
    for m in ("dump all database", "find sql vuln and exploit it", "pentest localhost",
              "exploit the sqli", "hack this", "scan for vulnerabilities"):
        assert modes.is_exploit_intent(m), m


def test_exploit_intent_ignores_plain_probes():
    for m in ("read the homepage headers", "fetch /ftp", "what is the server banner"):
        assert not modes.is_exploit_intent(m), m


def test_extract_target():
    assert modes.extract_target("dump db at http://localhost:3001/x") == "http://localhost:3001/x"
    assert modes.extract_target("exploit it") == ""
    assert modes.extract_target("scan https://shop.test:8443 now") == "https://shop.test:8443"
