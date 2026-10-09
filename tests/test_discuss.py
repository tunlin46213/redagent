"""Analyst<->executor discussion: proposal parsing, config flag, deep-dive round."""

import textwrap
import types

from redagent import analyst, hunt
from redagent.config import Config
from redagent.scope import Scope


def test_propose_parses_fenced_json_and_skips_malformed(monkeypatch):
    monkeypatch.setattr(analyst, "_complete", lambda *a, **k:
                        '```json\n[{"tool":"sql_test","url":"http://h/x?q=1","why":"r"},'
                        '{"nope":1}]\n```')
    out = analyst.propose(types.SimpleNamespace(), "findings", ["sql_test"])
    assert len(out) == 1 and out[0]["tool"] == "sql_test" and out[0]["url"] == "http://h/x?q=1"


def test_propose_empty_on_garbage(monkeypatch):
    monkeypatch.setattr(analyst, "_complete", lambda *a, **k: "sorry, no JSON here")
    assert analyst.propose(types.SimpleNamespace(), "f", ["sql_test"]) == []


def test_config_deep_dive_flag(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent("""
        llm:
          deep_dive: true
        scope:
          allowed_targets: [localhost]
    """))
    assert Config(str(p)).deep_dive is True
    p.write_text("scope:\n  allowed_targets: [localhost]\n")
    assert Config(str(p)).deep_dive is False


def test_deep_dive_executes_valid_skips_bad(monkeypatch):
    # analyst proposes: one valid in-scope, one unknown tool, one out-of-scope
    monkeypatch.setattr(analyst, "propose", lambda cfg, rep, names: [
        {"tool": "fetch_url", "url": "http://localhost:3001/ftp/secret.bak", "why": "leak"},
        {"tool": "bogus_tool", "url": "http://localhost:3001/x", "why": "?"},
        {"tool": "fetch_url", "url": "http://evil.example/x.bak", "why": "oob"},
    ])
    monkeypatch.setattr(analyst, "review_results", lambda cfg, txt: "one new leak confirmed.")

    calls = []
    def fake_fetch(url):
        calls.append(url)
        return "HTTP 200\n\nsecret data"
    tools = {"fetch_url": fake_fetch}

    cfg = types.SimpleNamespace(scope=Scope(["localhost", "127.0.0.1"]),
                               analyst_model="deephat")
    findings = [hunt.Finding("sqli", "u", "critical", "x")]
    seen = set()
    md = hunt._deep_dive(cfg, "http://localhost:3001", tools, findings, seen,
                         emit=lambda s: None)

    # only the valid in-scope fetch ran; unknown tool + out-of-scope skipped
    assert calls == ["http://localhost:3001/ftp/secret.bak"]
    assert any(f.vuln_class == "deep-dive" for f in findings)        # new finding folded in
    assert "Deep-dive" in md and "SKIP unknown tool" in md and "out-of-scope" in md
    assert "Analyst verdict" in md
