"""Analyst pass: config parsing + graceful failure (never breaks the report)."""

import textwrap
import types

from redagent import analyst
from redagent.config import Config


def _cfg(tmp_path, body):
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent(body))
    return Config(str(p))


def test_analyst_model_defaults_to_model(tmp_path):
    cfg = _cfg(tmp_path, """
        llm:
          model: "qwen2.5:7b"
        scope:
          allowed_targets: [localhost]
    """)
    assert cfg.analyst_model == "qwen2.5:7b"
    assert cfg.analyst_timeout == 300


def test_analyst_model_parsed(tmp_path):
    cfg = _cfg(tmp_path, """
        llm:
          model: "qwen2.5:7b"
          analyst_model: "deephat"
          analyst_timeout: 60
        scope:
          allowed_targets: [localhost]
    """)
    assert cfg.analyst_model == "deephat" and cfg.analyst_timeout == 60


def test_analyze_empty_findings_returns_empty():
    cfg = types.SimpleNamespace(analyst_model="x", base_url="http://127.0.0.1:1",
                                api_key="k", analyst_timeout=1)
    assert analyst.analyze(cfg, "   ") == ""


def test_analyze_unreachable_endpoint_is_graceful():
    # points at a dead port -> must return "" rather than raise
    cfg = types.SimpleNamespace(analyst_model="x", base_url="http://127.0.0.1:1/v1",
                                api_key="k", analyst_timeout=1)
    assert analyst.analyze(cfg, "### SQLI\n- Severity: Critical") == ""
