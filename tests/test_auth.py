"""Authenticated-flow helpers: token extraction + optional auth config parsing."""

import textwrap

from redagent import hunt
from redagent.config import Config


def test_extract_token_from_json_field():
    body = 'HTTP 200\n\n{"authentication":{"token":"eyJhbGc.eyJ1c2Vy.sig-part"}}'
    assert hunt._extract_token(body) == "eyJhbGc.eyJ1c2Vy.sig-part"


def test_extract_token_none_when_absent():
    assert hunt._extract_token('{"status":"ok"}') == ""


def _write_cfg(tmp_path, body):
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent(body))
    return Config(str(p))


def test_config_auth_absent_is_none(tmp_path):
    cfg = _write_cfg(tmp_path, """
        scope:
          allowed_targets:
            - localhost
    """)
    assert cfg.auth is None


def test_config_auth_parsed(tmp_path):
    cfg = _write_cfg(tmp_path, """
        scope:
          allowed_targets:
            - localhost
        auth:
          login_url: "http://localhost:3001/rest/user/login"
          username: "u@example.com"
          password: "pw"
    """)
    assert cfg.auth["login_url"].endswith("/rest/user/login")
    assert cfg.auth["user_field"] == "email"   # default
    assert cfg.auth["pass_field"] == "password"
