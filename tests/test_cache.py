"""Hunt cache: config TTL + save/load round-trip (reuse recon + findings)."""

import textwrap
import types

from redagent import hunt
from redagent.config import Config


def test_hunt_cache_ttl_default_and_override(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("scope:\n  allowed_targets: [localhost]\n")
    assert Config(str(p)).hunt_cache_ttl == 3600
    p.write_text("hunt_cache_ttl: 0\nscope:\n  allowed_targets: [localhost]\n")
    assert Config(str(p)).hunt_cache_ttl == 0


def test_cache_round_trip(tmp_path):
    cfg = types.SimpleNamespace(workspace=str(tmp_path))
    data = {"http://h": {"ts": 123, "dirb": "x (Status: 200)",
                         "findings": [{"vuln_class": "sqli", "url": "u",
                                       "severity": "critical", "evidence": "e"}],
                         "done": [["u", "sqli"]]}}
    hunt._save_cache(cfg, data)
    assert hunt._load_cache(cfg) == data


def test_load_cache_missing_is_empty(tmp_path):
    cfg = types.SimpleNamespace(workspace=str(tmp_path))
    assert hunt._load_cache(cfg) == {}
