"""dir_bruteforce wordlist override: custom path wins, missing falls back."""

import textwrap

from redagent.config import Config


def _cfg(tmp_path, body):
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent(body))
    return Config(str(p))


def test_no_override_defaults_empty(tmp_path):
    cfg = _cfg(tmp_path, "scope:\n  allowed_targets: [localhost]\n")
    assert cfg.wordlist == ""   # tools.py then uses the bundled list


def test_absolute_override_used_when_present(tmp_path):
    wl = tmp_path / "big.txt"
    wl.write_text("admin\napi\n")
    cfg = _cfg(tmp_path, f"""
        wordlist: "{wl}"
        scope:
          allowed_targets: [localhost]
    """)
    assert cfg.wordlist == str(wl)


def test_relative_override_resolved_against_config_dir(tmp_path):
    (tmp_path / "lists").mkdir()
    (tmp_path / "lists" / "w.txt").write_text("x\n")
    cfg = _cfg(tmp_path, """
        wordlist: "lists/w.txt"
        scope:
          allowed_targets: [localhost]
    """)
    assert cfg.wordlist.endswith("lists/w.txt")


def test_missing_override_falls_back_to_empty(tmp_path):
    cfg = _cfg(tmp_path, """
        wordlist: "/nope/does-not-exist.txt"
        scope:
          allowed_targets: [localhost]
    """)
    assert cfg.wordlist == ""   # graceful fallback -> bundled list


def test_override_merges_with_curated_deduped(tmp_path):
    from redagent import tools
    wl = tmp_path / "breadth.txt"
    wl.write_text("zzz_unique_breadth\nmedia\n")   # 'media' also in curated
    cfg = _cfg(tmp_path, f"""
        wordlist: "{wl}"
        scope:
          allowed_targets: [localhost]
    """)
    tools.build_tools(cfg)                           # triggers the merge
    merged = (tmp_path / "workspace" / ".wordlist_merged.txt").read_text().splitlines()
    assert "rest/products/search" in merged          # deep curated path kept
    assert "zzz_unique_breadth" in merged            # override breadth added
    assert merged.count("media") == 1                # deduped across both
