"""expand_advice: vague 'what is next?' -> concrete strategist instruction."""

import types

from redagent import modes


def _cfg(tmp_path, report=None):
    ws = tmp_path / "workspace"
    ws.mkdir()
    if report is not None:
        (ws / "report.md").write_text(report)
    return types.SimpleNamespace(workspace=str(ws))


def test_normal_task_passes_through(tmp_path):
    msg = "test http://localhost:3001 for sqli"
    assert modes.expand_advice(msg, _cfg(tmp_path)) == msg


def test_advice_question_expanded(tmp_path):
    out = modes.expand_advice("what is next", _cfg(tmp_path))
    assert "lead pentester" in out.lower() and "prioritised" in out.lower()
    assert out != "what is next"


def test_burmese_advice_trigger(tmp_path):
    out = modes.expand_advice("ဘာဆက်လုပ်ရမလဲ", _cfg(tmp_path))
    assert "lead pentester" in out.lower()


def test_advice_includes_report_findings(tmp_path):
    out = modes.expand_advice("what should I do next",
                              _cfg(tmp_path, report="### SQLI\n- Severity: Critical"))
    assert "Findings recorded so far" in out and "SQLI" in out


def test_advice_without_report_has_no_findings_block(tmp_path):
    out = modes.expand_advice("recommend next steps", _cfg(tmp_path))
    assert "Findings recorded so far" not in out


def test_is_advice_detection():
    assert modes.is_advice("what is next")
    assert modes.is_advice("ဘာဆက်လုပ်ရမလဲ")
    assert not modes.is_advice("test http://localhost:3001 for sqli")


def test_has_analyst_true_only_when_dedicated():
    assert modes.has_analyst(types.SimpleNamespace(analyst_model="deephat", model="qwen2.5:7b"))
    assert not modes.has_analyst(types.SimpleNamespace(analyst_model="qwen2.5:7b", model="qwen2.5:7b"))
    assert not modes.has_analyst(types.SimpleNamespace(analyst_model="", model="qwen2.5:7b"))
