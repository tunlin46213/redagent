"""TUI event formatting (pure) + a headless pilot smoke test."""

import asyncio
import types

from redagent import tui


def _ev(name, **attrs):
    return type(name, (), attrs)()


def test_format_text_message():
    out = tui._format(_ev("TextMessage", content="SQLi confirmed", source="operator"))
    assert "operator" in out and "SQLi confirmed" in out


def test_format_empty_text_skipped():
    assert tui._format(_ev("TextMessage", content="  ", source="operator")) == ""


def test_format_tool_call_request():
    call = types.SimpleNamespace(name="sql_test", arguments='{"url":"http://h/x"}')
    out = tui._format(_ev("ToolCallRequestEvent", content=[call]))
    assert "sql_test" in out and "→" in out


def test_format_tool_execution_and_refusal():
    ok = types.SimpleNamespace(name="fetch_url", content="HTTP 200 body")
    bad = types.SimpleNamespace(name="nmap_web_scan", content="refused (out of scope): x")
    assert "fetch_url" in tui._format(_ev("ToolCallExecutionEvent", content=[ok]))
    assert "refused" in tui._format(_ev("ToolCallExecutionEvent", content=[bad]))


def test_format_unknown_event_skipped():
    assert tui._format(_ev("TaskResult", content="whatever")) == ""


def test_rich_escape_brackets():
    assert tui._rich_escape("a[b]c") == r"a\[b]c"


def test_tui_mounts_and_handles_command(tmp_path):
    """Headless: the app mounts, builds the operator, and a /scope command runs
    without touching the LLM or crashing."""
    from redagent.config import Config
    cfg = Config(None)

    async def _run():
        app = tui.RedagentTUI(cfg)
        async with app.run_test() as pilot:
            assert app.operator is not None          # on_mount built it
            app.query_one("#prompt").value = "/scope"
            await pilot.press("enter")               # should not raise
            app.query_one("#prompt").value = "/help"
            await pilot.press("enter")
            app.exit()

    asyncio.run(_run())
