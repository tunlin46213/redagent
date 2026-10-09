"""Run modes: task (single operator), team (recon/web/reporter), chat (interactive)."""

import asyncio
from pathlib import Path

from autogen_agentchat.teams import SelectorGroupChat
from autogen_agentchat.conditions import TextMentionTermination, MaxMessageTermination
from autogen_agentchat.ui import Console

from .config import Config
from .llm import make_client
from .tools import build_tools
from .agents import make_operator, make_team
from .report import save_from_messages


_ADVICE_HINTS = ("what is next", "what's next", "what next", "what should", "what now",
                 "suggest", "recommend", "next step", "advise", "advice",
                 "အကြံ", "ဘာဆက်", "ဘာလုပ်", "ဘာေတွလို")


def is_advice(msg: str) -> bool:
    """True when the message is a 'what next / recommend' style question."""
    low = msg.lower().strip()
    return any(h in low for h in _ADVICE_HINTS)


def has_analyst(cfg: Config) -> bool:
    """True when a DEDICATED analyst model (not the tool model) is configured."""
    return getattr(cfg, "analyst_model", "") not in ("", cfg.model)


def expand_advice(msg: str, cfg: Config) -> str:
    """Turn a vague 'what is next?' into a concrete strategist instruction so the
    agent reviews what it already found and recommends prioritised next steps,
    instead of echoing the question. Non-advice messages pass through unchanged."""
    low = msg.lower().strip()
    if not any(h in low for h in _ADVICE_HINTS):
        return msg
    instr = (
        "As the lead pentester, review EVERYTHING tested and discovered so far in "
        "this engagement (the conversation above, plus any findings below) and give "
        "the human a prioritised recommendation of what to do next. Name the untested "
        "endpoints and vuln classes, and which confirmed findings to exploit further; "
        "for each, give the exact tool + URL to run next. Do NOT repeat tests already "
        "done. End with a short ranked list (most impactful first)."
    )
    rep = Path(cfg.workspace) / "report.md"
    if rep.exists():
        try:
            body = rep.read_text()[:3000].strip()
            if body:
                instr += "\n\nFindings recorded so far:\n" + body
        except Exception:
            pass
    return instr


def _engagement_complete(result) -> bool:
    """True once the operator signalled it finished the whole engagement."""
    for m in reversed(getattr(result, "messages", []) or []):
        c = getattr(m, "content", "")
        if isinstance(c, str):
            return "ENGAGEMENT COMPLETE" in c
    return False


def _scope_targets(cfg: Config) -> list[str]:
    """The literal authorized hosts (not CIDRs) to pin into the operator prompt,
    minus any placeholder-looking entry (never teach the 7B a fake host)."""
    from .scope import _PLACEHOLDER_HOSTS
    return sorted(h for h in getattr(cfg.scope, "hosts", set())
                  if h not in _PLACEHOLDER_HOSTS)


async def run_task(task: str, cfg: Config) -> None:
    client = make_client(cfg)
    operator = make_operator(client, build_tools(cfg), targets=_scope_targets(cfg))
    # One autonomous pass does the engagement (bounded by max_tool_iterations).
    # Then, instead of dropping the user back to the shell, stay interactive so
    # they can steer or answer — the operator keeps its conversation state across
    # passes, so "continue" resumes. Exit only on the completion sentinel or when
    # the user types exit/quit. (A single RoundRobin loop was tried and dropped:
    # the 7B thrashed, re-testing one endpoint until the time budget ran out.)
    loop = asyncio.get_event_loop()
    result = await Console(operator.run_stream(task=task))
    while not _engagement_complete(result):
        try:
            reply = (await loop.run_in_executor(
                None, input, "\nyou> (Enter=continue, direction to steer, 'exit' to stop)\n")).strip()
        except EOFError:
            break
        if reply.lower() in ("exit", "quit", "q"):
            break
        # Enter with no text = keep going autonomously (don't exit on a stray
        # keypress); a 7B pass often stops mid-engagement with a partial message.
        result = await Console(operator.run_stream(task=reply or "continue"))
    await client.close()


async def run_team(task: str, cfg: Config) -> None:
    client = make_client(cfg)
    recon, web, reporter = make_team(client, build_tools(cfg))
    team = SelectorGroupChat(
        [recon, web, reporter], model_client=client,
        termination_condition=TextMentionTermination("ENGAGEMENT COMPLETE")
        | MaxMessageTermination(10),
        allow_repeated_speaker=False,
    )
    result = await Console(team.run_stream(task=task))
    saved = save_from_messages(result.messages, cfg.workspace)
    print(f"\n[saved] {saved}" if saved else "\n[warn] no report captured")
    await client.close()


async def run_chat(cfg: Config) -> None:
    client = make_client(cfg)
    operator = make_operator(client, build_tools(cfg), targets=_scope_targets(cfg))
    print("redagent chat — type 'exit' to quit.")
    loop = asyncio.get_event_loop()
    while True:
        msg = await loop.run_in_executor(None, input, "\nyou> ")
        if msg.strip().lower() in ("exit", "quit"):
            break
        # Advice questions go to the DeepHat analyst (better security reasoning, no
        # tools); fall back to the qwen operator with a strategist prompt if no
        # dedicated analyst is configured. Everything else drives tools via qwen.
        if is_advice(msg) and has_analyst(cfg):
            from .analyst import advise
            print("\n[analyst]")
            print(await loop.run_in_executor(None, advise, cfg, msg)
                  or "(analyst unavailable)")
        else:
            task = expand_advice(msg, cfg) if is_advice(msg) else msg
            await Console(operator.run_stream(task=task))
    await client.close()
