"""Textual TUI chat for redagent — a scrollable conversation with the operator,
tool calls/results streamed live, plus a few slash commands. Launch: redagent tui.
"""

from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Input, RichLog

from .config import Config
from .llm import make_client
from .tools import build_tools
from .agents import make_operator
from .modes import _scope_targets, expand_advice, is_advice, has_analyst

_HELP = (
    "[b]commands[/b] (slash optional): hunt <url>  advise [q]  scope  report  clear  help  quit   "
    "(anything else is sent to the agent; 'what next?' goes to the analyst)"
)


_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"   # braille spinner frames
_COMMANDS = {"hunt", "advise", "scope", "report", "clear", "help", "quit", "exit"}


def _rich_escape(s: str) -> str:
    return s.replace("[", r"\[")


def _format(ev) -> str:
    """Render one AutoGen stream event as a markup line (or '' to skip)."""
    kind = type(ev).__name__
    content = getattr(ev, "content", None)
    if kind == "TextMessage":
        text = (content or "").strip()
        return f"[green]operator[/] {_rich_escape(text)}" if text else ""
    if kind == "ThoughtEvent":
        text = (content or "").strip()
        return f"[dim italic]{_rich_escape(text)}[/]" if text else ""
    if kind == "ToolCallRequestEvent":
        out = []
        for call in content or []:
            args = _rich_escape(str(getattr(call, "arguments", "")))[:160]
            out.append(f"[yellow]→ {getattr(call, 'name', '?')}[/]([dim]{args}[/])")
        return "\n".join(out)
    if kind == "ToolCallExecutionEvent":
        out = []
        for res in content or []:
            body = _rich_escape(str(getattr(res, "content", "")).strip().replace("\n", " "))[:200]
            tag = "[red]refused[/]" if body.startswith("refused") else "[blue]✓[/]"
            out.append(f"  {tag} {getattr(res, 'name', '?')}: [dim]{body}[/]")
        return "\n".join(out)
    return ""   # TaskResult, summaries, etc.


class RedagentTUI(App):
    CSS = """
    RichLog { padding: 0 1; }
    Input { dock: bottom; border: tall $accent; }
    """
    BINDINGS = [("ctrl+c", "quit", "Quit"), ("ctrl+l", "clear", "Clear")]

    def __init__(self, cfg: Config):
        super().__init__()
        self.cfg = cfg
        self.client = None
        self.operator = None
        self.busy = False
        self._status = "working…"
        self._spin_i = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield RichLog(id="log", wrap=True, markup=True, highlight=False)
        yield Input(placeholder="task for the agent, or /help …", id="prompt")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "redagent"
        self.client = make_client(self.cfg)
        self._new_operator()
        log = self.query_one("#log", RichLog)
        log.write(f"[b]redagent[/b]  model: {self.cfg.model}")
        log.write(f"scope: {', '.join(_scope_targets(self.cfg)) or '(CIDRs only)'}")
        log.write(_HELP)
        self.query_one("#prompt", Input).focus()
        self.set_interval(0.1, self._spin)   # animate the busy indicator

    def _spin(self) -> None:
        if self.busy:
            self._spin_i = (self._spin_i + 1) % len(_SPINNER)
            self.sub_title = f"{_SPINNER[self._spin_i]} {self._status}"

    def _new_operator(self) -> None:
        self.operator = make_operator(self.client, build_tools(self.cfg),
                                      targets=_scope_targets(self.cfg))

    def _emit(self, text: str) -> None:
        """Write a line to the log (called in the main thread via call_from_thread)."""
        self.query_one("#log", RichLog).write(_rich_escape(str(text)))

    def action_clear(self) -> None:
        self._new_operator()
        self.query_one("#log", RichLog).clear()
        self.query_one("#log", RichLog).write("[dim]context cleared.[/]")

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        msg = event.value.strip()
        self.query_one("#prompt", Input).value = ""
        if not msg:
            return
        log = self.query_one("#log", RichLog)
        # Accept commands with OR without the leading slash: a bare 'hunt <url>'
        # is treated as '/hunt <url>' instead of being sent to the agent as a task.
        first = msg.split()[0].lstrip("/").lower()
        if msg.startswith("/") or first in _COMMANDS:
            self._command("/" + msg.lstrip("/"), log)
            return
        if self.busy:
            log.write("[red]busy — wait for the current task to finish.[/]")
            return
        log.write(f"[bold cyan]you[/] {_rich_escape(msg)}")
        # Advice questions -> DeepHat analyst (if configured); else qwen operator.
        if is_advice(msg) and has_analyst(self.cfg):
            self.run_advise(msg)
        else:
            self.run_agent(expand_advice(msg, self.cfg) if is_advice(msg) else msg, msg)

    def _command(self, msg: str, log: RichLog) -> None:
        cmd = msg.lower().split()[0]
        if cmd in ("/quit", "/exit"):
            self.exit()
        elif cmd == "/help":
            log.write(_HELP)
        elif cmd == "/scope":
            log.write("allowed: " + ", ".join(
                sorted(self.cfg.scope.hosts) + [str(n) for n in self.cfg.scope.nets]))
        elif cmd == "/clear":
            self.action_clear()
        elif cmd == "/report":
            p = Path(self.cfg.workspace) / "report.md"
            log.write(_rich_escape(p.read_text()) if p.exists() else "[dim]no report.md yet.[/]")
        elif cmd == "/hunt":
            parts = msg.split(maxsplit=1)
            if len(parts) < 2:
                log.write("[dim]usage: /hunt <target-url>  (e.g. /hunt http://localhost:3001)[/]")
            elif self.busy:
                log.write("[red]busy — wait for the current task to finish.[/]")
            else:
                log.write(f"[bold cyan]you[/] hunt {_rich_escape(parts[1])}")
                self.run_hunt_tui(parts[1].strip().strip('"\''))
        elif cmd == "/advise":
            if self.busy:
                log.write("[red]busy — wait for the current task to finish.[/]")
            else:
                q = msg.split(maxsplit=1)
                self.run_advise(q[1] if len(q) > 1 else "what should I test next?")
        else:
            log.write(f"[red]unknown command[/] {_rich_escape(cmd)} — try /help")

    @work(exclusive=True, group="agent")
    async def run_agent(self, task: str, original: str = "") -> None:
        log = self.query_one("#log", RichLog)
        self._status = "working (the 7B is slow)…"
        self.busy = True
        log.write("[dim]⏳ working…[/]")
        texts: list[str] = []
        try:
            async for ev in self.operator.run_stream(task=task):
                line = _format(ev)
                if line:
                    log.write(line)
                if type(ev).__name__ == "TextMessage" and (ev.content or "").strip():
                    texts.append(ev.content.strip())
        except Exception as e:                      # keep the TUI alive on tool/LLM errors
            log.write(f"[red]error:[/] {_rich_escape(str(e))}")
        else:
            # The 7B sometimes just echoes a vague prompt or answers nothing useful.
            if not texts or texts[-1].lower() == (original or task).lower():
                log.write("[dim]— give a concrete task, e.g. "
                          "'test http://localhost:3001 for sqli' (or use `redagent hunt <url>`).[/]")
        finally:
            self.busy = False
            self.sub_title = "ready"


    @work(thread=True, exclusive=True, group="agent")
    def run_advise(self, question: str) -> None:
        from .analyst import advise
        model = self.cfg.analyst_model if has_analyst(self.cfg) else self.cfg.model
        self._status = f"asking analyst ({model})…"
        self.busy = True
        try:
            out = advise(self.cfg, question)
            self.call_from_thread(self._emit, "[analyst]")
            self.call_from_thread(self._emit, out or "(analyst unavailable)")
        except Exception as e:
            self.call_from_thread(self._emit, f"analyst error: {e}")
        finally:
            self.busy = False
            self.call_from_thread(setattr, self, "sub_title", "ready")

    @work(thread=True, exclusive=True, group="agent")
    def run_hunt_tui(self, target: str) -> None:
        from .hunt import run_hunt
        self._status = "hunting…"
        self.busy = True
        try:
            run_hunt(target, self.cfg, emit=lambda s: self.call_from_thread(self._emit, s))
            self.call_from_thread(self._emit, "hunt complete — /report to view the findings.")
        except Exception as e:                      # keep the TUI alive on tool errors
            self.call_from_thread(self._emit, f"hunt error: {e}")
        finally:
            self.busy = False
            self.call_from_thread(setattr, self, "sub_title", "ready")


def run_tui(cfg: Config) -> None:
    RedagentTUI(cfg).run()
