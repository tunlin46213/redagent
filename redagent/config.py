"""Load config.yaml and expose a typed-ish config object plus the Scope guard."""

from pathlib import Path

import yaml

from .scope import Scope

# Search order: $REDAGENT_CONFIG, cwd/config.yaml, package-root/config.yaml.
_DEFAULT = Path(__file__).resolve().parent.parent / "config.yaml"


class Config:
    def __init__(self, path: str | None = None):
        import os
        # Search order: explicit arg -> $REDAGENT_CONFIG -> ./config.yaml ->
        # ~/.config/redagent/config.yaml -> packaged default.
        user_cfg = Path.home() / ".config" / "redagent" / "config.yaml"
        cfg_path = Path(
            path
            or os.environ.get("REDAGENT_CONFIG")
            or (Path.cwd() / "config.yaml" if (Path.cwd() / "config.yaml").exists() else "")
            or (user_cfg if user_cfg.exists() else "")
            or _DEFAULT
        )
        data = yaml.safe_load(cfg_path.read_text()) or {}
        self.path = cfg_path

        llm = data.get("llm", {})
        self.base_url = llm.get("base_url", "http://localhost:11434/v1")
        self.api_key = llm.get("api_key", "ollama")
        self.model = llm.get("model", "qwen2.5:7b")
        self.parallel_tool_calls = bool(llm.get("parallel_tool_calls", False))
        # Optional second model used ONLY for plain-text analysis (no tool calls),
        # e.g. a security-tuned model like DeepHat. Falls back to the tool model.
        self.analyst_model = llm.get("analyst_model") or self.model
        # Generous default: a cold model load + a full review can take minutes on a
        # small GPU. A dead endpoint still fails fast (connection refused).
        self.analyst_timeout = int(llm.get("analyst_timeout", 300))
        # Opt-in: after a hunt, let the analyst propose follow-up tests that the
        # engine executes, then review the results (a bounded analyst<->executor
        # exchange). Adds latency; off by default.
        self.deep_dive = bool(llm.get("deep_dive", False))

        sc = data.get("scope", {})
        self.scope = Scope(sc.get("allowed_targets", ["localhost", "127.0.0.1"]),
                           sc.get("authorized_until", ""))

        root = cfg_path.parent
        self.workspace = (root / data.get("workspace", "workspace")).resolve()
        self.workspace.mkdir(exist_ok=True)
        self.tool_timeout = int(data.get("tool_timeout", 300))

        # Optional dir_bruteforce wordlist override (e.g. a SecLists path for a
        # thorough scan). Absolute, or relative to the config file. Falls back to
        # the bundled curated list if unset or the path does not exist.
        wl = str(data.get("wordlist", "")).strip()
        if wl:
            p = Path(wl) if wl.startswith("/") else (root / wl)
            self.wordlist = str(p) if p.exists() else ""
        else:
            self.wordlist = ""

        # Optional authenticated-flow creds (for capturing a session JWT). The
        # login target must still be in scope. None = unauthenticated engagement.
        auth = data.get("auth") or {}
        self.auth = {
            "login_url": auth.get("login_url", ""),
            "username": auth.get("username", ""),
            "password": auth.get("password", ""),
            "user_field": auth.get("user_field", "email"),
            "pass_field": auth.get("pass_field", "password"),
        } if auth.get("login_url") else None
