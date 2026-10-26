# redagent — Architecture

A local, scope-enforced pentest agent. It drives real security tools (nmap,
gobuster, sqlmap, nuclei, nikto, …) from a local LLM (Ollama / qwen2.5) and
reports findings. Everything a tool touches is checked against an allowlist
(Rules of Engagement) first.

Two models work together:

- **qwen2.5:7b** — the *tool driver*. It emits structured function calls, so it
  runs the agentic modes (`task`, `team`, `chat`, `tui`).
- **DeepHat** (optional `analyst_model`) — the *security analyst*. It can't do
  structured tool calls, but it's strong at plain-text security reasoning, so it
  reviews findings and gives advice. Never in the tool loop.

---

## Module map (`redagent/`)

| File | Lines | Responsibility |
|------|------:|----------------|
| `cli.py` | 69 | Argument parsing + dispatch to a mode. Entry point `main()`. |
| `config.py` | 76 | Loads `config.yaml` → a `Config` object (model, scope, workspace, options). |
| `scope.py` | 88 | The RoE guard. `Scope.check(target)` — allow / refuse, placeholder detection. |
| `llm.py` | 17 | Builds the Ollama (OpenAI-compatible) client for the tool model. |
| `tools.py` | 525 | The 19 tools. `build_tools(cfg)` returns `{name: fn}`, each scope-checked. |
| `agents.py` | 133 | AutoGen agent definitions: the operator + the recon/web/reporter team. |
| `modes.py` | 171 | `task` / `team` / `chat` runners + intent routing (advice, exploit). |
| `hunt.py` | 431 | The deterministic worklist engine (recon → leads → chain → report). |
| `analyst.py` | 146 | DeepHat calls: `analyze` (review), `advise` (what-next), `propose`/`review_results` (deep-dive). |
| `tui.py` | 238 | Textual full-screen chat UI. |
| `report.py` | 51 | Report save helper (team mode). |
| `skills/*.md` | — | Methodology checklists injected into agent prompts. |
| `wordlists/common_paths.txt` | 281 | The bundled curated dir_bruteforce wordlist. |

---

## Modes (`redagent <mode>`)

| Command | Runner | LLM used | What it does |
|---------|--------|----------|--------------|
| `hunt "<url>"` | `hunt.run_hunt` | DeepHat only (analysis) | **Deterministic** worklist scan + exploit chaining → `report.md`. No qwen. |
| `task "<task>"` | `modes.run_task` | qwen | One autonomous operator pass over the full tool set. |
| `team "<task>"` | `modes.run_team` | qwen | recon → web → reporter agents (SelectorGroupChat) → `report.md`. |
| `chat` | `modes.run_chat` | qwen + DeepHat | Interactive REPL. |
| `tui` | `tui.run_tui` | qwen + DeepHat | Interactive full-screen UI (Textual). |
| `scope` | — | none | Print the current engagement scope. |

**Reliability note:** qwen (7B) is unreliable at multi-step tool selection — it
skips `sql_test`, hallucinates targets. So `hunt` moves all orchestration into
Python (deterministic), and `chat`/`tui` route *exploit-intent* messages to
`hunt` instead of the operator (see Intent routing).

---

## `hunt` — the worklist engine (the core)

```
target URL
  │
  ├─ scope.check + HTTP reachability probe      (fail fast if down / out of scope)
  │
  ├─ cache?  reuse recon + findings if < hunt_cache_ttl, else:
  │     recon:  nmap_web_scan + dir_bruteforce + web_crawl (katana) + web_fingerprint (httpx) + port_scan (naabu)
  │
  ├─ seed_leads()  →  severity-ordered queue
  │     search→sqli/xss, sensitive-200→exposure, base→vuln_scan/nikto,
  │     login→auth, wp-*→wpscan, https→testssl
  │
  ├─ for each lead (skip ones already done, per cache):
  │     run ONE tool  →  _is_finding()?  →  record
  │     derive_followups():  SQLi→sql_enumerate (dump tables),
  │                          /ftp listing→fetch each sensitive file, exposed file→secret_scan,
  │     any result with a JWT →  chain jwt_test
  │
  ├─ deep_dive (opt-in):  DeepHat proposes tests → engine runs → DeepHat reviews
  │
  ├─ analyst (DeepHat):  review all findings → "## Analyst Assessment"
  │
  └─ write workspace/report.md   +   save workspace/.hunt_cache.json
```

Key dataclasses in `hunt.py`: `Lead(url, vuln_class, tool, reason, severity)` and
`Finding(vuln_class, url, severity, evidence)`.

**Why deterministic:** the whole engagement plan (what to test, in what order,
what to chain) lives in Python, not in the 7B's head — so it never thrashes,
garbles tool calls, or skips the SQLi endpoint.

---

## Tools (`tools.py` → `build_tools(cfg)`)

Every tool calls `cfg.scope.check()` first and returns `"refused (out of scope)"`
otherwise. The 19 tools:

| Tool | Backend | Purpose |
|------|---------|---------|
| `web_search` | ddgs | External lookups (CVEs, docs) |
| `fetch_url` | urllib | GET a page: status, headers, body |
| `http_request` | urllib | Any method/headers/body (IDOR, auth) |
| `nmap_web_scan` | nmap | Open web ports + service versions (noise-trimmed) |
| `port_scan` | naabu | Fast unprivileged top-1000 TCP sweep — services on non-standard ports |
| `dir_bruteforce` | gobuster | Endpoint discovery (curated or merged SecLists wordlist) |
| `web_crawl` | katana | JS-aware crawl: real routes/params a wordlist misses (feeds sql/xss) |
| `web_fingerprint` | httpx | Status/title/server + detected tech (CMS/framework) — orients the engagement |
| `sql_test` | sqlmap | Detect SQL injection (clean-param, `--technique=BEU`) |
| `sql_enumerate` | sqlmap | Post-exploit: dump DB tables (banner-filtered) |
| `xss_test` | dalfox | Detect reflected XSS |
| `vuln_scan` | nuclei | CVEs / misconfig / exposures |
| `nikto_scan` | nikto | Server misconfig / dangerous files (error-surfacing) |
| `wpscan_scan` | wpscan | WordPress-specific |
| `testssl_scan` | testssl | TLS/HTTPS config |
| `jwt_test` | pure-python | Decode JWT + flag alg:none / weak HMAC secret |
| `secret_scan` | pure-python | Fetch an exposed file + flag leaked keys/tokens/JWTs/creds |
| `read_file` / `write_file` | — | Workspace notes/reports |

The optional binaries (katana, httpx, naabu, nikto, wpscan, testssl) need not be installed; a tool returns
a clear "not installed" message if its binary is missing.

---

## Scope guard (`scope.py`) — non-negotiable

`Scope.check(target)` is the single authorization gate:

- Allows a host if it's a literal match, an IP in an allowed CIDR, or resolves
  into one. Refuses everything else.
- Rejects a catch-all `0.0.0.0/0` scope outright.
- Enforces `authorized_until` (an engagement end date).
- **Placeholder detection** (before DNS): a host like `host` / `example.com` /
  `target` is refused with a *"that's a placeholder, use the real host"* message —
  the 7B often invents these, and this stops one resolving into RFC1918 by
  accident.

---

## qwen + DeepHat hybrid (`analyst.py`)

DeepHat is plain-text only (no tools), reached over Ollama's chat-completions
endpoint, output hard-capped with `num_predict` (without it the 7B rambles for
minutes). Four entry points:

- `analyze(cfg, report)` — full findings review (assessment + triage + remediation).
- `advise(cfg, question)` — answers "what next?" grounded in `report.md`.
- `propose(cfg, …)` / `review_results(cfg, …)` — the deep-dive exchange.

**Phase-batched:** DeepHat is only loaded *after* all tool work, so on a small
GPU qwen and DeepHat never fight for VRAM (at most one model swap).

---

## Intent routing (`modes.py`, used by `chat` + `tui`)

A chat/TUI message is classified before it reaches the operator:

- `is_exploit_intent()` — "dump database", "exploit", "pentest", "find sql
  vuln"… → routed to `hunt` (deterministic) with a URL from the message or the
  last-seen target.
- `is_advice()` — "what next?", "recommend"… → routed to DeepHat `advise()` (or a
  qwen strategist prompt if no analyst is configured).
- Otherwise → the qwen operator for a single-action probe.

---

## Configuration (`config.yaml`)

Search order: `--config` → `$REDAGENT_CONFIG` → `./config.yaml` →
`~/.config/redagent/config.yaml` → packaged default.
(The user config is symlinked to the project `config.yaml` so edits apply everywhere.)

| Key | Default | Meaning |
|-----|---------|---------|
| `llm.model` | `qwen2.5:7b` | Tool-driving model |
| `llm.analyst_model` | = `model` | Analysis model (set to DeepHat for the hybrid) |
| `llm.analyst_timeout` | 300 | Analyst call timeout (cold load can take minutes) |
| `llm.deep_dive` | false | Opt-in analyst↔executor follow-up round |
| `scope.allowed_targets` | localhost + RFC1918 | The RoE allowlist |
| `scope.authorized_until` | "" | Optional engagement end date |
| `workspace` | `workspace` | Where reports + caches land |
| `tool_timeout` | 300 | Per-tool subprocess timeout |
| `hunt_cache_ttl` | 3600 | Reuse recon + findings for this long (0 = always fresh) |
| `wordlist` | "" | dir_bruteforce override (merged with curated; e.g. SecLists) |
| `auth.*` | none | Optional login creds to capture a session JWT |

---

## Workspace outputs

| File | Written by | Contents |
|------|-----------|----------|
| `workspace/report.md` | hunt / team | The findings report (+ DeepHat assessment) |
| `workspace/.hunt_cache.json` | hunt | Cached recon + findings per target (for reuse) |
| `workspace/.wordlist_merged.txt` | tools | curated + override wordlist (when override set) |

---

## Tests (`tests/`, `uv run --group dev pytest`)

Pure-logic, no network / LLM / Docker: `test_scope`, `test_tools`, `test_hunt`,
`test_analyst`, `test_advice`, `test_auth`, `test_discuss`, `test_cache`,
`test_routing`, `test_wordlist`, `test_tui` (headless pilot). They lock in the
fixes (clean-param, nmap trim, placeholder scope, finding detection, chains,
routing, cache round-trip).

---

## Install / run

```bash
cd ~/agents/redagent
uv tool install . --force        # installs the `redagent` command
redagent scope                   # print the authorized scope
redagent hunt http://localhost:3001   # the main event
redagent tui                     # interactive UI
```

Requires Ollama running (with the configured models pulled) and, on PATH: nmap,
gobuster, sqlmap, dalfox, nuclei, curl; optionally katana, httpx, naabu, nikto, wpscan, testssl.
