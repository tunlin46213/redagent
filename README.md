# redagent

Local, scope-enforced pentest agent. It drives real security tools (nmap,
gobuster, sqlmap, nuclei, nikto, …) from a local LLM (Ollama / qwen2.5) and
reports findings. Every tool checks your engagement scope (RoE) before touching
a target.

Two models, each doing what it's good at:
- **qwen2.5:7b** drives the tools (structured function calls) — the agentic modes.
- **DeepHat** (optional) reviews findings and gives advice (plain text, no tools).

> **Deep dive:** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — module map, the
> hunt flow, the hybrid, the full config reference.

## Install

```bash
cd ~/agents/redagent
uv tool install .            # installs the `redagent` command
```

Needs Ollama up (models from `config.yaml`) and these on PATH: nmap, gobuster,
sqlmap, dalfox, nuclei, curl. Optional: nikto, wpscan, testssl (each tool says so
if its binary is missing).

## Modes

```bash
redagent hunt http://localhost:3001     # ⭐ deterministic chained scan -> report.md
redagent tui                            # full-screen interactive UI (Textual)
redagent chat                           # interactive REPL
redagent task "fetch http://localhost:3001/ftp"   # one autonomous operator pass
redagent team "assess http://localhost:3001"      # recon/web/reporter -> report.md
redagent scope                          # print the authorized scope
```

**`hunt` is the main event.** It's deterministic (Python orchestrates, not the
7B): recon → severity-ordered leads → run one tool each → chain follow-ups
(SQLi → dump DB tables, `/ftp` listing → fetch files, JWT → inspect) → optional
DeepHat analyst assessment → `workspace/report.md`.

In `chat`/`tui`, an exploit request ("dump database", "find sql vuln and exploit")
is routed to `hunt` automatically — the 7B operator is unreliable at multi-step
tool selection, so the deterministic path handles it.

## Config (`config.yaml`)

Found via: `--config` → `$REDAGENT_CONFIG` → `./config.yaml` →
`~/.config/redagent/config.yaml` → packaged default.

Key options: `llm.model` (tool driver), `llm.analyst_model` (set to DeepHat for
the hybrid), `scope.allowed_targets`, `hunt_cache_ttl`, `wordlist` (SecLists
override), `auth.*` (login creds to capture a JWT). Full table in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#configuration-configyaml).

## Scope (RoE)

Every target-touching tool checks `scope.allowed_targets` first. Localhost +
RFC1918 are allowed by default (lab works out of the box). For an **authorized**
external engagement, add the specific host/domain/CIDR — one per target. A
catch-all (`0.0.0.0/0`) is rejected, placeholder hosts (`example.com`) are
refused, and `authorized_until` can set an end date. This guards against both
out-of-scope targets and the agent picking a wrong one.

## Tests

```bash
uv run --group dev pytest        # pure-logic, no network/LLM/Docker
```
