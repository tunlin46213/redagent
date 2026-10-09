# redagent

Local, scope-enforced pentest agent (AutoGen + Ollama/qwen2.5). One CLI, three
modes, tools that only touch targets declared in your engagement scope.

## Install
    cd ~/agents/redagent
    uv tool install .        # installs the `redagent` command
    # or: uv run redagent <mode> ...

Needs Ollama up (model in config.yaml, default qwen2.5:7b) and nmap, gobuster,
sqlmap, nuclei, curl on PATH.

## Use
    redagent scope                                   # show authorized scope
    redagent task "fetch http://localhost:3001/ftp"  # single operator
    redagent team "assess http://localhost:3001"     # recon/web/reporter -> report.md
    redagent chat                                     # interactive

## Scope (RoE)
Every target-touching tool checks scope.allowed_targets in config.yaml first.
Localhost + RFC1918 allowed by default (lab works out of the box). For an
AUTHORIZED external engagement, add the specific host/domain/CIDR — one per
target. A catch-all (0.0.0.0/0) is rejected. Protects against out-of-scope
targets and against the agent picking a wrong target by mistake.
