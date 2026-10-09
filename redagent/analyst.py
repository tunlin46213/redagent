"""Security analyst pass — plain-text LLM review/advice over scan findings.

Uses cfg.analyst_model (e.g. DeepHat) via the Ollama OpenAI-compatible endpoint
with NO tool calling, so a security-tuned model that can't do structured tools is
a good fit here. Never raises: on any error it returns "" and the caller falls
back / skips — the scan and report always stand on their own.
"""

import json
import re
import urllib.request
from pathlib import Path

_SYSTEM = (
    "You are a senior penetration tester reviewing an automated scan report. Be "
    "concise, concrete, and honest — do not invent findings."
)

_REVIEW = """Review the findings below and produce markdown with these sections:

## Analyst Assessment
A 2-3 sentence executive summary of the overall risk.

## Triage
For each finding: its title, a confidence tag (Confirmed / Likely / Possible false
positive), and one line of impact. Call out anything that looks like a tool warning
or noise rather than a real vulnerability.

## Remediation
One concrete fix per real finding.

## Recommended next steps
The top 3 actions to deepen this engagement (exact endpoint / technique).

Findings:
{findings}
"""

_ADVISE_SYSTEM = (
    "You are a senior penetration tester advising a colleague mid-engagement. "
    "Be concrete and prioritised; recommend specific endpoints and techniques."
)

_ADVISE = """Current engagement findings:
{findings}

Your colleague asks: {question}

Answer in UNDER 150 words as a short ranked list (most impactful first). For each
item: the exact endpoint/technique + which tool to run. No preamble, no repeating
tests already confirmed above.
"""


def _complete(cfg, system: str, user: str, max_tokens: int = 500) -> str:
    """One plain-text completion against the analyst model. '' on any failure.

    max_tokens hard-caps generation (options.num_predict): without it a small model
    can ramble for minutes. ~10s/120 tokens on the 4GB box, so keep it tight."""
    payload = {
        "model": cfg.analyst_model,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "stream": False,
        "temperature": 0.2,
        "max_tokens": max_tokens,            # OpenAI-style cap
        "options": {"num_predict": max_tokens},  # Ollama-native cap (the one that bites)
    }
    req = urllib.request.Request(
        cfg.base_url.rstrip("/") + "/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {cfg.api_key}"})
    try:
        with urllib.request.urlopen(req, timeout=cfg.analyst_timeout) as r:
            data = json.load(r)
        return (data["choices"][0]["message"]["content"] or "").strip()
    except Exception:
        return ""


def analyze(cfg, findings_text: str) -> str:
    """Markdown assessment of a findings report, or '' if unavailable."""
    if not findings_text.strip():
        return ""
    return _complete(cfg, _SYSTEM, _REVIEW.format(findings=findings_text[:6000]),
                     max_tokens=900)


def advise(cfg, question: str) -> str:
    """Answer a 'what next?'-style question grounded in the current report.md."""
    rep = Path(cfg.workspace) / "report.md"
    try:
        findings = rep.read_text()[:2500].strip() if rep.exists() else ""
    except Exception:
        findings = ""
    return _complete(cfg, _ADVISE_SYSTEM,
                     _ADVISE.format(findings=findings or "(no findings recorded yet)",
                                    question=question), max_tokens=300)


# --- analyst <-> executor discussion (bounded exchange) ---

_PROPOSE_SYSTEM = "You are a senior pentester planning follow-up tests. Output ONLY JSON."

_PROPOSE = """Findings so far:
{findings}

Available tools (use these names exactly): {tools}

Propose up to 3 HIGH-VALUE follow-up tests to deepen the engagement. Output ONLY a
JSON array; each item: {{"tool": "<tool name>", "url": "<full in-scope URL>", "why":
"<short reason>"}}. No prose, no code fences."""

_REVIEW2 = """You proposed follow-up tests. Their results:
{results}

In under 120 words: state any NEW confirmed findings and whether the proposals paid
off. Be concrete."""


def propose(cfg, findings_text: str, tool_names) -> list[dict]:
    """Ask the analyst for up to 3 structured follow-up tests. [] on any failure."""
    raw = _complete(cfg, _PROPOSE_SYSTEM,
                    _PROPOSE.format(findings=findings_text[:3000],
                                    tools=", ".join(tool_names)), max_tokens=400)
    m = re.search(r"\[.*\]", raw, re.S)
    if not m:
        return []
    try:
        items = json.loads(m.group(0))
    except Exception:
        return []
    out = []
    for it in items if isinstance(items, list) else []:
        if isinstance(it, dict) and it.get("tool") and it.get("url"):
            out.append({"tool": str(it["tool"]).strip(),
                        "url": str(it["url"]).strip(),
                        "why": str(it.get("why", "")).strip()})
    return out[:3]


def review_results(cfg, results_text: str) -> str:
    """Analyst's short verdict on the executed follow-up tests."""
    return _complete(cfg, _ADVISE_SYSTEM, _REVIEW2.format(results=results_text[:4000]),
                     max_tokens=300)
