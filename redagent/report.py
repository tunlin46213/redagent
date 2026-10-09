"""Deterministic report extraction — don't rely on a 7B to call write_file."""

import re
from pathlib import Path


def extract_report(text: str) -> str:
    """Pull the report body even when the model dumped its write_file call as text."""
    m = re.search(r'"content"\s*:\s*"(.*)"', text, re.DOTALL)
    if m:
        try:
            return m.group(1).encode("utf-8").decode("unicode_escape")
        except Exception:
            return m.group(1)
    body = text.replace("ENGAGEMENT COMPLETE", "").strip()
    # Strip a whole-document ```markdown ... ``` fence if the model wrapped it,
    # and a stray leading "### report.md" / "# report.md" title line.
    body = re.sub(r"^```[a-zA-Z]*\n", "", body)
    body = re.sub(r"\n```\s*$", "", body)
    body = re.sub(r"^#{1,6}\s*report\.md\s*\n+", "", body, flags=re.IGNORECASE)
    return body.strip()


def save_from_messages(messages, workspace: Path, filename: str = "report.md") -> str | None:
    """Prefer a substantive reporter report; otherwise fall back to concatenating
    the recon/web findings so a report is saved even when the 7B reporter only
    emits 'ENGAGEMENT COMPLETE'."""
    reporter_report = ""
    findings: list[str] = []
    for msg in messages:
        src = getattr(msg, "source", "")
        c = getattr(msg, "content", "")
        if not isinstance(c, str):
            continue
        c = c.strip()
        if not c:
            continue
        if src == "reporter" and len(c.replace("ENGAGEMENT COMPLETE", "").strip()) > 50:
            reporter_report = c
        elif src in ("recon", "web") and len(c) > 40:
            findings.append(f"## {src}\n\n{c}")

    if reporter_report:
        body = extract_report(reporter_report)
    elif findings:
        body = "# Findings (compiled from team transcript)\n\n" + "\n\n".join(findings)
    else:
        return None
    out = workspace / filename
    out.write_text(body, encoding="utf-8")
    return str(out)
