"""Agent + team definitions, built from the tool set and model client."""

from autogen_agentchat.agents import AssistantAgent
from pathlib import Path

_SKILLS_DIR = Path(__file__).resolve().parent / "skills"

def load_skill(name: str) -> str:
    try:
        return (_SKILLS_DIR / f"{name}.md").read_text(encoding="utf-8")
    except Exception:
        return ""


def with_skills(base: str, *names: str) -> str:
    """Append each existing skill file (in order) to a base system message."""
    blocks = [s for s in (load_skill(n) for n in names) if s]
    return base + ("\n\n" + "\n\n".join(blocks) if blocks else "")


def make_operator(client, tools: dict, targets: list[str] | None = None):
    """Single autonomous operator with the full tool set (for task/chat modes).

    `targets` are the engagement's real authorized hosts (from the scope); they are
    pinned into the prompt so the 7B uses them instead of inventing example.com.
    """
    system_message = (
        "You complete the task using your tools. Choose the tool that fits "
        "(web_search for external facts, nmap_web_scan/dir_bruteforce for "
        "mapping a host, fetch_url/http_request to inspect endpoints, sql_test/"
        "xss_test/vuln_scan to check for vulns, nikto_scan for server misconfig, "
        "wpscan_scan for WordPress sites only, testssl_scan for HTTPS/TLS config, "
        "jwt_test to inspect a captured JWT, read/write_file for notes). Call EXACTLY "
        "ONE tool per turn, wait for its result, never put a placeholder like "
        "$(...) into another tool's arguments, and copy earlier results verbatim. "
        "ALWAYS use the real target host from the task (e.g. localhost:3001) in "
        "every URL — never a placeholder host like 'host' or 'example.com'. "
        "For sql_test/xss_test pass a clean param value (q=apple) and never type "
        "SQL/payloads yourself. If a tool "
        "says 'refused (out of scope)', stop and report it — do not retry other "
        "hosts. "
        "The in-scope targets are PRE-AUTHORIZED: never ask the user to confirm, "
        "approve, or whether to proceed, and never end a turn with a question to "
        "the user. Work autonomously through every endpoint and vuln class you "
        "identified, moving to a NEW endpoint or vuln class each turn. NEVER re-run "
        "a test you already confirmed (if sql_test already found 'q is vulnerable', "
        "do not test that same parameter again) — re-testing the same thing wastes "
        "the engagement. When no untested endpoint or vuln class remains, finish "
        "with a short plain-language summary of ALL findings and end your final "
        "message with the exact line: ENGAGEMENT COMPLETE"
    )
    if targets:
        system_message += (
            "\n\nAUTHORIZED TARGET HOST(S) for this engagement: "
            + ", ".join(targets)
            + ". Build every URL against one of these exact hosts. If the task does "
            "not name a host, use the first one. Never substitute a placeholder."
        )
    system_message = with_skills(system_message, "web_methodology", "api_testing")
    return AssistantAgent(
        name="operator",
        model_client=client,
        tools=list(tools.values()),
        reflect_on_tool_use=True,
        max_tool_iterations=16,  # a full engagement (recon + several endpoints)
        system_message=system_message,                    # needs room to finish
    )


def make_team(client, tools: dict):
    """recon / web / reporter specialists for SelectorGroupChat."""
    recon = AssistantAgent(
        name="recon", model_client=client,
        tools=[tools["nmap_web_scan"], tools["dir_bruteforce"]],
        description="Reconnaissance: discovers open web services and hidden endpoints.",
        system_message=with_skills(
            "You are recon. The target is authorized and in scope (localhost and "
            "lab hosts are valid targets) — never refuse it yourself; the tools "
            "enforce scope and will say 'refused' only if truly out of scope. Call "
            "ONE tool per turn: nmap_web_scan then dir_bruteforce on the target, "
            "state the endpoints/services found in a few lines, then hand off naming "
            "what web should probe. Do not test vulnerabilities yourself.",
            "recon_checklist",
        ),
    )
    web = AssistantAgent(
        name="web", model_client=client,
        tools=[tools["fetch_url"], tools["http_request"], tools["sql_test"],
               tools["xss_test"], tools["vuln_scan"], tools["nikto_scan"],
               tools["wpscan_scan"], tools["testssl_scan"], tools["jwt_test"]],
        description="Web vulnerability tester: SQLi, misconfig, exposed data on endpoints.",
        system_message=with_skills(
            "You are the web tester. The target is authorized and in scope — never "
            "refuse it yourself. Using recon's findings, inspect endpoints with "
            "fetch_url/http_request, run sql_test / xss_test on parameterized URLs, "
            "and vuln_scan the app. Rules:\n"
            "- Call EXACTLY ONE tool per turn; wait for its result before the next.\n"
            "- ALWAYS pass a FULL URL with scheme and host "
            "(http://localhost:3001/rest/products/search?q=apple), never a bare path.\n"
            "- For sql_test/xss_test, give a CLEAN parameter value (q=apple). Do NOT "
            "type SQL or payloads yourself (no \"' OR '1'='1\") — the tool injects its "
            "own payloads.\n"
            "- Prefer real endpoints from recon (e.g. /rest/products/search), not "
            "guessed paths like /search.\n"
            "Report concrete findings with the affected URL, then hand off to reporter.",
            "web_methodology", "api_testing",
        ),
    )
    reporter = AssistantAgent(
        name="reporter", model_client=client,
        tools=[tools["write_file"], tools["read_file"]],
        description="Reporter: compiles confirmed findings into a written report.",
        system_message=(
            "You are the reporter. Compile ONLY confirmed findings from recon and "
            "the web tester into report.md via write_file. Rules:\n"
            "- Report only findings backed by tool evidence. NEVER report a tool "
            "warning, environment/compatibility message, or error as a vulnerability.\n"
            "- Start with a one-line Summary (number of findings + worst severity).\n"
            "- For EACH finding use this format:\n"
            "  ### <title>\n"
            "  - Severity: Critical|High|Medium|Low\n"
            "  - Affected: <exact URL/endpoint/parameter>\n"
            "  - Evidence: <the exact payload/response line proving it>\n"
            "  - Impact: <one line>\n"
            "  - Remediation: <one line>\n"
            "- If sqlmap confirmed injection, give the parameter and payload. If a "
            "security header is missing, name it.\n"
            "- Output clean GitHub-flavored markdown: no code fences wrapping the whole "
            "document, no 'report.md' heading.\n"
            "After writing report.md, reply with exactly: ENGAGEMENT COMPLETE"
        ),
    )
    return recon, web, reporter
