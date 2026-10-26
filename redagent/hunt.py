"""Worklist-driven engagement ('hunt' mode).

Recon seeds a severity-ordered queue of leads; each lead runs ONE tool; a
confirmed finding can push follow-up leads (the chaining hook). Orchestration and
prioritisation live here in Python — deterministic — so the small model never has
to plan a multi-step engagement itself. Scope is still enforced inside every tool.
"""

import json
import re
import time
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlparse, urljoin, parse_qsl

from .config import Config
from .tools import build_tools

SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Lead:
    url: str
    vuln_class: str          # sqli | xss | exposure | misconfig
    tool: str                # tool name to run against url
    reason: str
    severity: str = "medium"


@dataclass
class Finding:
    vuln_class: str
    url: str
    severity: str
    evidence: str


_SENSITIVE = ("ftp", "metrics", ".git", ".env", "backup", "backups", "dump",
              "config", "phpinfo", "server-status", "actuator", "swagger",
              "api-docs", "robots.txt")


def _base(target: str) -> str:
    if "://" not in target:
        target = "http://" + target
    p = urlparse(target)
    return f"{p.scheme}://{p.netloc}"


def seed_leads(base: str, dirb_output: str, crawl_output: str = "") -> list[Lead]:
    """Turn recon output into a prioritised lead queue.

    dirb_output is gobuster's path list; crawl_output (optional) is katana's
    crawled URLs — its parameter-bearing endpoints become sql_test/xss_test leads
    a wordlist alone would miss.
    """
    leads = [
        Lead(base, "misconfig", "vuln_scan", "nuclei baseline scan", "medium"),
        Lead(base, "misconfig", "nikto_scan", "server misconfig/outdated software", "medium"),
    ]
    p = urlparse(base)
    if p.scheme == "https":
        leads.append(Lead(p.netloc, "tls", "testssl_scan",
                          "HTTPS endpoint — check TLS config", "medium"))
    wordpress = False
    for line in dirb_output.splitlines():
        m = re.match(r"(\S+)\s+\(Status:\s*(\d+)\)", line.strip())
        if not m:
            continue
        path, status = m.group(1), int(m.group(2))
        url = base.rstrip("/") + "/" + path.lstrip("/")
        low = path.lower()
        if "search" in low:
            leads.append(Lead(url + "?q=apple", "sqli", "sql_test",
                              f"parameterized endpoint {path}", "high"))
            leads.append(Lead(url + "?q=apple", "xss", "xss_test",
                              f"reflects parameter {path}", "medium"))
        if status == 200 and any(k in low for k in _SENSITIVE):
            leads.append(Lead(url, "exposure", "fetch_url",
                              f"{path} returned 200 (possible exposure)", "high"))
        if any(k in low for k in ("wp-login", "wp-admin", "wp-content", "wp-json", "xmlrpc")):
            wordpress = True
        if any(k in low for k in ("login", "signin", "auth", "token", "session")):
            leads.append(Lead(url, "auth", "fetch_url",
                              f"auth surface {path} — capture token/response", "medium"))
    if wordpress:
        leads.append(Lead(base, "wordpress", "wpscan_scan",
                          "WordPress detected — scan core/plugins/users", "high"))
    # katana-crawled parameter endpoints -> sqli/xss leads. Dedup by endpoint
    # signature (path + the set of param names) so many crawled URLs that differ
    # only in values collapse to one sql_test/xss_test lead per real endpoint.
    base_netloc = urlparse(base).netloc
    seen_sig: set[tuple[str, tuple[str, ...]]] = set()
    for line in crawl_output.splitlines():
        u = line.strip()
        if "?" not in u or not u.startswith(("http://", "https://")):
            continue
        pu = urlparse(u)
        if pu.netloc != base_netloc:
            continue
        keys = tuple(sorted(k for k, _ in parse_qsl(pu.query)))
        sig = (pu.path, keys)
        if not keys or sig in seen_sig:
            continue
        seen_sig.add(sig)
        leads.append(Lead(u, "sqli", "sql_test",
                          f"crawled param endpoint {pu.path}", "high"))
        leads.append(Lead(u, "xss", "xss_test",
                          f"crawled reflected param {pu.path}", "medium"))
    leads.sort(key=lambda l: SEVERITY.get(l.severity, 2))
    return leads


def _is_finding(lead: Lead, result: str) -> tuple[bool, str, str]:
    """(is_finding, severity, evidence) for a tool result."""
    r = result.lower()
    if lead.tool == "sql_test":
        if "is vulnerable" in r or "parameter:" in r or "injectable" in r:
            ev = next((ln for ln in result.splitlines()
                       if "Payload:" in ln or "Parameter:" in ln), result[:200])
            return True, "critical", ev.strip()
    elif lead.tool == "sql_enumerate":
        tables = [ln for ln in result.splitlines() if ln.strip().startswith("|")]
        if tables or "Database:" in result:
            n = len(tables)
            return True, "critical", f"{n} table row(s) enumerated: " + " ".join(tables[:8])[:250]
    elif lead.tool == "xss_test":
        if any(k in r for k in ("[poc]", "[vuln]", "triggered", "reflected xss", "vulnerable")):
            return True, "high", result.splitlines()[0][:200]
    elif lead.tool == "vuln_scan":
        hits = [ln for ln in result.splitlines() if ln.strip().startswith("[")]
        if hits:
            sev = "high" if "[high]" in r or "[critical]" in r else "medium"
            return True, sev, "; ".join(hits[:5])[:300]
    elif lead.tool == "nikto_scan":
        hits = [ln for ln in result.splitlines() if ln.strip().startswith("+ ")]
        if hits:
            return True, "medium", "; ".join(hits[:5])[:300]
    elif lead.tool == "wpscan_scan":
        hits = [ln for ln in result.splitlines() if ln.strip().startswith("[!]")]
        if hits:
            return True, "high", "; ".join(hits[:5])[:300]
    elif lead.tool == "testssl_scan":
        hits = [ln for ln in result.splitlines()
                if any(k in ln for k in ("VULNERABLE", "NOT ok", "WEAK", "expired",
                                         "self signed"))]
        if hits:
            return True, "medium", "; ".join(hits[:5])[:300]
    elif lead.tool == "jwt_test":
        # Match the finding LABELS ("CRITICAL:"/"HIGH:"), not bare words — the
        # clean result literally says "no alg:none / weak-secret issue found".
        if "critical:" in r or "high:" in r:
            return True, "critical" if "critical:" in r else "high", \
                result.replace("\n", " ")[:200]
    elif lead.tool == "secret_scan":
        if "critical:" in r or "high:" in r or "medium:" in r:
            sev = ("critical" if "critical:" in r
                   else "high" if "high:" in r else "medium")
            return True, sev, "leaked secret — " + result.replace("\n", "; ")[:220]
    elif lead.tool == "fetch_url":
        if not result.startswith("HTTP 200"):
            return False, lead.severity, ""
        # A specific sensitive file that downloads at all is an exposure.
        fname = lead.url.rsplit("/", 1)[-1].lower().split("?")[0]
        if fname in ("robots.txt", "sitemap.xml", "humans.txt"):
            return False, "info", ""   # informational, not a real exposure
        if lead.url.lower().endswith(_SENSITIVE_EXT):
            return True, "high", f"downloadable sensitive file ({lead.url.rsplit('/', 1)[-1]})"
        # An exposure-class lead only exists for a path recon already deemed
        # sensitive, so a 200 here IS the exposure — label it by its content.
        if lead.vuln_class == "exposure":
            return True, lead.severity, _exposure_label(lead.url, result)
    return False, lead.severity, ""


def _exposure_label(url: str, result: str) -> str:
    """One-line description of what a sensitive 200 response exposed."""
    body = result.split("\n\n", 1)[-1]
    path = urlparse(url).path or url
    if "listing directory" in result:
        return f"directory listing exposed at {path}"
    if "# HELP" in result or "# TYPE" in result:
        return f"Prometheus metrics exposed at {path}"
    if "BEGIN RSA" in result or "BEGIN PRIVATE" in result:
        return f"private key material exposed at {path}"
    if body.lstrip()[:1] in ("{", "["):
        return f"configuration/JSON data exposed at {path}"
    return f"sensitive endpoint readable without auth (HTTP 200) at {path}"


_SENSITIVE_EXT = (".bak", ".md", ".yml", ".yaml", ".json", ".txt", ".gz", ".zip",
                  ".tar", ".sql", ".env", ".conf", ".ini", ".pem", ".key", ".log")


def derive_followups(lead: Lead, finding: Finding, base: str, result: str) -> list[Lead]:
    """(b) exploit chaining: a confirmed finding opens post-exploitation leads."""
    out: list[Lead] = []
    if lead.vuln_class == "sqli":
        # Confirmed injection -> enumerate the database tables.
        out.append(Lead(lead.url, "sqli-exploit", "sql_enumerate",
                        "enumerate DB tables from confirmed SQLi", "critical"))
    elif lead.vuln_class == "exposure" and "listing directory" in result:
        # Directory listing -> fetch each sensitive-looking file it links. The
        # fetch_url tool truncates the body before the file list, and the hrefs
        # are site-root-relative (ftp/x.bak), so re-fetch the full body here and
        # resolve each link against the base.
        seen_links = set()
        for href in _list_links(lead.url):
            # serve-index hrefs (ftp/x.bak) are relative to the site root, not /ftp/.
            target = urljoin(base.rstrip("/") + "/", href)
            if (not target.startswith(base) or target.rstrip("/") == lead.url.rstrip("/")
                    or target in seen_links or not target.lower().endswith(_SENSITIVE_EXT)):
                continue
            seen_links.add(target)
            out.append(Lead(target, "exposure", "fetch_url",
                            f"sensitive file listed under {urlparse(lead.url).path}", "high"))
    elif lead.vuln_class == "exposure":
        # A readable exposed file/endpoint (not a directory listing) -> scan its
        # body for leaked secrets. Each file fetched out of a listing above is
        # itself an 'exposure' fetch_url lead, so this chains per-file too.
        out.append(Lead(lead.url, "secret", "secret_scan",
                        f"scan exposed {urlparse(lead.url).path} for leaked secrets", "high"))
    return out


_JWT_RE = re.compile(r"eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+")


def _extract_token(text: str) -> str:
    """Pull a JWT out of a login response (JSON token field or raw body)."""
    m = _JWT_RE.search(text)
    return m.group(0) if m else ""


def _authenticate(cfg, base: str) -> str:
    """POST configured creds to the login endpoint; return a captured JWT or ''.
    Scope is enforced; a login_url outside scope is refused."""
    import json as _json
    auth = getattr(cfg, "auth", None)
    if not auth:
        return ""
    url = auth["login_url"]
    try:
        cfg.scope.check(url)
    except Exception as e:
        print(f"[hunt] auth skipped: {e}")
        return ""
    body = _json.dumps({auth["user_field"]: auth["username"],
                        auth["pass_field"]: auth["password"]}).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "redagent"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return _extract_token(r.read(8000).decode("utf-8", "replace"))
    except Exception as e:
        print(f"[hunt] auth failed: {e}")
        return ""


def _list_links(url: str) -> list[str]:
    """Full-body fetch (bounded) of a directory listing, returning its hrefs."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "redagent"})
        with urllib.request.urlopen(req, timeout=15) as r:
            body = r.read(40000).decode("utf-8", "replace")
    except Exception:
        return []
    return re.findall(r'href="([^"]+)"', body)


def run_hunt(target: str, cfg: Config, emit=print) -> None:
    """Run the worklist engagement. `emit` receives each progress line (default
    print; the TUI passes a callback that writes into its log)."""
    tools = build_tools(cfg)
    base = _base(target)
    host = urlparse(base).hostname or ""

    emit(f"[hunt] target: {base}")
    # Fail fast + clearly if the target is in scope but not actually serving HTTP,
    # rather than running the whole worklist and reporting a misleading "0 findings".
    try:
        cfg.scope.check(base)
    except Exception as e:
        emit(f"[hunt] refused (out of scope): {e}")
        return
    try:
        req = urllib.request.Request(base, headers={"User-Agent": "redagent"})
        urllib.request.urlopen(req, timeout=8)
    except Exception as e:
        emit(f"[hunt] target unreachable: {base} is not serving HTTP ({e}). "
             "Is it up? (docker start juice-shop)")
        return
    # Reuse a recent run's recon + findings for this target instead of scanning
    # from scratch (and hammering the target) every time.
    cache = _load_cache(cfg)
    entry = cache.get(base)
    fresh = bool(cfg.hunt_cache_ttl and entry
                 and (time.time() - entry.get("ts", 0)) < cfg.hunt_cache_ttl)
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    if fresh:
        age = int((time.time() - entry["ts"]) // 60)
        emit(f"[hunt] reusing cached recon + {len(entry['findings'])} finding(s) "
             f"({age}m old; set hunt_cache_ttl: 0 for a fresh scan).")
        dirb = entry["dirb"]
        crawl = entry.get("crawl", "")
        stack = entry.get("stack", "")
        findings = [Finding(**f) for f in entry["findings"]]
        seen = {tuple(k) for k in entry["done"]}
    else:
        emit("[hunt] recon: nmap_web_scan + dir_bruteforce + web_crawl + web_fingerprint + port_scan ...")
        nmap = tools["nmap_web_scan"](host)
        if nmap.startswith("refused"):
            emit(f"[hunt] {nmap}")
            return
        dirb = tools["dir_bruteforce"](base)
        # katana crawl + httpx fingerprint are best-effort extra context; a missing
        # binary or error must not abort the hunt, so swallow anything unusable.
        crawl = tools["web_crawl"](base)
        if crawl.startswith(("refused", "error", "(no")):
            crawl = ""
        stack = tools["web_fingerprint"](base)
        if stack.startswith(("refused", "error", "(")):
            stack = ""
        elif stack:
            emit(f"[hunt] fingerprint: {stack}")
        # naabu port sweep: surface services on non-standard ports. Best-effort —
        # folded into the recon-context line so it is cached and shown in the report.
        ports = tools["port_scan"](host)
        if not ports.startswith(("refused", "error", "(")):
            emit(f"[hunt] open ports: {ports}")
            stack = (stack + " | " if stack else "") + f"open ports: {ports}"

    queue = seed_leads(base, dirb, crawl)
    # Fingerprint-driven lead: if httpx tags the app as WordPress, make sure the
    # WordPress scan runs even when recon paths didn't reveal wp-* endpoints.
    if "wordpress" in stack.lower() and not any(l.tool == "wpscan_scan" for l in queue):
        queue.append(Lead(base, "wordpress", "wpscan_scan",
                          "httpx fingerprint: WordPress", "high"))
        queue.sort(key=lambda l: SEVERITY.get(l.severity, 2))
    token = _authenticate(cfg, base)
    if token:
        emit(f"[hunt] authenticated — captured session JWT ({token[:18]}...)")
        queue.insert(0, Lead(token, "auth", "jwt_test",
                             "inspect captured session JWT", "high"))
    pending = [l for l in queue if (l.url, l.vuln_class) not in seen]
    emit(f"[hunt] {len(queue)} leads queued; {len(pending)} new to test "
         f"({len(seen)} already done).")

    step = 0
    while queue:
        lead = queue.pop(0)
        key = (lead.url, lead.vuln_class)
        if key in seen:
            continue
        seen.add(key)
        step += 1
        emit(f"\n[{step}] {lead.vuln_class.upper():9} {lead.tool} -> {lead.url}"
              f"\n      why: {lead.reason}")
        result = tools[lead.tool](lead.url)
        if result.startswith("refused"):
            emit(f"      refused: {result}")
            continue
        # Any tool result may expose a JWT (login/config responses): chain jwt_test.
        if lead.tool != "jwt_test":
            for tok in set(re.findall(r"eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+", result)):
                if (tok, "auth") not in seen and not any(l.url == tok for l in queue):
                    queue.append(Lead(tok, "auth", "jwt_test",
                                      f"JWT found in {lead.tool} response", "high"))
                    emit(f"      +chain: auth jwt_test -> (token {tok[:18]}...)")
        hit, sev, ev = _is_finding(lead, result)
        if hit:
            f = Finding(lead.vuln_class, lead.url, sev, ev)
            findings.append(f)
            emit(f"      >>> FINDING [{sev}]: {ev[:120]}")
            for nl in derive_followups(lead, f, base, result):
                if (nl.url, nl.vuln_class) not in seen:
                    queue.append(nl)
                    emit(f"      +chain: {nl.vuln_class} {nl.tool} -> {nl.url}")
            queue.sort(key=lambda l: SEVERITY.get(l.severity, 2))
        else:
            emit("      (nothing confirmed)")

    # Optional analyst<->executor discussion: the analyst proposes follow-up tests,
    # the engine executes the valid/in-scope ones, new findings fold back in.
    deepdive_md = ""
    if getattr(cfg, "deep_dive", False) and findings:
        deepdive_md = _deep_dive(cfg, base, tools, findings, seen, emit)

    report = _report(base, findings, stack)
    # Phase-batched analyst pass: all tool work is done, so loading the analyst
    # model now costs at most one model swap (no interleaving). Best-effort.
    if findings:
        emit(f"[hunt] analyst ({cfg.analyst_model}) reviewing findings …")
        from .analyst import analyze
        assessment = analyze(cfg, report)
        if assessment:
            report += "\n\n---\n\n" + assessment + "\n"
            emit("[hunt] analyst assessment added to report.")
        else:
            emit("[hunt] analyst unavailable — report stands without it.")
    if deepdive_md:
        report += "\n\n---\n\n" + deepdive_md + "\n"

    out = Path(cfg.workspace) / "report.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")
    emit(f"[hunt] {len(findings)} finding(s). report -> {out}")

    # Persist recon + findings so a re-run reuses them (within hunt_cache_ttl).
    if cfg.hunt_cache_ttl:
        cache[base] = {
            "ts": entry["ts"] if fresh else time.time(),
            "dirb": dirb,
            "crawl": crawl,
            "stack": stack,
            "findings": [asdict(f) for f in findings],
            "done": sorted(list(k) for k in seen),
        }
        _save_cache(cfg, cache)


def _load_cache(cfg) -> dict:
    try:
        return json.loads((Path(cfg.workspace) / ".hunt_cache.json").read_text())
    except Exception:
        return {}


def _save_cache(cfg, data: dict) -> None:
    try:
        (Path(cfg.workspace) / ".hunt_cache.json").write_text(json.dumps(data))
    except Exception:
        pass


def _deep_dive(cfg, base, tools, findings, seen, emit) -> str:
    """Bounded analyst<->executor exchange: the analyst (DeepHat) proposes up to 3
    follow-up tests, the engine executes the valid/in-scope ones deterministically
    (no model swap during execution), new findings fold into `findings`, then the
    analyst reviews the results. Returns a markdown '## Deep-dive' block ('' if none).
    """
    from .analyst import propose, review_results
    emit("[hunt] deep-dive: analyst proposing follow-up tests …")
    proposals = propose(cfg, _report(base, findings), list(tools.keys()))
    if not proposals:
        emit("[hunt] deep-dive: no proposals (analyst unavailable or none).")
        return ""
    log = []
    for pr in proposals:
        tool, url, why = pr["tool"], pr["url"], pr.get("why", "")
        if tool not in tools:
            log.append(f"- SKIP unknown tool `{tool}` ({url})")
            continue
        try:
            cfg.scope.check(url)
        except Exception:
            log.append(f"- SKIP out-of-scope `{url}`")
            continue
        if (url, "deep") in seen:
            continue
        seen.add((url, "deep"))
        emit(f"[deep-dive] {tool} -> {url}  ({why[:60]})")
        result = tools[tool](url)
        hit, sev, ev = _is_finding(Lead(url, "deep", tool, why, "medium"), result)
        if hit:
            findings.append(Finding("deep-dive", url, sev, ev))
            emit(f"      >>> NEW FINDING [{sev}]: {ev[:100]}")
            log.append(f"- **{tool}** {url} → FINDING [{sev}]: {ev[:150]}")
        else:
            log.append(f"- {tool} {url} → {result[:120].strip()}")
    verdict = review_results(cfg, "\n".join(log))
    md = "## Deep-dive (analyst-proposed)\n" + "\n".join(log)
    if verdict:
        md += "\n\n**Analyst verdict:** " + verdict
    return md


def _report(base: str, findings: list[Finding], stack: str = "") -> str:
    findings = sorted(findings, key=lambda f: SEVERITY.get(f.severity, 2))
    worst = findings[0].severity if findings else "none"
    lines = [f"# Engagement report — {base}", "",
             f"**Summary:** {len(findings)} finding(s); worst severity: {worst}.", ""]
    if stack:
        lines += [f"**Stack:** {stack}", ""]
    for f in findings:
        lines += [f"### {f.vuln_class.upper()} — {f.url}",
                  f"- Severity: {f.severity.capitalize()}",
                  f"- Affected: {f.url}",
                  f"- Evidence: {f.evidence}", ""]
    if not findings:
        lines.append("_No confirmed findings._")
    return "\n".join(lines)
