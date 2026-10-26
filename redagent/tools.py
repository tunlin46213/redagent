"""Tool set. build_tools(cfg) returns plain functions bound to the config, so
each one enforces the engagement scope and writes inside the workspace. Every
tool that takes a URL/host calls cfg.scope.check() first and refuses otherwise.
"""

import re
import json
import shutil
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from ddgs import DDGS

from .scope import ScopeError


def _clean_params(url: str) -> str:
    """Strip manual SQL-injection syntax a model may have typed into a parameter
    value (e.g. q=apple' AND '1'='1 -> q=apple). sqlmap injects its OWN payloads,
    so each parameter just needs a clean, valid baseline value."""
    parts = urlparse(url)
    if not parts.query:
        return url
    cleaned = []
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        m = re.match(r"[A-Za-z0-9_.\-@ ]*", v)
        safe = (m.group(0) if m else "").strip()
        cleaned.append((k, safe or "1"))
    return urlunparse(parts._replace(query=urlencode(cleaned)))


def _nmap_trim(out: str) -> str:
    """nmap -sV dumps a huge service-fingerprint block for services it can't
    identify (the per-port `fingerprint-strings:` sub-blocks and the trailing
    SF-Port... submission block). That noise floods a small model and derails
    it mid-engagement; keep the port table and real script output, drop the
    fingerprint dump. Ports come from the table; headers come from fetch_url."""
    kept, skipping_fp = [], False
    for ln in out.splitlines():
        s = ln.strip()
        if ("unrecognized despite returning data" in s
                or s.startswith("==============NEXT SERVICE FINGERPRINT")
                or s.startswith("SF:") or s.startswith("SF-Port")):
            break
        if s.startswith("| fingerprint-strings:"):
            skipping_fp = True
            continue
        if skipping_fp:
            if s.startswith("|_"):      # script terminator: block done
                skipping_fp = False
            elif s.startswith("|"):     # still inside the fingerprint block
                continue
            else:                       # non-pipe line ends the block; keep it
                skipping_fp = False
                kept.append(ln)
            continue
        kept.append(ln)
    return "\n".join(kept).rstrip()


# High-signal secret patterns (severity, label, regex). Kept deliberately tight —
# a pentest wants real leaks (keys/tokens), not every form field named "password".
_SECRET_PATTERNS = [
    ("critical", "private key",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("critical", "AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("critical", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("high", "GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b")),
    ("high", "GitHub PAT", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}\b")),
    ("high", "Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("high", "Slack webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    ("high", "Stripe secret key", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b")),
    ("high", "JWT", re.compile(r"\beyJ[\w-]+\.eyJ[\w-]+\.[\w-]+")),
    ("medium", "credential assignment", re.compile(
        r"(?i)(?:api[_-]?key|secret|password|passwd|token)\s*[:=]\s*[\"']?[A-Za-z0-9/+=_\-]{8,}")),
]


def _redact(s: str) -> str:
    s = s.strip().strip("\"'")
    return f"{s[:4]}…{s[-2:]}" if len(s) > 8 else f"{s[:2]}…"


def scan_secrets(text: str) -> list[tuple[str, str, str]]:
    """Scan text for leaked secrets. Returns distinct (severity, label, redacted)
    tuples — pure, side-effect-free, so it is unit-tested directly."""
    out: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for sev, label, rx in _SECRET_PATTERNS:
        for m in rx.finditer(text):
            sample = m.group(0)
            if (label, sample) in seen:
                continue
            seen.add((label, sample))
            out.append((sev, label, _redact(sample)))
    return out


def _cors_verdict(sent_origin: str, acao: str | None, acac: str | None) -> str | None:
    """Grade one CORS probe into a labelled finding (or None). Pure/testable.
    acao/acac are the Access-Control-Allow-Origin / -Credentials response headers."""
    creds = (acac or "").strip().lower() == "true"
    if acao and acao == sent_origin:
        if sent_origin == "null":
            return (("HIGH" if creds else "MEDIUM")
                    + ": reflects 'null' Origin — a sandboxed iframe/file origin can read responses"
                    + (" WITH credentials." if creds else "."))
        if creds:
            return (f"CRITICAL: reflects arbitrary Origin ({sent_origin}) with "
                    "credentials — any site can read authenticated responses.")
        return (f"HIGH: reflects arbitrary Origin ({sent_origin}) — any site can "
                "read responses (no credentials).")
    if acao == "*":
        return ("MEDIUM: Access-Control-Allow-Origin: * — responses are world-readable"
                + (" WITH credentials (invalid+dangerous)." if creds else " (no credentials)."))
    return None


def _naabu_ports(output: str) -> list[int]:
    """Parse naabu's 'host:port' lines into a sorted unique port list, ignoring
    its banner/log noise. Pure, so it is unit-tested directly."""
    ports: set[int] = set()
    for ln in output.splitlines():
        m = re.match(r"^[^\s:]+:(\d{1,5})$", ln.strip())
        if m and 0 < int(m.group(1)) <= 65535:
            ports.add(int(m.group(1)))
    return sorted(ports)


def build_tools(cfg):
    WS: Path = cfg.workspace
    # The bundled curated list carries the deep, app-specific paths (e.g.
    # rest/products/search) a generic SecLists list lacks. When an override is set,
    # MERGE both (curated first, deduped) so a thorough scan keeps the deep paths
    # AND gains the override's breadth — rather than replacing one with the other.
    _BUNDLED_WL = Path(__file__).resolve().parent / "wordlists" / "common_paths.txt"
    _override = getattr(cfg, "wordlist", "")
    if _override and Path(_override).resolve() != _BUNDLED_WL.resolve():
        seen, lines = set(), []
        for src in (_BUNDLED_WL, Path(_override)):
            try:
                for ln in src.read_text(errors="ignore").splitlines():
                    w = ln.strip()
                    if w and w not in seen:
                        seen.add(w)
                        lines.append(w)
            except Exception:
                pass
        try:
            merged = WS / ".wordlist_merged.txt"
            merged.write_text("\n".join(lines) + "\n", encoding="utf-8")
            WORDLIST = merged
        except Exception:
            WORDLIST = _BUNDLED_WL
    else:
        WORDLIST = _BUNDLED_WL

    def _safe_path(path: str) -> Path:
        p = (WS / path).resolve()
        if not str(p).startswith(str(WS.resolve())):
            raise ValueError("path escapes workspace")
        return p

    def _have(binary: str) -> bool:
        return shutil.which(binary) is not None

    def _run(cmd: list[str], timeout: int | None = None) -> str:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout or cfg.tool_timeout, cwd=WS)
        except subprocess.TimeoutExpired:
            return "error: command timed out"
        return ((p.stdout or "") + (p.stderr or ""))[:4000] or f"(exit {p.returncode})"

    def web_search(query: str) -> str:
        """Look up CURRENT or EXTERNAL information you do not already know (latest
        versions, CVEs, docs, news). Not for this computer. Input: a search query."""
        try:
            results = DDGS().text(query, max_results=5)
        except Exception as e:
            return f"search error: {e}"
        return "\n".join(f"- {r.get('title')}: {r.get('body')}" for r in results) or "no results"

    def fetch_url(url: str) -> str:
        """Fetch a web page (GET) and return status, headers, and body start.
        Use to inspect a site/endpoint. Input: a full in-scope URL."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        if not url.startswith(("http://", "https://")):
            return "error: url must start with http:// or https://"
        req = urllib.request.Request(url, headers={"User-Agent": "redagent"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                h = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
                return f"HTTP {r.status}\n{h}\n\n{r.read(8000).decode('utf-8','replace')[:4000]}"
        except urllib.error.HTTPError as e:
            return f"HTTP {e.code}\n{e.headers}\n\n{e.read(800).decode('utf-8','replace')}"
        except Exception as e:
            return f"fetch error: {e}"

    def http_request(method: str, url: str, headers: str = "", body: str = "") -> str:
        """Send a custom HTTP request (any method/headers/body) to an in-scope URL.
        Use for logins, APIs, and injection tests. headers = JSON object string."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        hdrs = {"User-Agent": "redagent"}
        if headers.strip():
            try:
                hdrs.update(json.loads(headers))
            except json.JSONDecodeError:
                return "error: headers must be a JSON object string"
        req = urllib.request.Request(url, data=body.encode() if body else None,
                                     headers=hdrs, method=method.upper())
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                h = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
                return f"HTTP {r.status}\n{h}\n\n{r.read(2500).decode('utf-8','replace')}"
        except urllib.error.HTTPError as e:
            return f"HTTP {e.code}\n{e.headers}\n\n{e.read(1500).decode('utf-8','replace')}"
        except Exception as e:
            return f"request error: {e}"

    def nmap_web_scan(target: str) -> str:
        """Scan an in-scope host for common web ports + service versions (safe
        fixed scripts). Input: a hostname or IP."""
        try:
            host = cfg.scope.check(target)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        return _nmap_trim(_run(
            ["nmap", "-sV", "-Pn", "-p", "80,443,3000,3001,8080,8443",
             "--script", "http-title,http-headers,http-methods", "--", host]))

    def dir_bruteforce(url: str) -> str:
        """Discover hidden directories/endpoints on an in-scope web server
        (gobuster + bundled wordlist, with SPA wildcard handling). Input: base URL."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        cmd = ["gobuster", "dir", "-u", url, "-w", str(WORDLIST), "-q", "-t", "20",
               "--no-error", "-k"]
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                cmd += ["--exclude-length", str(len(r.read()))]
        except Exception:
            pass
        return _run(cmd)

    def sql_test(url: str, data: str = "") -> str:
        """Test an in-scope URL for SQL injection with sqlmap (non-interactive).
        Input: a full URL whose query holds the parameter to test
        (http://host/rest/products/search?q=apple). Pass `data` ONLY for a real
        POST body with DIFFERENT fields — never repeat a query param in `data`."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        url = _clean_params(url)  # strip any manual SQL the model typed into params
        # The 7B often echoes a URL query param into `data` too (data="q=apple"
        # for ?q=apple). sqlmap then treats it as a POST body, tests the wrong
        # channel ("POST parameter 'q' does not appear to be dynamic") and misses
        # the GET injection. Drop data keys already in the query; keep genuine
        # POST-only keys so real POST bodies still work.
        if data:
            query_keys = {k for k, _ in parse_qsl(urlparse(url).query,
                                                   keep_blank_values=True)}
            data = "&".join(kv for kv in data.split("&")
                            if kv.split("=", 1)[0] not in query_keys)
        # --technique=BEU drops the slow time-based (T) and stacked (S) tests,
        # which otherwise take minutes per URL and blow the engagement budget.
        # Boolean + Error + Union is enough to confirm most injections.
        cmd = ["sqlmap", "-u", url, "--batch", "--level", "2", "--risk", "1",
               "--technique=BEU", "--flush-session", "--disable-coloring"]
        if data:
            cmd += ["--data", data]
        out = _run(cmd)
        keep = [ln for ln in out.splitlines() if any(k in ln.lower() for k in
                ("injectable", "parameter", "payload", "back-end dbms",
                 "vulnerable", "does not seem", "type:", "title:"))]
        return "\n".join(keep)[:3000] or out[-1500:]

    def sql_enumerate(url: str) -> str:
        """Post-exploitation of a CONFIRMED SQL injection: enumerate the database
        tables via sqlmap on an in-scope URL. Run only after sql_test confirmed
        'q is vulnerable'. Input: the same URL+param (q=apple) that was injectable."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        url = _clean_params(url)
        cmd = ["sqlmap", "-u", url, "--batch", "--level", "2", "--risk", "1",
               "--technique=BEU", "--tables", "--disable-coloring"]
        out = _run(cmd, timeout=240)
        # Keep real table rows (| Name |) + the Database/count lines; drop sqlmap's
        # ASCII-art banner, which also starts with '|' and would pollute evidence.
        row = re.compile(r"^\|\s*[A-Za-z_][\w$]*\s*\|$")
        keep = [ln for ln in out.splitlines()
                if row.match(ln.strip()) or "Database:" in ln
                or re.search(r"\[\d+ tables?\]", ln)]
        return "\n".join(keep)[:3000] or "(no tables enumerated)"

    def vuln_scan(url: str) -> str:
        """Scan an in-scope web app for known vulns/misconfig with nuclei.
        Input: a base URL."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        # Tag-filter keeps nuclei fast (exposures/misconfig/default-logins) instead
        # of running the full template set, which blows the engagement time budget.
        # Broad coverage: run the full template set (no tag restriction) filtered to
        # medium+ severity so CVEs, misconfig, exposures, takeovers, injection, etc.
        # are all checked. Severity filter keeps it from running forever on info noise.
        out = _run(["nuclei", "-u", url, "-silent", "-nc",
                    "-severity", "medium,high,critical"], timeout=300)
        # Drop nuclei/Go runtime noise (e.g. the harmless sonic/ast CPU warning)
        # so the model never mistakes a warning for a finding. Real findings look
        # like "[template-id] [proto] [severity] url".
        findings = [ln for ln in out.splitlines()
                    if ln.strip() and "sonic/ast" not in ln
                    and not ln.lower().startswith("warning")]
        return "\n".join(findings) or "(no findings)"

    def xss_test(url: str) -> str:
        """Test an in-scope URL with parameters for cross-site scripting (XSS)
        using dalfox. Input: a URL with a query parameter, e.g.
        http://localhost:3001/rest/products/search?q=apple ."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        url = _clean_params(url)  # dalfox injects its own payloads; strip any the
                                  # model hand-typed (q=<script>...> -> q=1)
        out = _run(["dalfox", "url", url, "--no-color", "--no-spinner",
                    "--silence", "--skip-bav"], timeout=240)
        lines = [ln for ln in out.splitlines()
                 if any(k in ln for k in ("[POC]", "[VULN]", "[G]", "[R]", "triggered", "reflected"))]
        return "\n".join(lines)[:3000] or "(no XSS reported)"

    def web_crawl(url: str) -> str:
        """Crawl an in-scope web app for real endpoints and parameters with katana
        (JS-aware). Surfaces routes/params a wordlist misses, to feed sql_test/
        xss_test. Input: a base URL. Param-bearing URLs are listed first."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        if not _have("katana"):
            return "error: katana not installed (copy from the kali sandbox or `go install github.com/projectdiscovery/katana/cmd/katana@latest`)"
        # -fs fqdn keeps the crawl ON the target host (never fetches out-of-scope
        # links it finds, e.g. a third-party CDN); depth 2 + JS crawl is a good
        # time/coverage trade-off for a lab app.
        out = _run(["katana", "-u", url, "-d", "2", "-jc", "-fs", "fqdn",
                    "-c", "10", "-timeout", "10", "-silent", "-nc"], timeout=120)
        host = urlparse(url).netloc
        seen, params, other = set(), [], []
        for ln in out.splitlines():
            u = ln.strip()
            if not u.startswith(("http://", "https://")):
                continue
            p = urlparse(u)
            if p.netloc != host:                   # same host only (scope hygiene)
                continue
            if "{{" in u or "%7B%7B" in u:          # Angular/template placeholders
                continue
            if u in seen:
                continue
            seen.add(u)
            (params if p.query else other).append(u)
        return "\n".join(params + other)[:3000] or "(no endpoints crawled)"

    def web_fingerprint(url: str) -> str:
        """Fingerprint an in-scope web endpoint with httpx: status, title, server,
        and detected technologies (CMS/frameworks/languages). Input: a base URL.
        One concise line — use it to orient an engagement and pick targeted tools."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        if not _have("httpx"):
            return "error: httpx not installed (copy from the kali sandbox or `go install github.com/projectdiscovery/httpx/cmd/httpx@latest`)"
        try:
            p = subprocess.run(
                ["httpx", "-u", url, "-json", "-silent", "-nc", "-td", "-title",
                 "-server", "-sc"],
                capture_output=True, text=True, timeout=60, cwd=WS)
        except subprocess.TimeoutExpired:
            return "error: httpx timed out"
        out = (p.stdout or "").strip().splitlines()
        if not out:
            return "(no response)"
        try:
            d = json.loads(out[0])
        except json.JSONDecodeError:
            return "(fingerprint failed)"
        parts = [f"HTTP {d.get('status_code', '?')}"]
        if d.get("title"):
            parts.append(f"title: {d['title']}")
        if d.get("webserver"):
            parts.append(f"server: {d['webserver']}")
        if d.get("tech"):
            parts.append("tech: " + ", ".join(d["tech"]))
        if d.get("content_type"):
            parts.append(f"type: {d['content_type']}")
        return " | ".join(parts)

    def port_scan(host: str) -> str:
        """Discover open TCP ports on an in-scope host with naabu (fast,
        unprivileged connect scan of the top 1000 ports). Surfaces services on
        non-standard ports that the fixed web-port nmap scan misses. Input: a
        hostname or IP."""
        try:
            h = cfg.scope.check(host)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        if not _have("naabu"):
            return "error: naabu not installed (copy from the kali sandbox or `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest`)"
        out = _run(["naabu", "-host", h, "-s", "connect", "-tp", "1000", "-silent"],
                   timeout=150)
        ports = _naabu_ports(out)
        return ", ".join(str(p) for p in ports) if ports else "(no open ports found)"

    def cors_check(url: str) -> str:
        """Check an in-scope URL's CORS policy for misconfiguration: does it reflect
        an arbitrary Origin or 'null', or use '*' — and is Access-Control-Allow-
        Credentials set (which turns a reflected Origin into cross-site theft of
        authenticated data)? Input: a full in-scope URL."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"

        def _probe(origin: str):
            req = urllib.request.Request(
                url, headers={"User-Agent": "redagent", "Origin": origin})
            try:
                with urllib.request.urlopen(req, timeout=15) as r:
                    h = r.headers
            except urllib.error.HTTPError as e:
                h = e.headers
            except Exception:
                return (None, None)
            return (h.get("Access-Control-Allow-Origin"),
                    h.get("Access-Control-Allow-Credentials"))

        evil = "https://evil.example"
        findings = []
        acao, acac = _probe(evil)
        v = _cors_verdict(evil, acao, acac)
        if v:
            findings.append(v)
        nacao, nacac = _probe("null")
        v = _cors_verdict("null", nacao, nacac)
        if v:
            findings.append(v)
        if not findings:
            return f"no CORS misconfig (ACAO for {evil}: {acao or 'not returned'})"
        return "\n".join(findings)

    def secret_scan(url: str) -> str:
        """Fetch an in-scope URL (e.g. an exposed .env / .bak / config / backup
        file) and scan its body for leaked secrets: private keys, cloud/API keys,
        tokens, JWTs, credential assignments. Input: a full in-scope URL. Run it on
        a sensitive file an engagement already found readable."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        req = urllib.request.Request(url, headers={"User-Agent": "redagent"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                body = r.read(200000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            body = e.read(200000).decode("utf-8", "replace")
        except Exception as e:
            return f"fetch error: {e}"
        hits = scan_secrets(body)
        if not hits:
            return "no secrets found"
        # Label each line CRITICAL:/HIGH:/MEDIUM: so hunt._is_finding can grade it.
        return "\n".join(f"{sev.upper()}: {label} ({sample})"
                         for sev, label, sample in hits[:20])

    def read_file(path: str) -> str:
        """Read a text file from the workspace. Input: a relative filename."""
        try:
            return _safe_path(path).read_text(encoding="utf-8")[:8000]
        except Exception as e:
            return f"read error: {e}"

    def write_file(path: str, content: str) -> str:
        """Save text to a file in the workspace. Inputs: relative filename + content."""
        try:
            fp = _safe_path(path)
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(content, encoding="utf-8")
            return f"wrote {len(content)} chars to {fp.relative_to(WS)}"
        except Exception as e:
            return f"write error: {e}"

    def nikto_scan(url: str) -> str:
        """Scan an in-scope web server for misconfig/outdated software/dangerous
        files with nikto. Input: a base URL. Broad but noisy; use once per host."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        if not _have("nikto"):
            return "error: nikto not installed (sudo pacman -S nikto)"
        out = _run(["nikto", "-h", url, "-ask", "no", "-nointeractive",
                    "-maxtime", "120s"], timeout=150)
        # Real findings are "+ " lines minus the run banner/summary. Mid-scan
        # "ERROR:" lines are normal, so don't let them nuke a valid result.
        skip = ("Target ", "Start Time", "End Time", "host(s) tested",
                "requests:", "Nikto v", "No CGI", "Platform:", "Server:")
        keep = [ln for ln in out.splitlines()
                if ln.startswith("+ ") and not any(s in ln for s in skip)]
        if keep:
            return "\n".join(keep)[:3000]
        # No findings — did it even run? (e.g. missing perl-xml-writer)
        if "Required module" in out or not out.strip() or out.strip().startswith("(exit"):
            return f"nikto error (did not run): {out.strip()[:300]}"
        return "(no notable nikto findings)"

    def wpscan_scan(url: str) -> str:
        """Scan an in-scope WordPress site for vulnerable core/plugins/themes and
        exposed users with wpscan. Input: a base URL. WordPress targets only."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        if not _have("wpscan"):
            return "error: wpscan not installed (sudo pacman -S wpscan)"
        out = _run(["wpscan", "--url", url, "--no-banner", "--random-user-agent",
                    "--format", "cli-no-color"], timeout=240)
        keep = [ln for ln in out.splitlines() if ln.strip().startswith(("[+]", "[!]", "[i]"))]
        return "\n".join(keep)[:3000] or out[-1500:]

    def testssl_scan(target: str) -> str:
        """Check an in-scope HTTPS endpoint's TLS config for weak protocols,
        ciphers, and cert issues with testssl.sh. Input: the in-scope target as
        host:port (e.g. localhost:443). Only meaningful for TLS/HTTPS services."""
        try:
            cfg.scope.check(target)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        binary = "testssl" if _have("testssl") else "testssl.sh"
        if not _have(binary):
            return "error: testssl not installed (sudo pacman -S testssl.sh)"
        out = _run([binary, "--quiet", "--color", "0", "--warnings", "off",
                    target], timeout=300)
        keep = [ln for ln in out.splitlines()
                if any(k in ln for k in ("VULNERABLE", "NOT ok", "offered", "WEAK",
                                         "insecure", "expired", "self signed"))]
        return "\n".join(keep)[:3000] or "(no TLS issues surfaced; or not an HTTPS port)"

    def jwt_test(token: str) -> str:
        """Decode a JSON Web Token and flag weaknesses: 'alg:none' acceptance and
        a weak HMAC signing secret (dictionary check). Input: the raw JWT string.
        No network/scope — operates on a token you already captured."""
        import base64, hashlib, hmac, json as _json
        def _b64(seg: str) -> bytes:
            return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
        parts = token.strip().split(".")
        if len(parts) < 2:
            return "error: not a JWT (expected header.payload.signature)"
        try:
            header = _json.loads(_b64(parts[0]))
            payload = _json.loads(_b64(parts[1]))
        except Exception as e:
            return f"error: cannot decode JWT ({e})"
        findings = []
        alg = str(header.get("alg", "")).lower()
        if alg in ("none", ""):
            findings.append("CRITICAL: alg:none — signature not verified, token is forgeable.")
        if alg.startswith("hs") and len(parts) == 3:
            signing = f"{parts[0]}.{parts[1]}".encode()
            sig = _b64(parts[2])
            digest = {"hs256": hashlib.sha256, "hs384": hashlib.sha384,
                      "hs512": hashlib.sha512}.get(alg)
            weak = ["secret", "password", "changeme", "jwt", "key", "admin", "test",
                    "1234", "123456", "qwerty", "secretkey", "supersecret", "token"]
            for cand in weak:
                if digest and hmac.compare_digest(
                        hmac.new(cand.encode(), signing, digest).digest(), sig):
                    findings.append(f"HIGH: weak HMAC secret cracked = '{cand}' — "
                                    "tokens can be forged.")
                    break
        head = _json.dumps(header)
        body = _json.dumps(payload)[:800]
        return (f"header: {head}\npayload: {body}\n"
                + ("\n".join(findings) if findings else "no alg:none / weak-secret issue found"))

    return {
        "web_search": web_search, "fetch_url": fetch_url, "http_request": http_request,
        "nmap_web_scan": nmap_web_scan, "dir_bruteforce": dir_bruteforce,
        "sql_test": sql_test, "sql_enumerate": sql_enumerate,
        "vuln_scan": vuln_scan, "xss_test": xss_test, "web_crawl": web_crawl,
        "web_fingerprint": web_fingerprint,
        "nikto_scan": nikto_scan, "wpscan_scan": wpscan_scan,
        "testssl_scan": testssl_scan, "jwt_test": jwt_test,
        "secret_scan": secret_scan, "port_scan": port_scan, "cors_check": cors_check,
        "read_file": read_file, "write_file": write_file,
    }
