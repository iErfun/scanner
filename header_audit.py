#!/usr/bin/env python3
"""HTTP security header audit + tech hints from response headers/body."""
from __future__ import annotations

from typing import Dict, List, Tuple

from core_utils import C, get, normalize_url, pause, print_finding, save_json_report, session

# header -> (required?, severity if missing, note)
CHECKS = [
    ("Strict-Transport-Security", True, "high", "Missing HSTS"),
    ("Content-Security-Policy", True, "med", "Missing CSP"),
    ("X-Content-Type-Options", True, "med", "Missing nosniff"),
    ("X-Frame-Options", True, "med", "Clickjacking risk"),
    ("Referrer-Policy", False, "low", "Missing Referrer-Policy"),
    ("Permissions-Policy", False, "low", "Missing Permissions-Policy"),
    ("Cross-Origin-Opener-Policy", False, "low", "Missing COOP"),
    ("Cross-Origin-Resource-Policy", False, "low", "Missing CORP"),
]

BAD_SERVER_LEAK = ("X-Powered-By", "Server", "X-AspNet-Version", "X-AspNetMvc-Version")

TECH_SIGS = [
    ("wp-content", "WordPress"),
    ("Drupal.settings", "Drupal"),
    ("__NEXT_DATA__", "Next.js"),
    ("ng-version", "Angular"),
    ("react", "React (hint)"),
    ("laravel_session", "Laravel"),
    ("cf-ray", "Cloudflare"),
    ("x-amz-request-id", "AWS"),
    ("x-vercel-id", "Vercel"),
    ("x-github-request-id", "GitHub"),
]


def audit(url: str) -> Dict:
    s = session()
    url = normalize_url(url)
    r = get(s, url, allow_redirects=True, timeout=10)
    findings: List[dict] = []
    if not r:
        print(f"{C.RED}[!] no response{C.R}")
        return {"url": url, "findings": findings}
    headers = {k.lower(): v for k, v in r.headers.items()}
    print(f"{C.GOLD}[*] {url}  status={r.status_code}{C.R}\n")

    for name, required, sev, note in CHECKS:
        if name.lower() not in headers:
            findings.append({"type": "missing-header", "header": name, "severity": sev, "note": note})
            print_finding("Missing Header", f"{name} — {note}", severity=sev)
        else:
            print(f"  {C.GREEN}[+]{C.R} {name}: {headers[name.lower()][:80]}")

    for name in BAD_SERVER_LEAK:
        if name.lower() in headers:
            findings.append({"type": "info-leak", "header": name, "value": headers[name.lower()], "severity": "low"})
            print_finding("Info Leak", f"{name}: {headers[name.lower()]}", severity="low")

    body = r.text or ""
    techs = []
    for sig, name in TECH_SIGS:
        if sig.lower() in body.lower() or sig.lower() in str(headers):
            techs.append(name)
    techs = sorted(set(techs))
    if techs:
        print(f"\n{C.NEON}[*] Tech hints: {', '.join(techs)}{C.R}")
        findings.append({"type": "tech", "techs": techs, "severity": "info"})

    cookies = r.headers.get("Set-Cookie", "")
    if cookies:
        low = cookies.lower()
        if "httponly" not in low:
            print_finding("Cookie", "Set-Cookie without HttpOnly", severity="med")
            findings.append({"type": "cookie", "issue": "missing HttpOnly", "severity": "med"})
        if "secure" not in low and url.startswith("https"):
            print_finding("Cookie", "Set-Cookie without Secure on HTTPS", severity="med")
            findings.append({"type": "cookie", "issue": "missing Secure", "severity": "med"})

    return {"url": url, "status": r.status_code, "findings": findings, "techs": techs}


def run():
    print(f"\n{C.PURP}{C.B}  Header / Tech Audit{C.R}\n")
    url = input(f"{C.AQUA}[?] URL: {C.R}").strip()
    if not url:
        return
    result = audit(url)
    if result["findings"]:
        path = save_json_report("header_audit", result)
        print(f"\n{C.GREEN}[+] Saved: {path}{C.R}")
    pause()


if __name__ == "__main__":
    run()
