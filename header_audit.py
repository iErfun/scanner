#!/usr/bin/env python3
"""HTTP security header audit + tech fingerprint hints."""
from __future__ import annotations

from typing import Dict, List, Tuple

from core_utils import C, get, normalize_url, pause, print_finding, save_json_report, session

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("high", "Missing HSTS"),
    "Content-Security-Policy": ("high", "Missing CSP"),
    "X-Content-Type-Options": ("med", "Missing X-Content-Type-Options"),
    "X-Frame-Options": ("med", "Missing X-Frame-Options / clickjacking risk"),
    "Referrer-Policy": ("low", "Missing Referrer-Policy"),
    "Permissions-Policy": ("low", "Missing Permissions-Policy"),
    "X-XSS-Protection": ("info", "Legacy X-XSS-Protection absent (ok on modern browsers)"),
    "Cross-Origin-Opener-Policy": ("low", "Missing COOP"),
    "Cross-Origin-Resource-Policy": ("low", "Missing CORP"),
}

LEAK_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Varnish", "Via", "X-Backend-Server",
]


def audit(url: str) -> dict:
    s = session(timeout=12)
    r = get(s, url, allow_redirects=True, timeout=12)
    if not r:
        return {"error": "no response", "url": url}
    headers = {k: v for k, v in r.headers.items()}
    missing = []
    present = []
    for h, (sev, msg) in SECURITY_HEADERS.items():
        if h.lower() not in {k.lower() for k in headers}:
            missing.append({"header": h, "severity": sev, "detail": msg})
        else:
            # case-insensitive fetch
            val = next(v for k, v in headers.items() if k.lower() == h.lower())
            present.append({"header": h, "value": val})
    leaks = []
    for h in LEAK_HEADERS:
        for k, v in headers.items():
            if k.lower() == h.lower():
                leaks.append({"header": k, "value": v})
    return {
        "url": url,
        "final_url": str(r.url),
        "status": r.status_code,
        "missing": missing,
        "present": present,
        "leaks": leaks,
        "all_headers": headers,
    }


def run(url: str = None):
    print(f"\n{C.PURP}{C.B}  Header Security Audit{C.R}\n")
    url = normalize_url(url or input(f"{C.AQUA}[?] URL: {C.R}"))
    if not url:
        pause()
        return
    print(f"{C.GOLD}[*] Fetching {url} ...{C.R}")
    data = audit(url)
    if data.get("error"):
        print(f"{C.RED}[!] {data['error']}{C.R}")
        pause()
        return
    print(f"{C.NEON}[+] Status {data['status']} → {data['final_url']}{C.R}")
    for m in data["missing"]:
        print_finding("Missing Header", m["detail"], m["header"], m["severity"])
    for L in data["leaks"]:
        print_finding("Info Leak", L["header"], L["value"], "med")
    for p in data["present"]:
        print(f"  {C.GREEN}[ok]{C.R} {p['header']}: {C.GRAY}{p['value'][:80]}{C.R}")
    path = save_json_report("header_audit", data)
    print(f"{C.GREEN}[+] Saved: {path}{C.R}")
    pause()


if __name__ == "__main__":
    run()
