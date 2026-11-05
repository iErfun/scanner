#!/usr/bin/env python3
"""Pull JS from a page and hunt API keys / tokens / secrets."""
from __future__ import annotations

import re
from typing import List, Set
from urllib.parse import urljoin

from core_utils import C, get, normalize_url, pause, print_finding, save_json_report, session

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("Generic API key", re.compile(r"(?i)(api[_-]?key|apikey|secret|token)[\"'\s:=]+[\"']([A-Za-z0-9_\-]{16,})[\"']")),
    ("Bearer", re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*")),
    ("Stripe", re.compile(r"(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{20,}")),
]

SCRIPT_SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)


def extract_scripts(html: str, base: str) -> List[str]:
    urls = []
    for m in SCRIPT_SRC.finditer(html or ""):
        urls.append(urljoin(base, m.group(1)))
    return urls


def scan_text(text: str, source: str) -> List[dict]:
    hits = []
    for name, rx in SECRET_PATTERNS:
        for m in rx.finditer(text or ""):
            val = m.group(0)
            if len(val) > 8:
                hits.append({"type": name, "match": val[:80], "source": source})
    return hits


def run():
    print(f"\n{C.PURP}{C.B}  JS / Page Secret Hunter{C.R}\n")
    url = normalize_url(input(f"{C.AQUA}[?] URL: {C.R}").strip())
    if not url:
        return
    s = session()
    r = get(s, url, allow_redirects=True, timeout=12)
    if not r:
        print(f"{C.RED}[!] no response{C.R}")
        pause()
        return
    findings = scan_text(r.text or "", url)
    scripts = extract_scripts(r.text or "", url)
    print(f"{C.GOLD}[*] {len(scripts)} external scripts{C.R}")
    seen: Set[str] = set()
    for src in scripts[:40]:
        if src in seen:
            continue
        seen.add(src)
        rr = get(s, src, allow_redirects=True, timeout=10)
        if not rr or not rr.text:
            continue
        hits = scan_text(rr.text, src)
        for h in hits:
            findings.append(h)
            print_finding(h["type"], h["source"], h["match"], "high")
    # also page body
    for h in scan_text(r.text or "", url):
        if h not in findings:
            findings.append(h)
            print_finding(h["type"], h["source"], h["match"], "high")
    print(f"\n{C.NEON}[+] Secrets-like matches: {len(findings)}{C.R}")
    if findings:
        path = save_json_report("js_secrets", {"url": url, "findings": findings})
        print(f"{C.GREEN}[+] Saved: {path}{C.R}")
    pause()


if __name__ == "__main__":
    run()
