#!/usr/bin/env python3
"""Shared helpers for XOMLSX modules — session, colors, report, safe I/O."""
from __future__ import annotations

import json
import random
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    requests = None


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


UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
]


def session(proxies: Optional[dict] = None, timeout: float = 8.0) -> "requests.Session":
    if not requests:
        raise RuntimeError("requests is required")
    s = requests.Session()
    s.verify = False
    s.headers.update({
        "User-Agent": random.choice(UA_POOL),
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close",
    })
    if proxies:
        s.proxies.update(proxies)
    s.timeout = timeout
    return s


def get(s, url, **kw):
    try:
        return s.get(url, allow_redirects=kw.pop("allow_redirects", False),
                     timeout=kw.pop("timeout", 8), **kw)
    except Exception:
        return None


def post(s, url, **kw):
    try:
        return s.post(url, allow_redirects=kw.pop("allow_redirects", False),
                      timeout=kw.pop("timeout", 8), **kw)
    except Exception:
        return None


def params_from_url(url: str) -> List[str]:
    return list(parse_qs(urlparse(url).query).keys())


def inject(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(qs, doseq=True), p.fragment))


def root_of(url: str) -> str:
    p = urlparse(url if "://" in url else "http://" + url)
    return f"{p.scheme}://{p.netloc}"


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def finding(kind: str, detail: str, evidence: str = "", severity: str = "info") -> dict:
    return {
        "type": kind,
        "detail": detail,
        "evidence": (evidence or "")[:400],
        "severity": severity,
        "ts": datetime.now(timezone.utc).isoformat(),
    }


def print_finding(kind: str, detail: str, evidence: str = "", severity: str = "med"):
    color = C.RED if severity in ("high", "critical") else C.YEL if severity == "med" else C.CYN
    print(f"{color}{C.B}[!] {kind}{C.R}")
    print(f"    {C.YEL}{detail}{C.R}")
    if evidence:
        print(f"    {C.GRAY}{evidence[:160].replace(chr(10), ' ')}{C.R}")


def save_json_report(name: str, data: Any) -> str:
    path = f"{name}_{int(time.time())}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    return path


def save_text_report(name: str, title: str, lines: List[str]) -> str:
    path = f"{name}_{int(time.time())}.txt"
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"{'=' * 60}\n  {title}\n{'=' * 60}\n\n")
        for line in lines:
            f.write(line + "\n")
    return path


def pause():
    input(f"\n{C.GRAY}[Press Enter]{C.R}")
