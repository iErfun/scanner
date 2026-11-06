#!/usr/bin/env python3
"""Lightweight technology / fingerprint detector from headers + body."""
from __future__ import annotations

import re
from typing import List

from core_utils import preflight_attack, C, get, normalize_url, pause, save_json_report, session

FINGERPRINTS = [
    ("WordPress", re.compile(r"wp-content|wp-includes|wordpress", re.I)),
    ("Drupal", re.compile(r"Drupal\.settings|X-Drupal", re.I)),
    ("Joomla", re.compile(r"Joomla!|/media/jui/", re.I)),
    ("Laravel", re.compile(r"laravel_session|XSRF-TOKEN", re.I)),
    ("Django", re.compile(r"csrfmiddlewaretoken|django", re.I)),
    ("Express", re.compile(r"X-Powered-By:\s*Express", re.I)),
    ("nginx", re.compile(r"Server:\s*nginx", re.I)),
    ("Apache", re.compile(r"Server:\s*Apache", re.I)),
    ("IIS", re.compile(r"Server:\s*Microsoft-IIS", re.I)),
    ("PHP", re.compile(r"X-Powered-By:\s*PHP|PHPSESSID", re.I)),
    ("ASP.NET", re.compile(r"X-AspNet|ASP\.NET|__VIEWSTATE", re.I)),
    ("React", re.compile(r"react|data-reactroot|_next/static", re.I)),
    ("Vue", re.compile(r"__vue__|vue\.js|data-v-", re.I)),
    ("Angular", re.compile(r"ng-version|angular", re.I)),
    ("Cloudflare", re.compile(r"cf-ray|cloudflare", re.I)),
    ("Shopify", re.compile(r"cdn\.shopify|Shopify\.theme", re.I)),
    ("Magento", re.compile(r"Mage\.Cookies|magento", re.I)),
    ("jQuery", re.compile(r"jquery[.-]", re.I)),
]


def detect(url: str, proxies=None, headers=None) -> dict:
    s = session(proxies=proxies, headers=headers)
    r = get(s, url, allow_redirects=True, timeout=12)
    if not r:
        return {"error": "no response"}
    blob = "\n".join(f"{k}: {v}" for k, v in r.headers.items()) + "\n" + (r.text or "")[:200000]
    hits: List[str] = []
    for name, rx in FINGERPRINTS:
        if rx.search(blob):
            hits.append(name)
    return {
        "url": url,
        "final_url": str(r.url),
        "status": r.status_code,
        "server": r.headers.get("Server", ""),
        "powered_by": r.headers.get("X-Powered-By", ""),
        "tech": hits,
    }


def run(url: str = None):
    print(f"\n{C.PURP}{C.B}  Tech / Fingerprint Detect{C.R}\n")
    url = normalize_url(url or input(f"{C.AQUA}[?] URL: {C.R}"))
    if not url:
        pause()
        return
    cfg = preflight_attack()
    data = detect(url, proxies=cfg["proxies"], headers=cfg["headers"])
    if data.get("error"):
        print(f"{C.RED}[!] {data['error']}{C.R}")
        pause()
        return
    print(f"{C.NEON}[+] {data['status']} {data['final_url']}{C.R}")
    if data.get("server"):
        print(f"  Server: {data['server']}")
    if data.get("powered_by"):
        print(f"  X-Powered-By: {data['powered_by']}")
    for t in data.get("tech") or []:
        print(f"  {C.GREEN}[tech]{C.R} {t}")
    if not data.get("tech"):
        print(f"  {C.GRAY}no strong fingerprint{C.R}")
    path = save_json_report("tech_detect", data)
    print(f"{C.GREEN}[+] Saved: {path}{C.R}")
    pause()


if __name__ == "__main__":
    run()
