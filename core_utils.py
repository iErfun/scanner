#!/usr/bin/env python3
"""Shared helpers — session, colors, report, safe I/O."""
from __future__ import annotations

import json
import os
import random
import re
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    requests = None  # type: ignore


class C:
    R = "[0m"
    B = "[1m"
    DIM = "[2m"
    RED = "[91m"
    GREEN = "[92m"
    YEL = "[93m"
    CYN = "[96m"
    WHT = "[97m"
    GOLD = "[38;2;255;200;60m"
    NEON = "[38;2;0;255;200m"
    PURP = "[38;2;168;85;247m"
    GRAY = "[38;2;100;105;120m"
    AQUA = "[38;2;34;211;238m"
    CRIM = "[38;2;248;113;113m"
    LIME = "[38;2;163;230;53m"
    PINK = "[38;2;244;114;182m"
    FRAME = "[38;2;139;92;246m"


UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
]


def session(timeout: float = 12.0, proxies: Optional[Dict[str, str]] = None,
            verify: bool = False, headers: Optional[Dict[str, str]] = None):
    if requests is None:
        raise RuntimeError("requests required: pip install requests")
    s = requests.Session()
    s.verify = verify
    base_headers = {
        "User-Agent": random.choice(UA_POOL),
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close",
    }
    if headers:
        base_headers.update(headers)
    s.headers.update(base_headers)
    if proxies:
        s.proxies.update(proxies)
    s.timeout = timeout
    return s


def preflight_attack():
    """Shared speed / proxy / fake-IP / header setup for attack modules.
    Returns dict: delay, threads, proxies, headers, speed_label, mode_label
    """
    print(f"\n{C.FRAME}{C.B}+{'-'*56}+{C.R}")
    print(f"{C.FRAME}{C.B}|{C.R}  {C.B}SELECT SCAN SPEED{C.R}")
    print(f"{C.FRAME}{C.B}+{'-'*56}+{C.R}")
    print(f"  {C.GREEN}1){C.R} Super Slow   delay=1.00  threads=2")
    print(f"  {C.GREEN}2){C.R} Slow         delay=0.50  threads=4")
    print(f"  {C.GREEN}3){C.R} Normal       delay=0.20  threads=8")
    print(f"  {C.GREEN}4){C.R} Fast         delay=0.05  threads=16")
    print(f"  {C.GREEN}5){C.R} Super Fast   delay=0.01  threads=32")
    print(f"  {C.GREEN}6){C.R} Custom")
    print(f"{C.FRAME}{C.B}+{'-'*56}+{C.R}")
    ch = input(f"{C.AQUA}[?] speed (1-6): {C.R}").strip()
    table = {
        "1": (1.00, 2, "Super Slow"),
        "2": (0.50, 4, "Slow"),
        "3": (0.20, 8, "Normal"),
        "4": (0.05, 16, "Fast"),
        "5": (0.01, 32, "Super Fast"),
    }
    if ch == "6":
        try:
            delay = float(input(f"{C.AQUA}[?] delay sec: {C.R}").strip() or "0.2")
        except ValueError:
            delay = 0.2
        try:
            threads = int(input(f"{C.AQUA}[?] threads: {C.R}").strip() or "8")
        except ValueError:
            threads = 8
        threads = max(1, min(64, threads))
        speed_label = f"Custom ({threads}t/{delay}s)"
    else:
        delay, threads, speed_label = table.get(ch, (0.20, 8, "Normal"))

    print(f"\n{C.FRAME}{C.B}+{'-'*56}+{C.R}")
    print(f"{C.FRAME}{C.B}|{C.R}  {C.B}CONNECTION / IP MODE{C.R}")
    print(f"{C.FRAME}{C.B}+{'-'*56}+{C.R}")
    print(f"  {C.GREEN}1){C.R} Own IP")
    print(f"  {C.GREEN}2){C.R} Custom Proxy (paste or file path)")
    print(f"  {C.GREEN}3){C.R} Fake IP headers (faker)")
    print(f"  {C.GREEN}4){C.R} Proxy + Fake IP")
    print(f"{C.FRAME}{C.B}+{'-'*56}+{C.R}")
    mc = input(f"{C.AQUA}[?] mode (1-4): {C.R}").strip()

    proxies = None
    headers: Dict[str, str] = {}
    mode_label = "Own IP"
    proxy_list = []

    if mc in ("2", "4"):
        first = input(f"{C.AQUA}[?] proxy URL or proxies.txt path: {C.R}").strip()
        if first and os.path.isfile(first):
            with open(first, "r", encoding="utf-8", errors="ignore") as f:
                proxy_list = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        elif first:
            proxy_list = [first]
            while True:
                line = input(f"{C.AQUA}[?] +proxy (empty=done): {C.R}").strip()
                if not line:
                    break
                proxy_list.append(line)
        if proxy_list:
            p = random.choice(proxy_list)
            proxies = {"http": p, "https": p}
            mode_label = f"Proxy x{len(proxy_list)}"
            print(f"  {C.GREEN}[+]{C.R} using {p}")

    if mc in ("3", "4"):
        try:
            from faker import Faker
            ip = Faker().ipv4_public()
            headers.update({
                "X-Forwarded-For": ip,
                "X-Real-IP": ip,
                "X-Client-IP": ip,
                "CF-Connecting-IP": ip,
                "True-Client-IP": ip,
                "Forwarded": f"for={ip};proto=https",
            })
            mode_label = (mode_label + " + FakeIP") if mc == "4" else f"Fake IP ({ip})"
            print(f"  {C.GREEN}[+]{C.R} fake IP headers → {ip}")
        except Exception as e:
            print(f"  {C.YEL}[!] faker: {e}{C.R}")

    print(f"  {C.GREEN}[+]{C.R} speed={speed_label}  mode={mode_label}  delay={delay}s  threads={threads}")
    return {
        "delay": delay,
        "threads": threads,
        "proxies": proxies,
        "headers": headers,
        "speed_label": speed_label,
        "mode_label": mode_label,
    }


def get(s, url, **kw):
    try:
        return s.get(url, allow_redirects=kw.pop("allow_redirects", False),
                     timeout=kw.pop("timeout", getattr(s, "timeout", 8)), **kw)
    except Exception:
        return None


def post(s, url, **kw):
    try:
        return s.post(url, allow_redirects=kw.pop("allow_redirects", False),
                      timeout=kw.pop("timeout", getattr(s, "timeout", 8)), **kw)
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
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def strip_scheme(host: str) -> str:
    host = (host or "").strip().lower()
    host = host.replace("https://", "").replace("http://", "")
    return host.split("/")[0].split(":")[0]


def finding(kind: str, detail: str, evidence: str = "", severity: str = "info") -> dict:
    return {
        "type": kind,
        "detail": detail,
        "evidence": (evidence or "")[:400],
        "severity": severity,
        "ts": datetime.now(timezone.utc).isoformat(),
    }


def print_finding(kind: str, detail: str, evidence: str = "", severity: str = "med") -> None:
    color = C.RED if severity in ("high", "critical") else C.YEL if severity == "med" else C.CYN
    print(f"{color}{C.B}[!] {kind}{C.R}")
    print(f"    {C.YEL}{detail}{C.R}")
    if evidence:
        print(f"    {C.GRAY}{evidence[:160].replace(chr(10), ' ')}{C.R}")


def reports_dir() -> str:
    import sys
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    d = os.path.join(base, "reports")
    os.makedirs(d, exist_ok=True)
    return d


def save_json_report(name: str, data: Any) -> str:
    path = os.path.join(reports_dir(), f"{name}_{int(time.time())}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    return path


def save_text_report(name: str, title: str, lines: List[str]) -> str:
    path = os.path.join(reports_dir(), f"{name}_{int(time.time())}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"{'=' * 60}\n  {title}\n{'=' * 60}\n\n")
        for line in lines:
            f.write(line + "\n")
    return path


def pause() -> None:
    try:
        input(f"\n{C.GRAY}[Press Enter]{C.R}")
    except EOFError:
        pass


def resolve_host(host: str) -> List[str]:
    ips: List[str] = []
    try:
        for info in socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


def safe_int(val: str, default: int) -> int:
    try:
        return int(str(val).strip())
    except Exception:
        return default
