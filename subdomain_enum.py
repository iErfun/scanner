#!/usr/bin/env python3
"""Subdomain enumeration — DNS brute + crt.sh + ThreatCrowd + HackerTarget + wordlist file."""
from __future__ import annotations

import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Set

from core_utils import (
    C,
    get,
    pause,
    print_finding,
    reports_dir,
    resolve_host,
    save_json_report,
    save_text_report,
    session,
    strip_scheme,
)

COMMON = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "vpn", "api", "dev", "staging", "test", "admin", "portal", "cdn",
    "app", "beta", "m", "mobile", "blog", "shop", "store", "support", "status",
    "git", "gitlab", "jenkins", "ci", "grafana", "monitor", "db", "mysql",
    "postgres", "redis", "elastic", "kibana", "s3", "assets", "static", "img",
    "images", "media", "files", "upload", "backup", "old", "new", "stage",
    "uat", "qa", "demo", "sandbox", "internal", "intranet", "corp", "office",
    "remote", "owa", "exchange", "autodiscover", "cpanel", "whm", "webdisk",
    "direct", "server", "node", "edge", "proxy", "gw", "gateway", "auth",
    "sso", "login", "secure", "ssl", "vpn1", "vpn2", "mx", "mx1", "mx2",
    "panel", "dashboard", "backend", "frontend", "ws", "wss", "socket",
    "mail1", "mail2", "ns3", "ns4", "cdn1", "cdn2", "static1", "img1",
    "api1", "api2", "v1", "v2", "docs", "wiki", "jira", "confluence",
    "helpdesk", "tickets", "crm", "erp", "hr", "finance", "billing",
    "pay", "payment", "checkout", "cart", "cdn-edge", "origin",
]


# ── UI ───────────────────────────────────────────────────────────────────────
def clear():
    os.system("cls" if os.name == "nt" else "clear")


def print_banner():
    crimson = getattr(C, "CRIM", getattr(C, "PURP", ""))
    gold = getattr(C, "GOLD", getattr(C, "YEL", ""))
    gray = getattr(C, "GRAY", getattr(C, "DIM", ""))
    dim = getattr(C, "DIM", "")
    reset = C.R
    clear()
    print(f"""{crimson}{C.B}
  ▄█████ ▄▄ ▄▄ ▄▄▄▄  ▄▄▄▄   ▄▄▄  ▄▄   ▄▄  ▄▄▄  ▄▄ ▄▄  ▄▄ 
  ▀▀▀▄▄▄ ██ ██ ██▄██ ██▀██ ██▀██ ██▀▄▀██ ██▀██ ██ ███▄██ 
  █████▀ ▀███▀ ██▄█▀ ████▀ ▀███▀ ██   ██ ██▀██ ██ ██ ▀██
  
""")


def status(msg: str, kind: str = "info") -> None:
    m = {
        "ok":   (C.GREEN,  "[+]"),
        "err":  (getattr(C, "CRIM", C.RED), "[!]"),
        "warn": (getattr(C, "YEL", C.YELLOW), "[~]"),
        "info": (C.CYN,    "[*]"),
        "hit":  (C.GREEN,  "[!]"),
    }
    c, t = m.get(kind, (C.CYN, "[*]"))
    print(f"  {c}{t} {msg}{C.R}")


# ── core ─────────────────────────────────────────────────────────────────────
def resolve(host: str) -> List[str]:
    return resolve_host(host)


def crtsh(domain: str, timeout: float = 25.0) -> Set[str]:
    found: Set[str] = set()
    s = session(timeout=timeout)
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    r = get(s, url, allow_redirects=True, timeout=timeout)
    if not r or r.status_code != 200:
        return found
    try:
        rows = r.json()
    except Exception:
        return found
    for row in rows if isinstance(rows, list) else []:
        name = (row.get("name_value") or "") + "\n" + (row.get("common_name") or "")
        for line in name.splitlines():
            line = line.strip().lower().lstrip("*.")
            if line.endswith("." + domain) or line == domain:
                found.add(line)
    return found


def threatcrowd(domain: str, timeout: float = 15.0) -> Set[str]:
    found: Set[str] = set()
    s = session(timeout=timeout)
    r = get(s, f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
            allow_redirects=True, timeout=timeout)
    if not r or r.status_code != 200:
        return found
    try:
        data = r.json()
        for sub in data.get("subdomains") or []:
            sub = str(sub).strip().lower()
            if sub.endswith("." + domain) or sub == domain:
                found.add(sub)
    except Exception:
        pass
    return found


def hackertarget(domain: str, timeout: float = 15.0) -> Set[str]:
    found: Set[str] = set()
    s = session(timeout=timeout)
    r = get(s, f"https://api.hackertarget.com/hostsearch/?q={domain}",
            allow_redirects=True, timeout=timeout)
    if not r or r.status_code != 200 or not r.text:
        return found
    for line in r.text.splitlines():
        part = line.split(",")[0].strip().lower()
        if part.endswith("." + domain) or part == domain:
            found.add(part)
    return found


def load_wordlist(path: Optional[str]) -> List[str]:
    words = list(COMMON)
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip().lower()
                if w and not w.startswith("#") and w not in words:
                    words.append(w)
    return words


def brute(domain: str, wordlist: List[str], threads: int = 50) -> Set[str]:
    found: Set[str] = set()

    def check(sub: str):
        host = f"{sub}.{domain}"
        ips = resolve(host)
        if ips:
            return host, ips
        return None

    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        futs = {ex.submit(check, w): w for w in wordlist}
        for fut in as_completed(futs):
            res = fut.result()
            if res:
                host, ips = res
                found.add(host)
                print(f"  {C.GREEN}[dns]{C.R} {host}  "
                      f"{getattr(C, 'GRAY', C.DIM)}{', '.join(ips)}{C.R}")
    return found


def run(domain: str = None):
    print_banner()
    domain = strip_scheme(domain or input(f"  {C.AQUA}[?] Domain (example.com): {C.R}"))
    if not domain:
        status("empty domain", "err")
        pause()
        return

    wl_path = input(f"  {C.AQUA}[?] Extra wordlist path (Enter=built-in only): {C.R}").strip()
    threads_s = input(f"  {C.AQUA}[?] Threads [50]: {C.R}").strip() or "50"
    try:
        threads = max(1, min(200, int(threads_s)))
    except ValueError:
        threads = 50

    all_hosts: Set[str] = {domain}
    sources = {}

    status("crt.sh ...", "info")
    certs = crtsh(domain)
    sources["crt.sh"] = len(certs)
    for h in sorted(certs):
        ips = resolve(h)
        print(f"  {C.GREEN}[crt]{C.R} {h}  "
              f"{getattr(C, 'GRAY', C.DIM)}{', '.join(ips) if ips else '-'}{C.R}")
    all_hosts |= certs

    status("ThreatCrowd ...", "info")
    tc = threatcrowd(domain)
    sources["threatcrowd"] = len(tc)
    for h in sorted(tc - all_hosts):
        print(f"  {C.GREEN}[tc]{C.R}  {h}")
    all_hosts |= tc

    status("HackerTarget ...", "info")
    ht = hackertarget(domain)
    sources["hackertarget"] = len(ht)
    for h in sorted(ht - all_hosts):
        print(f"  {C.GREEN}[ht]{C.R}  {h}")
    all_hosts |= ht

    words = load_wordlist(wl_path or None)
    status(f"DNS brute ({len(words)} words, {threads} threads) ...", "info")
    bruted = brute(domain, words, threads=threads)
    sources["dns_brute"] = len(bruted)
    all_hosts |= bruted

    sorted_hosts = sorted(all_hosts)
    print()
    status(f"Total unique hosts: {len(sorted_hosts)}", "hit")
    for k, v in sources.items():
        print(f"    {getattr(C, 'GRAY', C.DIM)}{k}: {v}{C.R}")

    path = save_text_report("subdomains", f"Subdomains — {domain}", sorted_hosts)
    jpath = save_json_report(
        "subdomains",
        {"domain": domain, "hosts": sorted_hosts, "sources": sources},
    )
    status(f"saved → {path}", "ok")
    status(f"saved → {jpath}", "ok")
    pause()


if __name__ == "__main__":
    run()
