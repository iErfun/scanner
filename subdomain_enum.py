#!/usr/bin/env python3
"""Subdomain enumeration — DNS brute + crt.sh + common wordlist."""
from __future__ import annotations

import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set

from core_utils import C, get, normalize_url, pause, print_finding, root_of, save_text_report, session

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
]


def resolve(host: str) -> List[str]:
    ips = []
    try:
        for info in socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


def crtsh(domain: str, timeout: float = 20.0) -> Set[str]:
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


def brute(domain: str, wordlist: List[str], threads: int = 40) -> Set[str]:
    found: Set[str] = set()
    def check(sub):
        host = f"{sub}.{domain}"
        ips = resolve(host)
        if ips:
            return host, ips
        return None
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(check, w): w for w in wordlist}
        for fut in as_completed(futs):
            res = fut.result()
            if res:
                host, ips = res
                found.add(host)
                print(f"  {C.GREEN}[+]{C.R} {host}  {C.GRAY}{', '.join(ips)}{C.R}")
    return found


def run(domain: str = None):
    print(f"\n{C.PURP}{C.B}  Subdomain Enumeration{C.R}\n")
    domain = (domain or input(f"{C.AQUA}[?] Domain (example.com): {C.R}").strip()).lower()
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    if not domain:
        print(f"{C.RED}[!] empty domain{C.R}")
        return
    print(f"{C.GOLD}[*] crt.sh ...{C.R}")
    certs = crtsh(domain)
    for h in sorted(certs):
        ips = resolve(h)
        print(f"  {C.GREEN}[crt]{C.R} {h}  {C.GRAY}{', '.join(ips) if ips else '-'}{C.R}")
    print(f"{C.GOLD}[*] DNS brute ({len(COMMON)} words) ...{C.R}")
    bruted = brute(domain, COMMON)
    all_hosts = sorted(certs | bruted | {domain})
    print(f"\n{C.NEON}[+] Total unique hosts: {len(all_hosts)}{C.R}")
    path = save_text_report("subdomains", f"Subdomains — {domain}", all_hosts)
    print(f"{C.GREEN}[+] Saved: {path}{C.R}")
    pause()


if __name__ == "__main__":
    run()
