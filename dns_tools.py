#!/usr/bin/env python3
"""DNS tools: zone transfer attempt, record dump, takeovers-ish CNAME check."""
from __future__ import annotations

import socket
from typing import List, Tuple

from core_utils import C, pause, print_finding, save_text_report

try:
    import dns.resolver
    import dns.zone
    import dns.query
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


def resolve_ns(domain: str) -> List[str]:
    if not HAS_DNSPYTHON:
        return []
    try:
        ans = dns.resolver.resolve(domain, "NS")
        return [str(r.target).rstrip(".") for r in ans]
    except Exception:
        return []


def zone_transfer(domain: str, ns: str) -> List[str]:
    if not HAS_DNSPYTHON:
        return []
    try:
        z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=8))
        names = []
        for name in z.nodes.keys():
            names.append(f"{name}.{domain}".replace("@.", ""))
        return names
    except Exception:
        return []


def query_types(domain: str) -> List[Tuple[str, str]]:
    out = []
    if not HAS_DNSPYTHON:
        # fallback A only
        try:
            ips = socket.getaddrinfo(domain, None)
            for i in ips:
                out.append(("A", i[4][0]))
        except Exception:
            pass
        return out
    for rtype in ("A", "AAAA", "MX", "TXT", "CNAME", "SOA"):
        try:
            ans = dns.resolver.resolve(domain, rtype)
            for r in ans:
                out.append((rtype, str(r).rstrip(".")))
        except Exception:
            continue
    return out


# dangling CNAME fingerprints (common takeover targets)
TAKEOVER_FINGERPRINTS = [
    "github.io", "herokuapp.com", "s3.amazonaws.com", "cloudfront.net",
    "azurewebsites.net", "ghost.io", "shopify.com", "surge.sh",
    "bitbucket.io", "pantheonsite.io", "netlify.app", "vercel.app",
]


def check_takeover_hint(domain: str) -> List[str]:
    hints = []
    records = query_types(domain)
    for rtype, val in records:
        if rtype == "CNAME":
            for fp in TAKEOVER_FINGERPRINTS:
                if fp in val.lower():
                    hints.append(f"CNAME → {val} (possible takeover surface: {fp})")
    return hints


def run():
    print(f"\n{C.PURP}{C.B}  DNS Tools{C.R}\n")
    if not HAS_DNSPYTHON:
        print(f"{C.YEL}[!] dnspython not installed — limited mode (A records only){C.R}")
        print(f"{C.GRAY}    pip install dnspython{C.R}\n")
    domain = input(f"{C.AQUA}[?] Domain: {C.R}").strip().lower()
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    if not domain:
        return
    lines = []
    print(f"{C.GOLD}[*] Records for {domain}{C.R}")
    for rtype, val in query_types(domain):
        print(f"  {C.GREEN}{rtype:6}{C.R} {val}")
        lines.append(f"{rtype}\t{val}")
    ns_list = resolve_ns(domain)
    if ns_list:
        print(f"\n{C.GOLD}[*] NS: {', '.join(ns_list)}{C.R}")
        for ns in ns_list:
            print(f"{C.GOLD}[*] AXFR try @ {ns}{C.R}")
            names = zone_transfer(domain, ns)
            if names:
                print_finding("Zone Transfer", f"{ns} allowed AXFR — {len(names)} names", severity="high")
                lines.append(f"AXFR@{ns}: {len(names)} names")
                for n in names[:50]:
                    print(f"  {C.RED}{n}{C.R}")
                    lines.append(n)
            else:
                print(f"  {C.GRAY}refused / failed{C.R}")
    for h in check_takeover_hint(domain):
        print_finding("Takeover hint", h, severity="med")
        lines.append(h)
    if lines:
        path = save_text_report("dns_tools", f"DNS — {domain}", lines)
        print(f"{C.GREEN}[+] Saved: {path}{C.R}")
    pause()


if __name__ == "__main__":
    run()
