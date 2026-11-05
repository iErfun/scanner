#!/usr/bin/env python3
"""DNS tools — records, AXFR attempt, reverse, zone-ish dump."""
from __future__ import annotations

import socket
from typing import Dict, List

from core_utils import C, pause, resolve_host, save_json_report, strip_scheme

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.rdatatype
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV"]


def query_records(domain: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    if not HAS_DNSPYTHON:
        # fallback A only
        ips = resolve_host(domain)
        if ips:
            out["A"] = ips
        return out
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            out[rtype] = [r.to_text() for r in answers]
        except Exception:
            pass
    return out


def try_axfr(domain: str) -> Dict[str, List[str]]:
    results: Dict[str, List[str]] = {}
    if not HAS_DNSPYTHON:
        return results
    try:
        ns_ans = dns.resolver.resolve(domain, "NS")
        nameservers = [str(r.target).rstrip(".") for r in ns_ans]
    except Exception:
        return results
    for ns in nameservers:
        try:
            ns_ips = resolve_host(ns)
            if not ns_ips:
                continue
            z = dns.zone.from_xfr(dns.query.xfr(ns_ips[0], domain, lifetime=8))
            names = []
            for name, node in z.nodes.items():
                names.append(str(name) + "." + domain if str(name) != "@" else domain)
            results[ns] = sorted(set(names))
        except Exception as e:
            results[ns] = [f"AXFR denied/failed: {e}"]
    return results


def reverse_lookup(ip: str) -> List[str]:
    try:
        host, aliases, _ = socket.gethostbyaddr(ip)
        return [host] + list(aliases)
    except Exception:
        return []


def run(domain: str = None):
    print(f"\n{C.PURP}{C.B}  DNS Tools{C.R}\n")
    if not HAS_DNSPYTHON:
        print(f"{C.YEL}[!] dnspython not installed — limited mode (A/reverse only){C.R}")
        print(f"{C.GRAY}    pip install dnspython{C.R}\n")

    print(f"  1) Query records")
    print(f"  2) AXFR attempt")
    print(f"  3) Reverse lookup")
    print(f"  0) Back")
    choice = input(f"\n{C.AQUA}[?] Choice: {C.R}").strip()

    if choice == "1":
        domain = strip_scheme(domain or input(f"{C.AQUA}[?] Domain: {C.R}"))
        if not domain:
            pause()
            return
        print(f"{C.GOLD}[*] Querying {domain} ...{C.R}")
        recs = query_records(domain)
        if not recs:
            print(f"{C.RED}[!] no records{C.R}")
        for k, vals in recs.items():
            print(f"  {C.GREEN}{k}{C.R}")
            for v in vals:
                print(f"    {v}")
        path = save_json_report("dns_records", {"domain": domain, "records": recs})
        print(f"{C.GREEN}[+] Saved: {path}{C.R}")
        pause()
    elif choice == "2":
        domain = strip_scheme(domain or input(f"{C.AQUA}[?] Domain: {C.R}"))
        if not domain:
            pause()
            return
        print(f"{C.GOLD}[*] AXFR against NS of {domain} ...{C.R}")
        ax = try_axfr(domain)
        if not ax:
            print(f"{C.RED}[!] no NS / AXFR unavailable{C.R}")
        for ns, names in ax.items():
            print(f"  {C.CYN}NS {ns}{C.R}")
            for n in names[:200]:
                print(f"    {n}")
            if len(names) > 200:
                print(f"    ... +{len(names)-200} more")
        path = save_json_report("dns_axfr", {"domain": domain, "axfr": ax})
        print(f"{C.GREEN}[+] Saved: {path}{C.R}")
        pause()
    elif choice == "3":
        ip = input(f"{C.AQUA}[?] IP: {C.R}").strip()
        if not ip:
            pause()
            return
        hosts = reverse_lookup(ip)
        if hosts:
            for h in hosts:
                print(f"  {C.GREEN}{h}{C.R}")
        else:
            print(f"{C.RED}[!] no PTR{C.R}")
        pause()
    else:
        return


if __name__ == "__main__":
    run()
