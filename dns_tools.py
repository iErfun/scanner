#!/usr/bin/env python3
"""DNS tools — records, AXFR attempt, reverse, zone-ish dump."""
from __future__ import annotations

import os
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


# ── UI helpers ───────────────────────────────────────────────────────────────
def clear():
    os.system("cls" if os.name == "nt" else "clear")

def banner():
    clear()
    print(f"""{C.RED}{C.B}
▓█████▄  ███▄    █   ██████    
▒██▀ ██▌ ██ ▀█   █ ▒██    ▒    
░██   █▌▓██  ▀█ ██▒░ ▓██▄      
░▓█▄   ▌▓██▒  ▐▌██▒  ▒   ██▒   
░▒████▓ ▒██░   ▓██░▒██████▒▒   
 ▒▒▓  ▒ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░   
 ░ ▒  ▒ ░ ░░   ░ ▒░░ ░▒  ░ ░   
 ░ ░  ░    ░   ░ ░ ░  ░  ░     
   ░             ░       ░     
 ░                             
{C.R}{C.GOLD}{C.B}       XOMLEK  /  DNS TOOLS{C.R}
{C.GREEN}    Records  •  AXFR  •  Reverse  •  Zone Dump{C.R}
""")

def box(title: str, rows: List[tuple], width: int = 62) -> None:
    inner = width - 2
    edge = getattr(C, "FRAME", C.GOLD)
    print(f"{edge}╭{'─' * inner}╮{C.R}")
    if title:
        label = f"  {C.B}{title}{C.R}"
        pad = inner - len(title) - 2
        print(f"{edge}│{C.R}{label}{' ' * max(pad, 0)}{edge}│{C.R}")
        print(f"{edge}├{'─' * inner}┤{C.R}")
    for key, value in rows:
        plain = f"  {key}  {value}"
        pad = inner - len(plain)
        print(f"{edge}│{C.R}  {C.LIME}{key}{C.R}  {value}{' ' * max(pad, 0)}{edge}│{C.R}")
    print(f"{edge}╰{'─' * inner}╯{C.R}")


def prompt(label: str, default: str = "") -> str:
    suf = f" {C.GRAY}[{default}]{C.R}" if default else ""
    try:
        return input(f"{C.AQUA}{label}{C.R}{suf}: ").strip() or default
    except EOFError:
        return default


def status(msg: str, kind: str = "info") -> None:
    m = {
        "ok":   (C.GREEN, "[+]"),
        "err":  (C.CRIM,  "[!]"),
        "warn": (C.YEL,   "[~]"),
        "info": (C.CYN,   "[*]"),
        "hit":  (C.LIME,  "[!]"),
    }
    c, t = m.get(kind, (C.CYN, "[*]"))
    print(f"  {c}{t} {msg}{C.R}")


# ── core logic ───────────────────────────────────────────────────────────────
def query_records(domain: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    if not HAS_DNSPYTHON:
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


# ── actions ──────────────────────────────────────────────────────────────────
def action_query(domain: str = "") -> None:
    banner()
    box("DNS RECORDS", [("mode", "A · AAAA · MX · NS · TXT · CNAME · SOA · CAA · SRV")])
    print()
    domain = strip_scheme(domain or prompt("  Domain"))
    if not domain:
        return
    status(f"querying {domain} ...", "info")
    recs = query_records(domain)
    if not recs:
        status("no records found", "err")
    for k, vals in recs.items():
        print(f"  {C.GREEN}{k}{C.R}")
        for v in vals:
            print(f"    {C.DIM}{v}{C.R}")
    path = save_json_report("dns_records", {"domain": domain, "records": recs})
    status(f"saved → {path}", "ok")
    pause()


def action_axfr(domain: str = "") -> None:
    banner()
    box("AXFR ATTEMPT", [("target", "zone transfer against authoritative NS")])
    print()
    if not HAS_DNSPYTHON:
        status("dnspython required for AXFR", "err")
        pause()
        return
    domain = strip_scheme(domain or prompt("  Domain"))
    if not domain:
        return
    status(f"AXFR against NS of {domain} ...", "info")
    ax = try_axfr(domain)
    if not ax:
        status("no NS records or AXFR unavailable", "err")
    for ns, names in ax.items():
        print(f"  {C.CYN}NS {ns}{C.R}")
        for n in names[:200]:
            print(f"    {C.DIM}{n}{C.R}")
        if len(names) > 200:
            print(f"    {C.GRAY}... +{len(names) - 200} more{C.R}")
    path = save_json_report("dns_axfr", {"domain": domain, "axfr": ax})
    status(f"saved → {path}", "ok")
    pause()


def action_reverse() -> None:
    banner()
    box("REVERSE LOOKUP", [("mode", "PTR / gethostbyaddr")])
    print()
    ip = prompt("  IP")
    if not ip:
        return
    hosts = reverse_lookup(ip)
    if hosts:
        for h in hosts:
            status(h, "ok")
    else:
        status("no PTR record", "err")
    pause()


# ── menu ─────────────────────────────────────────────────────────────────────
def run(domain: str = None) -> None:
    while True:
        banner()
        box("DNS TOOLS", [
            ("1", "Query records        A · AAAA · MX · NS · TXT · ..."),
            ("2", "AXFR attempt         zone transfer test"),
            ("3", "Reverse lookup       IP → PTR"),
            ("0", "Back"),
        ])
        if not HAS_DNSPYTHON:
            print()
            status("dnspython not installed — limited mode (A/reverse only)", "warn")
            print(f"  {C.GRAY}    pip install dnspython{C.R}")
        print()
        c = prompt("  >>", "0")

        if c == "0":
            return
        elif c == "1":
            action_query(domain)
        elif c == "2":
            action_axfr(domain)
        elif c == "3":
            action_reverse()
        else:
            status("invalid choice", "err")


if __name__ == "__main__":
    run()
