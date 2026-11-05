#!/usr/bin/env python3
"""Fast TCP port scanner with service hints."""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

from core_utils import C, pause, resolve_host, save_json_report, strip_scheme

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
    8888, 9200, 27017, 5000, 8000, 8008, 8081, 8444, 9000, 9443,
]

SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}


def probe(host: str, port: int, timeout: float = 1.2) -> Tuple[int, bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(0.8)
            banner = ""
            try:
                if port in (80, 8080, 8000, 8888):
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
                banner = s.recv(128).decode("latin-1", errors="ignore").strip()
            except Exception:
                pass
            return port, True, banner[:80]
    except Exception:
        return port, False, ""


def scan(host: str, ports: List[int], threads: int = 100, timeout: float = 1.2) -> List[dict]:
    open_ports: List[dict] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(probe, host, p, timeout): p for p in ports}
        for fut in as_completed(futs):
            port, is_open, banner = fut.result()
            if is_open:
                svc = SERVICE_HINTS.get(port, "")
                print(f"  {C.GREEN}[open]{C.R} {port}/tcp  {C.GRAY}{svc} {banner}{C.R}")
                open_ports.append({"port": port, "service": svc, "banner": banner})
    return sorted(open_ports, key=lambda x: x["port"])


def run(target: str = None):
    print(f"\n{C.PURP}{C.B}  TCP Port Scanner{C.R}\n")
    target = strip_scheme(target or input(f"{C.AQUA}[?] Host/IP: {C.R}"))
    if not target:
        pause()
        return
    ips = resolve_host(target)
    print(f"{C.GOLD}[*] {target} → {', '.join(ips) or 'unresolved'}{C.R}")
    mode = input(f"{C.AQUA}[?] Ports: 1=common 2=1-1024 3=custom [1]: {C.R}").strip() or "1"
    if mode == "2":
        ports = list(range(1, 1025))
    elif mode == "3":
        raw = input(f"{C.AQUA}[?] comma/range (80,443,8000-8010): {C.R}").strip()
        ports = []
        for part in raw.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-", 1)
                ports.extend(range(int(a), int(b) + 1))
            elif part.isdigit():
                ports.append(int(part))
        ports = sorted(set(ports))
    else:
        ports = list(COMMON_PORTS)
    threads = 120 if len(ports) > 50 else 60
    print(f"{C.GOLD}[*] scanning {len(ports)} ports ...{C.R}")
    results = scan(target, ports, threads=threads)
    print(f"\n{C.NEON}[+] open: {len(results)}{C.R}")
    path = save_json_report("port_scan", {"target": target, "ips": ips, "open": results})
    print(f"{C.GREEN}[+] Saved: {path}{C.R}")
    pause()


if __name__ == "__main__":
    run()
