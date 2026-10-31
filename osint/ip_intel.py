#!/usr/bin/env python3
import os
import sys
import json
import time
import threading
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings()


class C:
    R='\033[0m'; B='\033[1m'; D='\033[2m'
    RED='\033[91m'; GRN='\033[92m'; YEL='\033[93m'
    CYN='\033[96m'; WHT='\033[97m'
    GLD='\033[38;2;255;215;0m'
    PUR='\033[38;2;191;64;255m'
    NEO='\033[38;2;0;255;213m'
    CRM='\033[38;2;220;20;60m'


def clear():
    os.system("clear" if os.name == "posix" else "cls")


def banner():
    clear()
    print(f"""{C.NEO}{C.B}
▐██ ▐██████      ▐██ ▐██████ ▐██████ ▐██████ ▐██   
▐██ ▐██ ▐██      ▐██ ▐██ ▐██   ▐██   ▐██     ▐██   
▐██ ▐██████      ▐██ ▐██ ▐██   ▐██   ▐████   ▐██   
▐██ ▐██          ▐██ ▐██ ▐██   ▐██   ▐██     ▐██   
▐██ ▐██          ▐██ ▐██ ▐██   ▐██   ▐██████ ▐█████
{C.R}""")
    print(f"{C.GLD}{C.B}{'IP INTELLIGENCE GATHERING'.center(60)}{C.R}")
    print(f"{C.D}{'powered by ip-api.com'.center(60)}{C.R}\n")


def lookup_ip(ip):
    """Fetch IP info from ip-api.com."""
    url = f"http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"

    try:
        r = requests.get(url, timeout=10, verify=False)
        return r.json()
    except requests.exceptions.Timeout:
        return {"status": "fail", "message": "Request timed out", "query": ip}
    except requests.exceptions.ConnectionError:
        return {"status": "fail", "message": "Connection error", "query": ip}
    except Exception as e:
        return {"status": "fail", "message": str(e), "query": ip}


def print_result(data):
    """Print result in a nice format."""
    if data.get("status") != "success":
        print(f"\n{C.CRM}[!] {data.get('query', '?')}: {data.get('message', 'unknown error')}{C.R}")
        return

    print(f"\n{C.PUR}{'='*60}{C.R}")
    print(f"{C.B}{C.WHT}  IP: {C.GLD}{data.get('query')}{C.R}")
    print(f"{C.PUR}{'='*60}{C.R}\n")

    rows = [
        ("Continent",   f"{data.get('continent')} ({data.get('continentCode')})"),
        ("Country",     f"{data.get('country')} ({data.get('countryCode')})"),
        ("Region",      f"{data.get('regionName')} ({data.get('region')})"),
        ("City",        data.get("city")),
        ("District",    data.get("district")),
        ("Zip",         data.get("zip")),
        ("Lat/Lon",     f"{data.get('lat')}, {data.get('lon')}"),
        ("Timezone",    f"{data.get('timezone')} (UTC offset: {data.get('offset')})"),
        ("Currency",    data.get("currency")),
        ("ISP",         data.get("isp")),
        ("Organization",data.get("org")),
        ("ASN",         data.get("as")),
        ("AS Name",     data.get("asname")),
        ("Reverse DNS", data.get("reverse")),
        ("Mobile",      "Yes" if data.get("mobile") else "No"),
        ("Proxy/VPN",   "Yes" if data.get("proxy") else "No"),
        ("Hosting",     "Yes" if data.get("hosting") else "No"),
    ]

    for label, value in rows:
        if value:
            print(f"  {C.NEO}{label:<14}{C.R} {C.WHT}{value}{C.R}")

    print(f"\n{C.PUR}{'='*60}{C.R}")


def save_json(data, path=None):
    """Save result as pretty JSON."""
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        ip = data.get("query", "unknown").replace(":", "_").replace(".", "_")
        path = f"ip_intel_{ip}_{ts}.json"

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    print(f"{C.GRN}[+] Saved: {path}{C.R}")
    return path


# ══════════════════════════════════════════════════════════════
# BATCH MODE
# ══════════════════════════════════════════════════════════════
def batch_lookup(ips, threads=5, delay=1.4):
    """Lookup multiple IPs with rate limit (45/min free tier)."""
    results = []
    lock = threading.Lock()
    counter = {"done": 0}
    total = len(ips)

    def worker(ip):
        time.sleep(delay)
        data = lookup_ip(ip)
        with lock:
            counter["done"] += 1
            n = counter["done"]

            ok = data.get("status") == "success"
            color = C.GRN if ok else C.CRM

            cc = data.get("countryCode", "--") if ok else "--"
            city = (data.get("city") or "-")[:18] if ok else "-"
            isp = ((data.get("isp") or "-")[:28]) if ok else (data.get("message", "fail")[:28])

            print(f"  {C.D}[{n:>3}/{total}]{C.R} "
                  f"{color}{ip[:20]:<20}{C.R} "
                  f"{C.GLD}{cc:<4}{C.R} "
                  f"{C.NEO}{city:<18}{C.R} "
                  f"{C.D}{isp}{C.R}")

            if ok:
                results.append(data)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        list(ex.map(worker, ips))

    return results


def load_ips_from_file(path):
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


def load_ips_pasted():
    print(f"\n{C.NEO}Paste IPs (one per line, empty line to finish){C.R}\n")
    out = []
    while True:
        try:
            line = input().strip()
        except EOFError:
            break
        if not line:
            break
        out.append(line)
    return out


# ══════════════════════════════════════════════════════════════
# MENUS
# ══════════════════════════════════════════════════════════════
def single_lookup():
    banner()
    ip = input(f"{C.GLD}Enter IP or domain{C.R} (Enter=exit): ").strip()
    if not ip:
        return

    print(f"\n{C.D}[*] Looking up {ip}...{C.R}")
    data = lookup_ip(ip)
    print_result(data)

    if data.get("status") == "success":
        print(f"\n{C.GLD}Save as JSON?{C.R} {C.D}(y/n){C.R}: ", end="")
        if input().strip().lower() == "y":
            save_json(data)

    input(f"\n{C.D}Enter...{C.R}")


def batch_mode():
    banner()
    print(f"{C.NEO}Batch Mode{C.R}\n")
    print(f"  {C.GLD}[1]{C.R}  Paste IPs")
    print(f"  {C.GLD}[2]{C.R}  Load from file")
    print(f"  {C.GLD}0{C.R}  Back\n")

    c = input(f"{C.GLD}>>{C.R} ").strip()

    if c == "0":
        return

    if c == "1":
        ips = load_ips_pasted()
    elif c == "2":
        p = input(f"{C.GLD}File path{C.R}: ").strip().strip('"').strip("'")
        ips = load_ips_from_file(p)
    else:
        return

    if not ips:
        print(f"{C.CRM}[!] No IPs{C.R}")
        input(f"\n{C.D}Enter...{C.R}")
        return

    print(f"\n{C.GRN}[+] Loaded: {len(ips)} IPs{C.R}")

    print(f"{C.NEO}Threads{C.R} {C.D}(default 5, max 8){C.R}: ", end="")
    t = input().strip()
    threads = int(t) if t.isdigit() else 5
    threads = min(threads, 8)

    print(f"{C.NEO}Delay between requests{C.R} {C.D}(default 1.4s){C.R}: ", end="")
    d = input().strip()
    try:
        delay = float(d) if d else 1.4
    except ValueError:
        delay = 1.4

    est = int(len(ips) * delay / max(threads, 1))
    print(f"\n{C.D}[*] Estimated: ~{est}s{C.R}")

    print(f"\n{C.GLD}Start? (y/n){C.R}: ", end="")
    if input().strip().lower() != "y":
        return

    print(f"\n{C.PUR}{'='*70}{C.R}")
    print(f"{C.B}  Scanning {len(ips)} IPs...{C.R}")
    print(f"{C.PUR}{'='*70}{C.R}\n")

    start = time.time()
    results = batch_lookup(ips, threads=threads, delay=delay)
    elapsed = time.time() - start

    # Summary
    print(f"\n{C.PUR}{'='*70}{C.R}")
    print(f"{C.B}  DONE{C.R}  ({elapsed:.1f}s)")
    print(f"{C.PUR}{'='*70}{C.R}\n")

    print(f"  {C.GRN}Success:  {len(results)}{C.R}")
    print(f"  {C.CRM}Failed:   {len(ips) - len(results)}{C.R}")

    # Country summary
    countries = {}
    for r in results:
        cc = r.get("country", "Unknown")
        countries[cc] = countries.get(cc, 0) + 1

    if countries:
        print(f"\n{C.NEO}By country:{C.R}")
        for country, count in sorted(countries.items(), key=lambda x: -x[1]):
            print(f"  {C.GLD}{country:<25}{C.R} {count}")

    # Proxy/Hosting summary
    proxy_count = sum(1 for r in results if r.get("proxy"))
    host_count = sum(1 for r in results if r.get("hosting"))
    mobile_count = sum(1 for r in results if r.get("mobile"))

    if proxy_count or host_count or mobile_count:
        print(f"\n{C.NEO}Classification:{C.R}")
        if proxy_count:
            print(f"  {C.CRM}Proxy/VPN:  {proxy_count}{C.R}")
        if host_count:
            print(f"  {C.YEL}Hosting:    {host_count}{C.R}")
        if mobile_count:
            print(f"  {C.CYN}Mobile:     {mobile_count}{C.R}")

    # Save
    if results:
        print(f"\n{C.GLD}Save all results as JSON?{C.R} {C.D}(y/n){C.R}: ", end="")
        if input().strip().lower() == "y":
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = f"ip_batch_{ts}.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
            print(f"{C.GRN}[+] Saved: {path}{C.R}")

    input(f"\n{C.D}Enter...{C.R}")


def run():
    while True:
        banner()
        print(f"  {C.GLD}[1]{C.R}  {C.NEO}Single Lookup{C.R}")
        print(f"  {C.GLD}[2]{C.R}  {C.NEO}Batch Lookup{C.R}")
        print(f"  {C.GLD}[0]{C.R}  {C.CRM}Exit{C.R}\n")

        c = input(f"{C.GLD}>>{C.R} ").strip()

        if c == "0":
            return
        elif c == "1":
            single_lookup()
        elif c == "2":
            batch_mode()
        else:
            print(f"{C.CRM}[!] Invalid{C.R}")
            time.sleep(1)


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print(f"\n{C.CRM}Bye{C.R}")