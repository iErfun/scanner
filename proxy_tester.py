import requests
import concurrent.futures
import time
import re
import os
import sys
import threading
import random
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

try:
    import socks

    HAS_SOCKS = True
except ImportError:
    HAS_SOCKS = False


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"


if os.name == "nt":
    os.system("")

PROXY_SOURCES = [
    "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/all/data.txt",
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/checked_proxies/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
    "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/proxy-free/free-proxy-list/main/socks5.txt",
]

TEST_URLS = [
    "https://api.ipify.org?format=json",
    "https://icanhazip.com",
    "https://httpbin.org/ip",
]

OUTPUT_FILE = "alive_proxies.txt"


@dataclass
class ProxyResult:
    proxy: str
    protocol: str
    alive: bool
    response_ms: float
    exit_ip: str
    error: Optional[str] = None


def banner(title, width=62):
    line = "=" * width
    return f"\n{C.BRIGHT_CYAN}{line}{C.RESET}\n{C.BOLD}{C.BRIGHT_WHITE}  {title.center(width - 4)}{C.RESET}\n{C.BRIGHT_CYAN}{line}{C.RESET}"


def divider(width=62):
    return f"{C.DIM}{'-' * width}{C.RESET}"


def print_logo():
    print(f"""{C.RED}
  ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗    ████████╗███████╗███████╗████████╗███████╗██████╗
  ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝   ╚══ ██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
  ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝        ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝
  ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝         ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗
  ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║          ██║   ███████╗███████║   ██║   ███████╗██║  ██║
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝          ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                                                      {C.RESET}""")


def parse_proxy_line(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    line = re.sub(r'^://', '', line)
    line = re.sub(r'^ttp://', 'http://', line)

    if not re.match(r'^(socks4|socks5|socks5h|http|https)://', line):
        line = "http://" + line

    m = re.match(r'^(socks4|socks5|socks5h|http|https)://(.+)$', line)
    if not m:
        return None

    protocol = m.group(1)
    rest = m.group(2)

    host = rest.rsplit("@", 1)[1] if "@" in rest else rest

    hp = host.rsplit(":", 1)
    if len(hp) != 2:
        return None

    ip, port = hp
    if not port.isdigit() or not ip:
        return None

    port_int = int(port)
    if port_int < 1 or port_int > 65535:
        return None

    return f"{protocol}://{rest}"


def split_and_parse(raw_data):
    if isinstance(raw_data, str):
        lines = re.split(r'[\n\r,;]+', raw_data)
    else:
        lines = raw_data

    parsed = []
    for line in lines:
        p = parse_proxy_line(line)
        if p:
            parsed.append(p)

    return list(dict.fromkeys(parsed))


def load_from_file():
    path = input(f"{C.BRIGHT_YELLOW}File path: {C.RESET}").strip().strip('"').strip("'")
    if not os.path.exists(path):
        print(f"{C.BRIGHT_RED}[!] File not found: {path}{C.RESET}")
        return []

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    return split_and_parse(content)


def load_from_paste():
    print(f"{C.BRIGHT_YELLOW}Paste proxies (double Enter to finish):{C.RESET}")

    lines = []
    empty_count = 0
    while True:
        try:
            line = input()
        except EOFError:
            break

        if line.strip() == "":
            empty_count += 1
            if empty_count >= 2:
                break
            continue

        empty_count = 0
        lines.append(line)

    return split_and_parse("\n".join(lines))


def fetch_from_url(url, timeout=15):
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return ""


def load_from_sources():
    print(banner(f"Fetching from {len(PROXY_SOURCES)} sources"))

    all_raw = []
    lock = threading.Lock()
    done = 0
    total = len(PROXY_SOURCES)

    def fetch_one(url):
        nonlocal done
        time.sleep(random.uniform(0.2, 0.8))
        text = fetch_from_url(url, timeout=15)
        with lock:
            done += 1
            domain = urlparse(url).netloc or "?"
            lines_count = len(text.splitlines()) if text else 0
            color = C.BRIGHT_GREEN if lines_count > 0 else C.DIM
            print(f"\r  {color}[{done:2}/{total}]{C.RESET} {domain[:30]:30} -> {lines_count:>6} lines   ",
                  end="", flush=True)
            if text:
                all_raw.append(text)

    max_workers = min(total, 16)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(fetch_one, url) for url in PROXY_SOURCES]
        for f in concurrent.futures.as_completed(futures):
            try:
                f.result(timeout=25)
            except Exception:
                pass

    print("\n")

    combined = "\n".join(all_raw)
    return split_and_parse(combined)


def choose_input():
    print(banner("Load Proxies"))
    print(f"  {C.BRIGHT_CYAN}[1]{C.RESET} From file")
    print(f"  {C.BRIGHT_CYAN}[2]{C.RESET} Paste manually")
    print(f"  {C.BRIGHT_CYAN}[3]{C.RESET} Auto-fetch from {len(PROXY_SOURCES)} sources")
    print(f"  {C.BRIGHT_CYAN}[4]{C.RESET} Custom URL")
    print(f"  {C.BRIGHT_CYAN}[0]{C.RESET} Exit")

    while True:
        choice = input(f"\n{C.BRIGHT_YELLOW}Choice (0-4, default 3): {C.RESET}").strip() or "3"

        if choice == "0":
            return None

        if choice == "1":
            return load_from_file()

        if choice == "2":
            return load_from_paste()

        if choice == "3":
            return load_from_sources()

        if choice == "4":
            url = input(f"{C.BRIGHT_YELLOW}URL: {C.RESET}").strip()
            if not url:
                continue
            text = fetch_from_url(url)
            return split_and_parse(text)

        print(f"{C.BRIGHT_RED}[!] Invalid option{C.RESET}")


class ProxyTester:
    def __init__(self, timeout=10, threads=100):
        self.timeout = timeout
        self.threads = threads
        self._lock = threading.Lock()
        self._done = 0
        self._total = 0

    def test_proxy(self, proxy_url):
        protocol = proxy_url.split("://", 1)[0]
        result = ProxyResult(
            proxy=proxy_url,
            protocol=protocol,
            alive=False,
            response_ms=0,
            exit_ip="?",
        )

        if protocol.startswith("socks") and not HAS_SOCKS:
            result.error = "NO_SOCKS"
            return result

        proxies = {"http": proxy_url, "https": proxy_url}
        start = time.perf_counter()

        for test_url in TEST_URLS:
            try:
                r = requests.get(
                    test_url,
                    proxies=proxies,
                    timeout=(self.timeout, self.timeout),
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                if r.status_code == 200:
                    elapsed = (time.perf_counter() - start) * 1000
                    result.alive = True
                    result.response_ms = round(elapsed, 1)
                    result.error = None

                    if "json" in test_url:
                        try:
                            result.exit_ip = r.json().get("origin", "?")
                        except Exception:
                            result.exit_ip = r.text.strip()[:50]
                    else:
                        result.exit_ip = r.text.strip()[:50]
                    return result

            except requests.exceptions.Timeout:
                result.error = "TIMEOUT"
                continue
            except requests.exceptions.ProxyError:
                result.error = "PROXY_ERROR"
                continue
            except requests.exceptions.ConnectionError:
                result.error = "CONN_ERROR"
                continue
            except requests.exceptions.SSLError:
                result.error = "SSL_ERROR"
                continue
            except Exception as e:
                result.error = type(e).__name__
                continue

        return result

    def test_all(self, proxy_urls):
        if not proxy_urls:
            return []

        self._total = len(proxy_urls)
        self._done = 0
        results = []

        def worker(p):
            r = self.test_proxy(p)
            with self._lock:
                self._done += 1
                self._print_progress()
            return r

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(worker, p) for p in proxy_urls]
            for f in concurrent.futures.as_completed(futures):
                try:
                    results.append(f.result())
                except Exception:
                    pass

        print("\n")
        return results

    def _print_progress(self):
        pct = (self._done / self._total) * 100 if self._total else 0
        bar_len = 30
        filled = int(bar_len * pct / 100)
        bar = "█" * filled + "░" * (bar_len - filled)
        sys.stdout.write(f"\r  {C.BRIGHT_CYAN}[{bar}] {pct:5.1f}% ({self._done}/{self._total}){C.RESET}   ")
        sys.stdout.flush()


def choose_settings():
    print(banner("Test Settings"))
    print(f"  {C.BRIGHT_CYAN}[1]{C.RESET} Fast       (timeout=5,  threads=150)")
    print(f"  {C.BRIGHT_CYAN}[2]{C.RESET} Normal     (timeout=10, threads=100)")
    print(f"  {C.BRIGHT_CYAN}[3]{C.RESET} Slow       (timeout=20, threads=50)")
    print(f"  {C.BRIGHT_CYAN}[4]{C.RESET} Custom")

    choice = input(f"\n{C.BRIGHT_YELLOW}Choice (1-4, default 2): {C.RESET}").strip() or "2"

    presets = {"1": (5, 150), "2": (10, 100), "3": (20, 50)}
    if choice in presets:
        return presets[choice]

    if choice == "4":
        t = input(f"{C.BRIGHT_YELLOW}Timeout (default 10): {C.RESET}").strip() or "10"
        th = input(f"{C.BRIGHT_YELLOW}Threads (default 100): {C.RESET}").strip() or "100"
        try:
            return float(t), int(th)
        except ValueError:
            return 10, 100

    return 10, 100


def save_results(results, path=OUTPUT_FILE):
    alive = [r for r in results if r.alive]
    alive.sort(key=lambda x: x.response_ms)

    with open(path, "w", encoding="utf-8") as f:
        for r in alive:
            f.write(r.proxy + "\n")

    return len(alive), path


def main():
    print_logo()

    if not HAS_SOCKS:
        print(f"{C.BRIGHT_YELLOW}[!] requests[socks] not installed.{C.RESET}")
        print(f"{C.BRIGHT_YELLOW}    Install: pip install requests[socks]{C.RESET}\n")

    proxies = choose_input()
    if proxies is None:
        print(f"{C.BRIGHT_CYAN}Bye!{C.RESET}")
        return

    if not proxies:
        print(f"{C.BRIGHT_RED}[!] No valid proxies loaded.{C.RESET}")
        return

    print(f"\n{C.BRIGHT_GREEN}[+] {len(proxies)} valid proxies loaded{C.RESET}")

    timeout, threads = choose_settings()

    print(banner("Confirm Test"))
    print(f"  Proxies:  {C.BOLD}{len(proxies)}{C.RESET}")
    print(f"  Timeout:  {timeout}s")
    print(f"  Threads:  {threads}")
    print(f"  Output:   {OUTPUT_FILE}")

    confirm = input(f"\n{C.BRIGHT_YELLOW}Start test? (y/n, default y): {C.RESET}").strip().lower() or "y"
    if confirm != "y":
        print(f"{C.YELLOW}[!] Cancelled.{C.RESET}")
        return

    print(banner(f"Testing {len(proxies)} proxies"))
    tester = ProxyTester(timeout=timeout, threads=threads)

    start = time.time()
    results = tester.test_all(proxies)
    duration = time.time() - start

    alive = [r for r in results if r.alive]
    alive.sort(key=lambda x: x.response_ms)

    print(banner("Results"))
    print(f"  {C.BRIGHT_GREEN}Alive:{C.RESET} {len(alive)}  |  "
          f"{C.BRIGHT_RED}Dead:{C.RESET} {len(results) - len(alive)}  |  "
          f"{C.BRIGHT_CYAN}Total:{C.RESET} {len(results)}")
    print(f"  {C.DIM}Time: {duration:.1f}s{C.RESET}\n")

    for r in alive[:30]:
        speed_c = C.BRIGHT_GREEN if r.response_ms < 1500 else (
            C.BRIGHT_YELLOW if r.response_ms < 3000 else C.DIM
        )
        print(f"  {C.BRIGHT_GREEN}[+]{C.RESET} {r.proxy[:50]:50} | "
              f"{speed_c}{r.response_ms:6.0f}ms{C.RESET} | "
              f"{C.DIM}{r.exit_ip}{C.RESET}")

    if len(alive) > 30:
        print(f"  {C.DIM}... and {len(alive) - 30} more{C.RESET}")

    if alive:
        count, path = save_results(results, OUTPUT_FILE)
        print(f"\n{C.BRIGHT_GREEN}[+] Saved {count} alive proxies to {path}{C.RESET}")
    else:
        print(f"\n{C.BRIGHT_RED}[!] No alive proxies found.{C.RESET}")

    input(f"\n{C.DIM}Press Enter to exit...{C.RESET}")


if __name__ == "__main__":
    main()