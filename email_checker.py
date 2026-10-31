import requests
import time
import json
import os
import random
import threading
import concurrent.futures
from dataclasses import dataclass, asdict
from typing import Optional


class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    CYAN    = "\033[36m"
    BRIGHT_RED     = "\033[91m"
    BRIGHT_GREEN   = "\033[92m"
    BRIGHT_YELLOW  = "\033[93m"
    BRIGHT_CYAN    = "\033[96m"
    BRIGHT_WHITE   = "\033[97m"


def enable_colors_windows():
    if os.name == "nt":
        try:
            os.system("")
        except Exception:
            pass


def banner(title, width=55):
    line = "=" * width
    return f"\n{C.BRIGHT_CYAN}{line}{C.RESET}\n{C.BOLD}{C.BRIGHT_WHITE}  {title.center(width - 4)}{C.RESET}\n{C.BRIGHT_CYAN}{line}{C.RESET}"


def divider(width=55, char="-"):
    return f"{C.DIM}{char * width}{C.RESET}"


def print_logo():
    print(f"{C.DIM}{'-' * 130}{C.RESET}")
    logo = r"""
▀██▀▀▀▀███ ▀███      ███▀       ███       ▀██▀ ▀██▀              ▄██▀██▄█       ▄▄█████▄█       ███       ▀██   ▀██▀
 ██     ██  ███▌    ▐███       ▐███▌       ██   ██              ██▀   ███    ▄██▀▀   ▀███      ▐███▌       ██▌   ██
 ██      █  ████    ████       █▌███       ██   ██             ▐█▌     ██   ██▀        ▀█      █▌███       ███   ██
 ██         ████▌  ▐█ ██      ▐█▌▐██▌      ██   ██             ██▌      █  ▐█▌                ▐█▌▐██▌      ███▌  ██
 ██   ▄█    ██▐██  █▌ ██      ██  ███      ██   ██              ▀█▄▄       ██                 ██  ███      ████  ██
 ███████    ██ ██▌▐█  ██     ▐█▌  ▐██▌     ██   ██                ▀▀▀▀██▄  ██                ▐█▌  ▐██▌     ██▐█▌ ██
 ██   ▀█    ██ ▐███▌  ██     ██    ███     ██   ██                     ▀█▌ ██                ██    ███     ██ ██ ██
 ██         ██  ███   ██    ▐█▌    ▐██▌    ██   ██             ▄        ██ ▐█▌              ▐█▌    ▐██▌    ██ ▐█▌██
 ██     ▄█  ██  ▐█▌   ██    ██▄▄▄▄▄▄███    ██   ██     ▄█      █▄      ▐█▌  ██▄         ▄   ██▄▄▄▄▄▄███    ██  ████
 ██    ▄██  ██   █    ██   ▐█▌      ▐██▌   ██   ██    ▄██      ███    ▄██    ▀██▄▄    ▄██  ▐█▌      ▐██▌   ██  ▐███
▄██▄▄▄████ ▄██▄      ▄██▄ ▄██▄      ▄███▄ ▄██▄ ▄██▄▄▄████      ████▄▄██▀       ▀▀██████▀  ▄██▄      ▄███▄ ▄██▄  ███

"""
    print(f"{C.BRIGHT_CYAN}{logo}{C.RESET}")
    print(f"{C.DIM}{'-' * 1}{C.RESET}")


@dataclass
class SiteTarget:
    name: str
    url: str
    method: str = "POST"
    email_field: str = "email"
    extra_data: Optional[dict] = None
    headers: Optional[dict] = None


@dataclass
class SiteVerdict:
    site: str
    email: str
    verdict: str
    evidence: str
    proxy_used: str = "?"
    error: Optional[str] = None


DEFAULT_SITES = [
    SiteTarget(name="GitHub",     url="https://github.com/signup_check/email",                        email_field="value"),
    SiteTarget(name="Twitter",    url="https://api.twitter.com/i/users/email_available.json",         email_field="email"),
    SiteTarget(name="Instagram",  url="https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/", email_field="email"),
    SiteTarget(name="Pinterest",  url="https://www.pinterest.com/resource/EmailExistsResource/get/",  email_field="email"),
    SiteTarget(name="Spotify",    url="https://www.spotify.com/api/signup/validate",                  email_field="email"),
    SiteTarget(name="Adobe",      url="https://auth.services.adobe.com/signup/v2/users",              email_field="email"),
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
]

ACCEPT_LANGS = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,fa;q=0.8",
]

FAKE_DOMAINS = [
    "thisdomaindoesnotexist-abc123.com",
    "not-a-real-domain-xyz789.net",
    "fake-domain-test-0000.org",
    "invalid-domain-checker-777.io",
    "definitely-not-registered-999.com",
    "no-such-domain-here-123.net",
    "totally-fake-domain-456.org",
    "random-unregistered-abc.xyz",
    "null-domain-test-111.io",
    "void-domain-xyz-222.net",
]

ADJECTIVES = ["silent", "rapid", "cosmic", "frozen", "hidden", "golden", "crimson", "lunar", "shadow", "iron", "velvet", "arctic"]

NOUNS = ["falcon", "tiger", "storm", "river", "mountain", "wolf", "phoenix", "dragon", "hawk", "comet", "forest", "ocean"]

CUSTOM_SITES_FILE = "custom_sites.json"

PING_URLS = [
    "https://api.ipify.org?format=json",
    "https://icanhazip.com",
    "https://httpbin.org/ip",
]


def random_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(ACCEPT_LANGS),
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }


def generate_fake_email():
    local = f"{random.choice(ADJECTIVES)}.{random.choice(NOUNS)}{random.randint(10, 9999)}"
    domain = random.choice(FAKE_DOMAINS)
    return f"{local}@{domain}"


def choose_fake_email():
    print(banner("Baseline Email (Fake)"))
    print(f"  {C.BRIGHT_CYAN}[1]{C.RESET} Auto generate")
    print(f"  {C.BRIGHT_CYAN}[2]{C.RESET} Manual")
    print(f"  {C.BRIGHT_CYAN}[3]{C.RESET} No baseline")

    while True:
        choice = input(f"\n{C.BRIGHT_YELLOW}Choice (1-3, default 1): {C.RESET}").strip() or "1"

        if choice == "1":
            fake = generate_fake_email()
            print(f"{C.DIM}Generated: {fake}{C.RESET}")
            return fake

        if choice == "2":
            manual = input(f"{C.BRIGHT_YELLOW}Enter fake email: {C.RESET}").strip()
            if manual and "@" in manual:
                return manual
            print(f"{C.BRIGHT_RED}[!] Invalid email.{C.RESET}")
            continue

        if choice == "3":
            print(f"{C.BRIGHT_GREEN}[+] Baseline disabled.{C.RESET}")
            return None

        print(f"{C.BRIGHT_RED}[!] Invalid option{C.RESET}")


def choose_delay():
    print(banner("Request Delay (Anti-Block)"))
    print(f"  {C.BRIGHT_CYAN}[1]{C.RESET} Fast       (0.2s)")
    print(f"  {C.BRIGHT_CYAN}[2]{C.RESET} Normal     (0.5s)")
    print(f"  {C.BRIGHT_CYAN}[3]{C.RESET} Slow       (1.0s)  {C.DIM}(recommended){C.RESET}")
    print(f"  {C.BRIGHT_CYAN}[4]{C.RESET} Very Slow  (2.0s)")
    print(f"  {C.BRIGHT_CYAN}[5]{C.RESET} None       (0s)")

    choice = input(f"\n{C.BRIGHT_YELLOW}Choice (1-5, default 3): {C.RESET}").strip() or "3"
    delay_map = {"1": 0.2, "2": 0.5, "3": 1.0, "4": 2.0, "5": 0.0}
    delay = delay_map.get(choice, 1.0)
    print(f"{C.DIM}Delay: {delay}s between requests{C.RESET}")
    return delay


def choose_max_attempts():
    print(banner("Max Proxy Attempts Per Site"))
    print(f"  {C.BRIGHT_CYAN}[1]{C.RESET} 5  (fast)")
    print(f"  {C.BRIGHT_CYAN}[2]{C.RESET} 10 (balanced)  {C.DIM}(recommended){C.RESET}")
    print(f"  {C.BRIGHT_CYAN}[3]{C.RESET} 20 (thorough)")
    print(f"  {C.BRIGHT_CYAN}[4]{C.RESET} Custom")

    choice = input(f"\n{C.BRIGHT_YELLOW}Choice (1-4, default 2): {C.RESET}").strip() or "2"
    preset = {"1": 5, "2": 10, "3": 20}

    if choice in preset:
        n = preset[choice]
    elif choice == "4":
        raw = input(f"{C.BRIGHT_YELLOW}Number (1-50): {C.RESET}").strip()
        try:
            n = max(1, min(50, int(raw)))
        except ValueError:
            n = 10
    else:
        n = 10

    print(f"{C.DIM}Max attempts: {n}{C.RESET}")
    return n


def choose_workers():
    print(banner("Concurrent Workers"))
    print(f"  {C.BRIGHT_CYAN}[1]{C.RESET} 1  (sequential, safest)")
    print(f"  {C.BRIGHT_CYAN}[2]{C.RESET} 3  (balanced)")
    print(f"  {C.BRIGHT_CYAN}[3]{C.RESET} 5  (fast)")

    choice = input(f"\n{C.BRIGHT_YELLOW}Choice (1-3, default 2): {C.RESET}").strip() or "2"
    workers_map = {"1": 1, "2": 3, "3": 5}
    return workers_map.get(choice, 3)


def load_custom_sites():
    if not os.path.exists(CUSTOM_SITES_FILE):
        return []
    try:
        with open(CUSTOM_SITES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return [SiteTarget(
            name=s["name"], url=s["url"],
            method=s.get("method", "POST"),
            email_field=s.get("email_field", "email"),
            extra_data=s.get("extra_data"),
            headers=s.get("headers"),
        ) for s in data.get("sites", [])]
    except Exception as e:
        print(f"{C.BRIGHT_RED}[!] Load error: {e}{C.RESET}")
        return []


def save_custom_sites(sites):
    try:
        data = {"sites": [
            {"name": s.name, "url": s.url, "method": s.method,
             "email_field": s.email_field, "extra_data": s.extra_data,
             "headers": s.headers}
            for s in sites
        ]}
        with open(CUSTOM_SITES_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"{C.BRIGHT_RED}[!] Save error: {e}{C.RESET}")
        return False


def add_custom_site():
    print(banner("Add Custom Site"))
    name = input(f"\n{C.BRIGHT_YELLOW}Site name: {C.RESET}").strip()
    if not name:
        return

    existing = load_custom_sites()
    for s in existing:
        if s.name.lower() == name.lower():
            print(f"{C.BRIGHT_RED}[!] Already exists.{C.RESET}")
            return

    url = input(f"{C.BRIGHT_YELLOW}URL: {C.RESET}").strip()
    if not url or not url.startswith(("http://", "https://")):
        print(f"{C.BRIGHT_RED}[!] Invalid URL.{C.RESET}")
        return

    method = input(f"{C.BRIGHT_YELLOW}Method (POST/GET, default POST): {C.RESET}").strip().upper() or "POST"
    email_field = input(f"{C.BRIGHT_YELLOW}Email field (default 'email'): {C.RESET}").strip() or "email"

    site = SiteTarget(name=name, url=url, method=method, email_field=email_field)
    existing.append(site)
    if save_custom_sites(existing):
        print(f"\n{C.BRIGHT_GREEN}[+] Added.{C.RESET}")


def list_custom_sites():
    sites = load_custom_sites()
    if not sites:
        print(f"\n{C.BRIGHT_YELLOW}[!] No custom sites.{C.RESET}")
        return
    print(f"\n{C.BRIGHT_CYAN}Custom sites ({len(sites)}):{C.RESET}")
    for i, s in enumerate(sites, 1):
        print(f"  {C.BRIGHT_CYAN}[{i}]{C.RESET} {C.BOLD}{s.name}{C.RESET}  ->  {C.DIM}{s.url}{C.RESET}")


def delete_custom_site():
    sites = load_custom_sites()
    if not sites:
        print(f"\n{C.BRIGHT_YELLOW}[!] No custom sites.{C.RESET}")
        return
    for i, s in enumerate(sites, 1):
        print(f"  {C.BRIGHT_CYAN}[{i}]{C.RESET} {s.name}")
    raw = input(f"\n{C.BRIGHT_YELLOW}Which to delete? {C.RESET}").strip()
    if raw.isdigit() and 1 <= int(raw) <= len(sites):
        target = sites[int(raw) - 1]
        confirm = input(f"{C.BRIGHT_YELLOW}Delete '{target.name}'? (y/n): {C.RESET}").strip().lower()
        if confirm == "y":
            sites.pop(int(raw) - 1)
            if save_custom_sites(sites):
                print(f"{C.BRIGHT_GREEN}[+] Deleted.{C.RESET}")


def custom_sites_menu():
    while True:
        print(banner("Custom Sites"))
        print(f"  {C.BRIGHT_CYAN}[1]{C.RESET} Add new site")
        print(f"  {C.BRIGHT_CYAN}[2]{C.RESET} List custom sites")
        print(f"  {C.BRIGHT_CYAN}[3]{C.RESET} Delete a site")
        print(f"  {C.BRIGHT_CYAN}[0]{C.RESET} Back")
        choice = input(f"\n{C.BRIGHT_YELLOW}Choice: {C.RESET}").strip()
        if choice == "0":
            return
        if choice == "1":
            add_custom_site()
            input(f"\n{C.DIM}Press Enter...{C.RESET}")
        elif choice == "2":
            list_custom_sites()
            input(f"\n{C.DIM}Press Enter...{C.RESET}")
        elif choice == "3":
            delete_custom_site()
            input(f"\n{C.DIM}Press Enter...{C.RESET}")


def startup_menu():
    while True:
        custom = load_custom_sites()
        print(f"  {C.BRIGHT_CYAN}[1]{C.RESET} Use default sites only")
        print(f"  {C.BRIGHT_CYAN}[2]{C.RESET} Use default + custom sites")
        print(f"  {C.BRIGHT_CYAN}[3]{C.RESET} Use custom sites only")
        print(f"  {C.BRIGHT_CYAN}[4]{C.RESET} Manage custom sites")
        print(f"  {C.BRIGHT_CYAN}[0]{C.RESET} Exit")
        choice = input(f"\n{C.BRIGHT_YELLOW}Choice (1-4, default 2): {C.RESET}").strip() or "2"

        if choice == "0":
            print(f"\n{C.BRIGHT_CYAN}Goodbye.{C.RESET}")
            return None
        if choice == "1":
            return list(DEFAULT_SITES)
        if choice == "2":
            if not custom:
                print(f"\n{C.BRIGHT_YELLOW}[!] No custom sites yet.{C.RESET}")
                continue
            return list(DEFAULT_SITES) + custom
        if choice == "3":
            if not custom:
                print(f"\n{C.BRIGHT_YELLOW}[!] No custom sites yet.{C.RESET}")
                continue
            return list(custom)
        if choice == "4":
            custom_sites_menu()
            continue


class ProxyRotator:
    def __init__(self, proxy_urls, mode="round_robin"):
        self.proxy_urls = [p.strip() for p in proxy_urls if p and p.strip()]
        self.mode = mode
        self.index = 0
        self.lock = threading.Lock()
        self.failed = set()

    def get(self):
        with self.lock:
            if not self.proxy_urls:
                return None
            healthy = [p for p in self.proxy_urls if p not in self.failed]
            if not healthy:
                return None
            if self.mode == "random":
                url = random.choice(healthy)
            else:
                url = healthy[self.index % len(healthy)]
                self.index += 1
        return {"http": url, "https": url}

    def mark_failed(self, proxy_url):
        with self.lock:
            self.failed.add(proxy_url)

    def healthy_count(self):
        with self.lock:
            return len([p for p in self.proxy_urls if p not in self.failed])

    def __len__(self):
        return len(self.proxy_urls)


def load_proxies_from_file(path):
    if not os.path.exists(path):
        return []
    proxies = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            line = line.replace("ttp://", "http://")
            if not line.startswith(("http://", "https://", "socks4://", "socks5://", "socks5h://")):
                line = "http://" + line
            proxies.append(line)
    return proxies


def choose_proxy():
    print(banner("Connection Mode"))
    print(f"  {C.BRIGHT_CYAN}[1]{C.RESET} Direct (your own IP)")
    print(f"  {C.BRIGHT_CYAN}[2]{C.RESET} Rotate from file")

    choice = input(f"\n{C.BRIGHT_YELLOW}Choice (1-2, default 1): {C.RESET}").strip() or "1"

    if choice == "1":
        print(f"{C.DIM}Direct connection{C.RESET}")
        return None

    path = input(f"{C.BRIGHT_YELLOW}Proxy file path: {C.RESET}").strip().strip('"').strip("'")
    if not path or not os.path.exists(path):
        print(f"{C.BRIGHT_RED}[!] File not found: {path}{C.RESET}")
        return None

    proxies = load_proxies_from_file(path)
    if not proxies:
        print(f"{C.BRIGHT_RED}[!] File is empty: {path}{C.RESET}")
        return None

    rotator = ProxyRotator(proxies)
    print(f"{C.BRIGHT_GREEN}[+] {len(rotator)} proxies loaded from {path}{C.RESET}")
    return rotator


class EmailScanner:
    def __init__(self, timeout=15, proxies=None, delay=1.0, jitter=0.3, ping_timeout=5):
        self.timeout = timeout
        self.proxies = proxies
        self.delay = delay
        self.jitter = jitter
        self.ping_timeout = ping_timeout

    def _sleep(self):
        if self.delay > 0:
            wait = self.delay + random.uniform(0, self.jitter)
            time.sleep(wait)

    def _test_proxy_alive(self, proxy):
        if not proxy:
            return True
        proxy_url = proxy.get("https") or proxy.get("http") or "?"
        for url in PING_URLS:
            try:
                r = requests.get(
                    url,
                    proxies=proxy,
                    timeout=(self.ping_timeout, self.ping_timeout),
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                if r.status_code == 200:
                    return True
            except Exception:
                continue
        if isinstance(self.proxies, ProxyRotator):
            self.proxies.mark_failed(proxy_url)
        return False

    def _one_request(self, session, target, email, proxy):
        data = {target.email_field: email}
        if target.extra_data:
            data.update(target.extra_data)

        headers = random_headers()
        if target.headers:
            headers.update(target.headers)

        proxy_url = "direct"
        if proxy:
            proxy_url = proxy.get("https") or proxy.get("http") or "?"

        result = {
            "status": None, "text": "", "location": "",
            "content_type": "", "error": None, "proxy": proxy_url,
        }

        try:
            if target.method.upper() == "POST":
                resp = session.post(target.url, data=data, headers=headers,
                                    timeout=self.timeout, allow_redirects=False, proxies=proxy)
            else:
                resp = session.get(target.url, params=data, headers=headers,
                                   timeout=self.timeout, allow_redirects=False, proxies=proxy)

            result["status"] = resp.status_code
            result["text"] = resp.text[:3000].lower()
            result["location"] = resp.headers.get("Location", "")
            result["content_type"] = resp.headers.get("Content-Type", "")

        except requests.exceptions.Timeout:
            result["error"] = "TIMEOUT"
        except requests.exceptions.ProxyError:
            result["error"] = "PROXY_ERROR"
        except requests.exceptions.ConnectionError:
            result["error"] = "CONN_ERROR"
        except requests.exceptions.SSLError:
            result["error"] = "SSL_ERROR"
        except Exception as e:
            result["error"] = f"{type(e).__name__}"

        return result

    def analyze_response(self, response):
        if response.get("error"):
            return "ERROR", response["error"]

        status = response["status"]
        text = response["text"]
        location = response["location"].lower()
        content_type = response.get("content_type", "").lower()

        EXISTS_KEYWORDS = ["already", "exists", "taken", "registered", "in use", "not available", "duplicate"]
        NOT_EXISTS_KEYWORDS = ["available", "not found", "doesn't exist", "not registered", "no account", "sign up", "create account", "register now", "new user"]

        for kw in EXISTS_KEYWORDS:
            if kw in text:
                return "EXISTS", f"keyword: '{kw}'"

        for kw in NOT_EXISTS_KEYWORDS:
            if kw in text:
                return "NOT_EXISTS", f"keyword: '{kw}'"

        if status in (409, 422, 400):
            return "EXISTS", f"status: {status}"

        if status in (301, 302, 303, 307, 308):
            if "login" in location or "signin" in location:
                return "EXISTS", "redirect -> login"
            if "signup" in location or "register" in location:
                return "NOT_EXISTS", "redirect -> signup"

        if "application/json" in content_type:
            try:
                data = json.loads(text)
                for key in ("exists", "taken", "registered"):
                    if key in data and data[key] is True:
                        return "EXISTS", f"json: {key}=true"
                    if key in data and data[key] is False:
                        return "NOT_EXISTS", f"json: {key}=false"
                if "available" in data:
                    if data["available"] is True:
                        return "NOT_EXISTS", "json: available=true"
                    if data["available"] is False:
                        return "EXISTS", "json: available=false"
            except Exception:
                pass

        if status == 429:
            return "RATE_LIMIT", "status: 429"
        if status == 403:
            return "BLOCKED", "status: 403"

        return "UNKNOWN", f"status: {status}"

    def scan_site(self, target, email, fake_email, max_attempts):
        attempts = 0
        last_proxy = "?"

        while attempts < max_attempts:
            attempts += 1

            proxy = None
            if isinstance(self.proxies, ProxyRotator):
                proxy = self.proxies.get()
            elif self.proxies:
                proxy = self.proxies

            if proxy:
                last_proxy = proxy.get("https") or proxy.get("http") or "?"
            else:
                last_proxy = "direct"

            #if proxy and not self._test_proxy_alive(proxy):
                #print(f"  {C.DIM}[x] {target.name}: dead proxy, retrying ({attempts}/{max_attempts}){C.RESET}")
                #continue

            with requests.Session() as session:
                real_resp = self._one_request(session, target, email, proxy)

                if real_resp.get("error") in ("PROXY_ERROR", "CONN_ERROR", "TIMEOUT", "SSL_ERROR"):
                    if isinstance(self.proxies, ProxyRotator) and proxy:
                        self.proxies.mark_failed(last_proxy)
                    continue

                if real_resp.get("error"):
                    return SiteVerdict(
                        site=target.name, email=email,
                        verdict="ERROR", evidence=real_resp["error"],
                        proxy_used=last_proxy, error=real_resp["error"]
                    )

                verdict, evidence = self.analyze_response(real_resp)

                if fake_email:
                    self._sleep()
                    fake_resp = self._one_request(session, target, fake_email, proxy)
                    fake_verdict, _ = self.analyze_response(fake_resp)

                    if fake_verdict in ("RATE_LIMIT", "BLOCKED"):
                        if isinstance(self.proxies, ProxyRotator) and proxy:
                            self.proxies.mark_failed(last_proxy)
                        continue

                    if verdict in ("RATE_LIMIT", "BLOCKED") and fake_verdict not in ("RATE_LIMIT", "BLOCKED"):
                        return SiteVerdict(
                            site=target.name, email=email,
                            verdict="EXISTS",
                            evidence="target blocked, baseline ok",
                            proxy_used=last_proxy,
                        )

                error = None
                if verdict in ("UNKNOWN", "RATE_LIMIT", "BLOCKED", "ERROR"):
                    error = f"{verdict}: {evidence}"

                return SiteVerdict(
                    site=target.name, email=email,
                    verdict=verdict, evidence=evidence,
                    proxy_used=last_proxy, error=error,
                )

        return SiteVerdict(
            site=target.name, email=email,
            verdict="ERROR",
            evidence=f"all {max_attempts} proxies failed",
            proxy_used=last_proxy,
            error="no_alive_proxies",
        )

    def scan_all(self, targets, email, fake_email, max_attempts=10, max_workers=3):
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.scan_site, t, email, fake_email, max_attempts): t
                for t in targets
            }
            for future in concurrent.futures.as_completed(futures):
                r = future.result()
                results.append(r)
                print_verdict_line(r)
        return results


def print_verdict_line(r):
    if r.verdict == "EXISTS":
        icon = f"{C.BRIGHT_GREEN}[+]{C.RESET}"
        label = f"{C.BRIGHT_GREEN}EXISTS{C.RESET}"
    elif r.verdict == "NOT_EXISTS":
        icon = f"{C.BRIGHT_RED}[-]{C.RESET}"
        label = f"{C.BRIGHT_RED}NOT FOUND{C.RESET}"
    elif r.verdict == "ERROR":
        icon = f"{C.BRIGHT_YELLOW}[!]{C.RESET}"
        label = f"{C.BRIGHT_YELLOW}ERROR{C.RESET}"
    else:
        icon = f"{C.BRIGHT_YELLOW}[?]{C.RESET}"
        label = f"{C.BRIGHT_YELLOW}UNKNOWN{C.RESET}"

    proxy_short = r.proxy_used
    if "://" in proxy_short:
        proxy_short = proxy_short.split("://")[-1]
    proxy_short = proxy_short[:25]

    print(f"  {icon} {C.BOLD}{r.site:15}{C.RESET} | {label:22} | {C.DIM}{proxy_short}{C.RESET}")


def ask_save_results(results):
    while True:
        answer = input(f"\n{C.BRIGHT_YELLOW}Save results? (y/n): {C.RESET}").strip().lower()
        if answer == "y":
            path = input(f"{C.BRIGHT_YELLOW}File (default: scan_result.json): {C.RESET}").strip() or "scan_result.json"
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump([asdict(r) for r in results], f, ensure_ascii=False, indent=2)
                print(f"{C.BRIGHT_GREEN}Saved to {path}{C.RESET}")
            except Exception as e:
                print(f"{C.BRIGHT_RED}Save error: {e}{C.RESET}")
            return
        if answer == "n":
            return


def main_menu():
    print(banner("Email Scanner - Main Menu"))
    print(f"  {C.BRIGHT_CYAN}[1]{C.RESET} {C.BOLD}Start scan{C.RESET}")
    print(f"  {C.BRIGHT_CYAN}[2]{C.RESET} Custom sites")
    print(f"  {C.BRIGHT_CYAN}[0]{C.RESET} Exit")
    while True:
        choice = input(f"\n{C.BRIGHT_YELLOW}Choice: {C.RESET}").strip()
        if choice in ("0", "1", "2"):
            return choice
        print(f"{C.BRIGHT_RED}[!] Invalid option{C.RESET}")


def main():
    enable_colors_windows()
    print_logo()
    targets = startup_menu()
    if targets is None:
        return

    print(f"\n{C.BRIGHT_GREEN}[+] Ready with {C.BOLD}{len(targets)}{C.RESET}{C.BRIGHT_GREEN} sites.{C.RESET}")

    while True:
        choice = main_menu()

        if choice == "0":
            print(f"\n{C.BRIGHT_CYAN}Goodbye.{C.RESET}")
            return

        if choice == "2":
            custom_sites_menu()
            continue

        if choice == "1":
            print(divider())
            email = input(f"{C.BRIGHT_YELLOW}Email to scan: {C.RESET}").strip()
            if not email or "@" not in email:
                print(f"{C.BRIGHT_RED}[!] Invalid email.{C.RESET}")
                continue

            fake_email = choose_fake_email()
            proxies = choose_proxy()
            delay = choose_delay()
            max_attempts = choose_max_attempts()
            workers = choose_workers()

            print(f"\n{C.BRIGHT_CYAN}{'=' * 55}{C.RESET}")
            print(f"  {C.BOLD}FINAL CONFIRMATION{C.RESET}")
            print(f"{C.BRIGHT_CYAN}{'=' * 55}{C.RESET}")
            print(f"  Email:        {email}")
            print(f"  Sites:        {len(targets)}")
            if fake_email:
                print(f"  Baseline:     {fake_email}")
            else:
                print(f"  Baseline:     none")
            if isinstance(proxies, ProxyRotator):
                print(f"  Mode:         rotating proxy ({len(proxies)} total)")
            else:
                print(f"  Mode:         direct (your IP)")
            print(f"  Max attempts: {max_attempts} per site")
            print(f"  Delay:        {delay}s")
            print(f"  Workers:      {workers}")
            print(f"{C.BRIGHT_CYAN}{'=' * 55}{C.RESET}")

            confirm = input(f"\n{C.BRIGHT_YELLOW}Start scan? (y/n, default y): {C.RESET}").strip().lower() or "y"
            if confirm != "y":
                print(f"{C.YELLOW}[!] Cancelled.{C.RESET}")
                continue

            print(f"\n{C.BRIGHT_CYAN}Scanning {C.BOLD}{len(targets)}{C.RESET}{C.BRIGHT_CYAN} sites (max {max_attempts} attempts each)...{C.RESET}\n")

            scanner = EmailScanner(
                timeout=15,
                proxies=proxies,
                delay=delay,
                jitter=0.3,
                ping_timeout=5,
            )

            start = time.time()
            results = scanner.scan_all(targets, email, fake_email, max_attempts, max_workers=workers)
            duration = time.time() - start

            print("\n" + f"{C.BRIGHT_CYAN}{'=' * 55}{C.RESET}")
            print(f"  {C.BOLD}{C.BRIGHT_WHITE}Results{C.RESET} {C.DIM}(total: {duration:.1f}s){C.RESET}")
            print(f"{C.BRIGHT_CYAN}{'=' * 55}{C.RESET}")

            order = {"EXISTS": 0, "UNKNOWN": 1, "ERROR": 2, "NOT_EXISTS": 3}

            for r in sorted(results, key=lambda x: order.get(x.verdict, 9)):
                if r.verdict == "EXISTS":
                    print(f"  {C.BRIGHT_GREEN}[+]{C.RESET} {C.BOLD}{r.site:15}{C.RESET} -> "
                          f"{C.BRIGHT_GREEN}EXISTS{C.RESET}      {C.DIM}({r.evidence}){C.RESET}")
                elif r.verdict == "NOT_EXISTS":
                    print(f"  {C.BRIGHT_RED}[-]{C.RESET} {C.BOLD}{r.site:15}{C.RESET} -> "
                          f"{C.BRIGHT_RED}NOT FOUND{C.RESET}   {C.DIM}({r.evidence}){C.RESET}")
                elif r.verdict == "ERROR":
                    print(f"  {C.BRIGHT_YELLOW}[!]{C.RESET} {C.BOLD}{r.site:15}{C.RESET} -> "
                          f"{C.BRIGHT_YELLOW}ERROR{C.RESET}       {C.DIM}({r.evidence}){C.RESET}")
                else:
                    print(f"  {C.BRIGHT_YELLOW}[?]{C.RESET} {C.BOLD}{r.site:15}{C.RESET} -> "
                          f"{C.BRIGHT_YELLOW}UNKNOWN{C.RESET}     {C.DIM}({r.evidence}){C.RESET}")

            found = sum(1 for r in results if r.verdict == "EXISTS")
            not_found = sum(1 for r in results if r.verdict == "NOT_EXISTS")
            unknown = sum(1 for r in results if r.verdict == "UNKNOWN")
            errors = sum(1 for r in results if r.verdict == "ERROR")

            print(divider())
            print(f"  {C.BRIGHT_GREEN}Found:{C.RESET} {C.BOLD}{found}{C.RESET}  |  "
                  f"{C.BRIGHT_RED}Not found:{C.RESET} {C.BOLD}{not_found}{C.RESET}  |  "
                  f"{C.BRIGHT_YELLOW}Unknown:{C.RESET} {C.BOLD}{unknown}{C.RESET}  |  "
                  f"{C.BRIGHT_RED}Error:{C.RESET} {C.BOLD}{errors}{C.RESET}")

            if isinstance(proxies, ProxyRotator):
                print(f"  {C.DIM}Proxy health: {proxies.healthy_count()}/{len(proxies)} alive{C.RESET}")

            ask_save_results(results)
            input(f"\n{C.DIM}Press Enter...{C.RESET}")


if __name__ == "__main__":
    main()