#!/usr/bin/env python3
"""JS / page secret hunter — API keys, tokens, private keys in HTML/JS."""
from __future__ import annotations

import hashlib
import math
import os
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from core_utils import (
    C, get, normalize_url, pause, preflight_attack,
    print_finding, save_json_report, session,
)

# ── patterns with severity ───────────────────────────────────────────────────
# (name, regex, severity, confidence)
SECRET_PATTERNS: List[Tuple[str, re.Pattern, str, str]] = [
    # CRITICAL — direct cloud access
    ("AWS Access Key",       re.compile(r"AKIA[0-9A-Z]{16}"), "critical", "high"),
    ("AWS Secret Key",       re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key[\"'\s:=]+[\"']([A-Za-z0-9/+=]{30,})[\"']"), "critical", "high"),
    ("Google API Key",       re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "critical", "high"),
    ("GitHub Token",         re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"), "critical", "high"),
    ("Slack Token",          re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "critical", "high"),
    ("Private Key",          re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "critical", "high"),
    ("Stripe Live",          re.compile(r"sk_live_[0-9A-Za-z]{20,}"), "critical", "high"),
    ("SendGrid",             re.compile(r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"), "critical", "high"),
    ("Firebase",             re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"), "critical", "high"),
    ("Discord Bot Token",    re.compile(r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"), "critical", "high"),
    ("Telegram Bot Token",   re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}"), "critical", "high"),
    ("Mailgun",              re.compile(r"key-[0-9a-zA-Z]{32}"), "critical", "high"),

    # HIGH — auth tokens
    ("JWT",                  re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "high", "high"),
    ("Bearer Token",         re.compile(r"(?i)bearer\s+([A-Za-z0-9\-._~+/]{20,}=*)"), "high", "medium"),
    ("Basic Auth",           re.compile(r"(?i)authorization\s*[:=]\s*['\"]?basic\s+([A-Za-z0-9+/=]{16,})"), "high", "high"),
    ("Twilio",               re.compile(r"SK[0-9a-fA-F]{32}"), "high", "high"),
    ("Stripe Test",          re.compile(r"sk_test_[0-9A-Za-z]{20,}"), "high", "medium"),
    ("Facebook Token",       re.compile(r"EAACEdEose0cBA[0-9A-Za-z]+"), "high", "high"),
    ("Heroku API",           re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "medium", "low"),

    # MEDIUM — generic
    ("Generic API Key",      re.compile(r"(?i)(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key|auth[_-]?token)[\"'\s:=]+[\"']([A-Za-z0-9_\-]{20,})[\"']"), "medium", "medium"),
    ("Generic Secret",       re.compile(r"(?i)(?:secret|password|passwd|pwd)[\"'\s:=]+[\"']([^\s\"']{8,})[\"']"), "medium", "low"),
    ("Google OAuth",         re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"), "low", "high"),
    ("reCAPTCHA Site",       re.compile(r"6[0-9A-Za-z_-]{39}"), "low", "medium"),
    ("Cloudflare",           re.compile(r"(?i)cloudflare[_-]?(?:api[_-]?)?(?:key|token)[\"'\s:=]+[\"']([A-Za-z0-9_-]{30,})[\"']"), "high", "medium"),
]

# ── false-positive filter ────────────────────────────────────────────────────
FP_WORDS = re.compile(
    r"(?i)(?:example|sample|placeholder|dummy|test|fake|your[_-]?|xxx|abc123|"
    r"changeme|todo|fixme|redacted|hidden|\*{6,}|<[^>]+>)"
)
ENTROPY_MIN = 3.5  # shannon bits per char

SCRIPT_SRC   = re.compile(r"<script[^>]*\bsrc=[\"']([^\"']+)[\"']", re.I)
INLINE_JS    = re.compile(r"<script(?:\s[^>]*)?>(.*?)</script>", re.I | re.S)
SOURCEMAP    = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")
JS_URL_IN_JS = re.compile(r"[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']")


# ── UI ───────────────────────────────────────────────────────────────────────
def clear():
    os.system("cls" if os.name == "nt" else "clear")


def banner():
    clear()
    print(f"""{C.RED}{C.B}
▄▄▄   ▄▄▄                               
███   ███              ██               
█████████ ██ ██ ████▄ ▀██▀▀ ▄█▀█▄ ████▄ 
███▀▀▀███ ██ ██ ██ ██  ██   ██▄█▀ ██ ▀▀ 
███   ███ ▀██▀█ ██ ██  ██   ▀█▄▄▄ ██    
{C.R}{C.GOLD}{C.B}      XOMLEK  /  JS SECRET HUNTER v2{C.R}
{C.GRAY}   API Keys  •  Tokens  •  Entropy  •  Sourcemaps{C.R}
{C.DIM}         authorized testing only{C.R}
""")


def status(msg: str, kind: str = "info"):
    m = {"ok": (C.GREEN, "[+]"), "err": (C.CRIM, "[!]"),
         "warn": (C.YEL, "[~]"), "info": (C.CYN, "[*]"),
         "hit": (C.LIME, "[!]")}
    c, t = m.get(kind, (C.CYN, "[*]"))
    print(f"  {c}{t} {msg}{C.R}")


# ── entropy ──────────────────────────────────────────────────────────────────
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_likely_fp(value: str) -> bool:
    return bool(FP_WORDS.search(value)) or len(value) < 8


# ── extraction ───────────────────────────────────────────────────────────────
def extract_script_urls(html: str, base: str) -> List[str]:
    urls: Set[str] = set()
    for m in SCRIPT_SRC.finditer(html or ""):
        urls.add(urljoin(base, m.group(1)))
    # also .js URLs mentioned inside inline JS
    for m in INLINE_JS.finditer(html or ""):
        for j in JS_URL_IN_JS.finditer(m.group(1)):
            try:
                urls.add(urljoin(base, j.group(1)))
            except Exception:
                pass
    return list(urls)


def extract_inline_js(html: str) -> List[str]:
    return [m.group(1) for m in INLINE_JS.finditer(html or "") if m.group(1).strip()]


def extract_sourcemaps(js_text: str, base: str) -> List[str]:
    urls: Set[str] = set()
    for m in SOURCEMAP.finditer(js_text or ""):
        try:
            urls.add(urljoin(base, m.group(1)))
        except Exception:
            pass
    return list(urls)


# ── scanner ──────────────────────────────────────────────────────────────────
def scan_text(text: str, source: str) -> List[dict]:
    hits: List[dict] = []
    seen: Set[str] = set()
    text = text or ""

    # regex patterns
    for name, rx, sev, conf in SECRET_PATTERNS:
        for m in rx.finditer(text):
            val = m.group(0)
            if is_likely_fp(val):
                continue
            key = hashlib.md5(val.encode(errors="ignore")).hexdigest()
            if key in seen:
                continue
            seen.add(key)
            # context ±40 chars
            start = max(0, m.start() - 40)
            end = min(len(text), m.end() + 40)
            ctx = text[start:end].replace("\n", " ")[:140]
            hits.append({
                "type": name, "match": val[:120], "source": source,
                "severity": sev, "confidence": conf, "context": ctx,
                "method": "regex",
            })

    # entropy-based (high-entropy 20-64 char tokens in quotes)
    for m in re.finditer(r"[\"']([A-Za-z0-9_\-+/=]{20,64})[\"']", text):
        val = m.group(1)
        if val in seen or is_likely_fp(val):
            continue
        # must look random: mix of upper/lower/digit AND high entropy
        has_mix = (any(c.isupper() for c in val)
                   and any(c.islower() for c in val)
                   and any(c.isdigit() for c in val))
        ent = shannon_entropy(val)
        if not (has_mix and ent >= ENTROPY_MIN):
            continue
        key = hashlib.md5(val.encode(errors="ignore")).hexdigest()
        if key in seen:
            continue
        seen.add(key)
        hits.append({
            "type": "High-Entropy String", "match": val[:120], "source": source,
            "severity": "medium", "confidence": "low",
            "context": f"entropy={ent:.2f}", "method": "entropy",
        })

    return hits


# ── fetch one URL (parallel-safe) ────────────────────────────────────────────
def fetch_and_scan(s, url: str, timeout: int = 10) -> Tuple[str, List[dict], List[str]]:
    """Returns (url, hits, child_js_urls)."""
    try:
        r = get(s, url, allow_redirects=True, timeout=timeout)
        if not r or not r.text:
            return url, [], []
        ctype = (r.headers.get("Content-Type") or "").lower()
        if ctype and not any(t in ctype for t in ("javascript", "ecmascript", "text/plain", "json", "html")):
            return url, [], []
        hits = scan_text(r.text, url)
        maps = extract_sourcemaps(r.text, url)
        return url, hits, maps
    except Exception:
        return url, [], []


# ── main ─────────────────────────────────────────────────────────────────────
def run(url: str = None):
    banner()
    url = normalize_url(url or input(f"  {C.AQUA}[?] URL:{C.R} "))
    if not url:
        pause()
        return

    cfg = preflight_attack()
    s = session(proxies=cfg["proxies"], headers=cfg["headers"])

    status(f"fetching {url}", "info")
    r = get(s, url, allow_redirects=True, timeout=12)
    if not r:
        status("no response", "err")
        pause()
        return

    findings: List[dict] = []

    # 1) main page
    findings.extend(scan_text(r.text or "", url))
    status(f"main page scanned ({len(r.text or '')} bytes)", "ok")

    # 2) inline scripts
    inline = extract_inline_js(r.text or "")
    for i, block in enumerate(inline):
        findings.extend(scan_text(block, f"{url}#inline-{i}"))
    status(f"inline <script> blocks: {len(inline)}", "info")

    # 3) external scripts (parallel)
    scripts = extract_script_urls(r.text or "", url)
    status(f"external scripts queued: {len(scripts)}", "info")

    sourcemaps: Set[str] = set()
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(fetch_and_scan, s, src): src for src in scripts[:80]}
        for i, fut in enumerate(as_completed(futs), 1):
            src, hits, maps = fut.result()
            if hits:
                findings.extend(hits)
                print(f"  {C.LIME}[!]{C.R} {len(hits)} hit(s) in {src[:60]}")
            sourcemaps.update(maps)
            if i % 10 == 0:
                print(f"  {C.DIM}... {i}/{len(futs)} scripts scanned{C.R}")

    # 4) source maps (gold mine)
    if sourcemaps:
        status(f"sourcemaps discovered: {len(sourcemaps)}", "hit")
        with ThreadPoolExecutor(max_workers=4) as pool:
            futs = {pool.submit(fetch_and_scan, s, sm, 15): sm for sm in list(sourcemaps)[:20]}
            for fut in as_completed(futs):
                sm, hits, _ = fut.result()
                if hits:
                    findings.extend(hits)
                    print(f"  {C.LIME}[!]{C.R} {len(hits)} hit(s) in sourcemap {sm[:60]}")

    # 5) dedupe
    uniq, seen_m = [], set()
    for h in findings:
        key = (h["type"], h["match"])
        if key not in seen_m:
            seen_m.add(key)
            uniq.append(h)

    # 6) sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    uniq.sort(key=lambda x: sev_order.get(x["severity"], 9))

    # 7) report
    print()
    if uniq:
        counts = Counter(h["severity"] for h in uniq)
        status(
            f"total: {len(uniq)}  |  "
            f"{C.CRIM}critical={counts['critical']}{C.R}  "
            f"{C.YEL}high={counts['high']}{C.R}  "
            f"{C.CYN}medium={counts['medium']}{C.R}  "
            f"{C.GRAY}low={counts['low']}{C.R}",
            "hit",
        )
        print()
        for h in uniq:
            sev_color = {"critical": C.CRIM, "high": C.YEL,
                         "medium": C.CYN, "low": C.GRAY}.get(h["severity"], C.GRAY)
            print(f"  {sev_color}[{h['severity'].upper()}]{C.R} "
                  f"{C.B}{h['type']}{C.R}  {C.DIM}({h['confidence']}){C.R}")
            print(f"    {C.LIME}{h['match'][:100]}{C.R}")
            print(f"    {C.DIM}{h['context'][:120]}{C.R}")
            print(f"    {C.GRAY}from: {h['source'][:80]}{C.R}")
            print()

        path = save_json_report("js_secrets", {
            "url": url,
            "summary": dict(counts),
            "findings": uniq,
        })
        status(f"saved → {path}", "ok")
    else:
        status("no secrets found", "warn")

    pause()


if __name__ == "__main__":
    run()
