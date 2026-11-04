"""Three-layer XSS detection engine."""

from __future__ import annotations

import html
import random
import string
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests
import urllib3

from xsspor.browser import USER_AGENTS, verify_xss
from xsspor.context import (
    context_to_categories,
    detect_context,
    severity_for,
)
from xsspor.payloads import all_payloads
from xsspor.proxy import ProxyPool

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class Finding:
    url: str
    method: str
    field: str
    payload: str
    category: str
    reflection: str
    context: str
    severity: str
    status_code: int
    evidence: str
    baseline_len: int
    response_len: int
    confirmed: Optional[bool] = None
    screenshot: Optional[str] = None
    request_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanConfig:
    url: str
    method: str = "GET"
    data: Optional[dict[str, str]] = None
    headers: Optional[dict[str, str]] = None
    cookies: Optional[dict[str, str]] = None
    threads: int = 3
    delay: float = 0.5
    timeout: float = 12.0
    browser_verify: bool = False
    payload_categories: Optional[list[str]] = None
    smart_context: bool = True
    proxy_pool: Optional[ProxyPool] = None
    screenshot_dir: Optional[str] = None


class DetectionEngine:
    """
    Layer 1: baseline comparison (clean request vs payload request)
    Layer 2: reflection analysis (verbatim / encoded / partial / none)
    Layer 3: context detection + severity matrix (+ optional Playwright)
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = requests.Session()
        if config.headers:
            self.session.headers.update(config.headers)
        if config.cookies:
            self.session.cookies.update(config.cookies)
        if "User-Agent" not in self.session.headers:
            self.session.headers["User-Agent"] = random.choice(USER_AGENTS)

        self.marker = "xom" + "".join(random.choices(string.ascii_lowercase, k=6)) + "xom"
        self.findings: list[Finding] = []
        self._lock = threading.Lock()
        self._last = 0.0
        self._rate_lock = threading.Lock()
        self.stats = {
            "sent": 0,
            "ok": 0,
            "errors": 0,
            "reflected": 0,
            "confirmed": 0,
        }
        self.successful_payloads: list[dict[str, Any]] = []

    def _rate_limit(self) -> None:
        with self._rate_lock:
            now = time.monotonic()
            slot = max(now, self._last + self.config.delay)
            self._last = slot
        wait = slot - time.monotonic()
        if wait > 0:
            time.sleep(wait)

    def _fields(self) -> list[str]:
        parsed = urlparse(self.config.url)
        if self.config.method.upper() == "GET":
            params = parse_qs(parsed.query, keep_blank_values=True)
            if params:
                return list(params.keys())
            if self.config.data:
                return list(self.config.data.keys())
            return []
        return list((self.config.data or {}).keys())

    def _build_request(self, field: str, value: str) -> tuple[str, Optional[dict[str, str]]]:
        if self.config.method.upper() == "GET":
            parsed = urlparse(self.config.url)
            q = parse_qs(parsed.query, keep_blank_values=True)
            if not q and self.config.data:
                q = {k: [v] for k, v in self.config.data.items()}
            q[field] = [value]
            return urlunparse(parsed._replace(query=urlencode(q, doseq=True))), None
        body = dict(self.config.data or {})
        body[field] = value
        return self.config.url, body

    def _request(self, field: str, value: str) -> tuple[Optional[requests.Response], str]:
        self._rate_limit()
        proxy = None
        pd = None
        if self.config.proxy_pool:
            proxy = self.config.proxy_pool.next()
            pd = self.config.proxy_pool.as_requests_dict(proxy)

        target, data = self._build_request(field, value)
        with self._lock:
            self.stats["sent"] += 1
        try:
            if self.config.method.upper() == "GET":
                resp = self.session.get(
                    target,
                    timeout=self.config.timeout,
                    verify=False,
                    allow_redirects=False,
                    proxies=pd,
                )
            else:
                resp = self.session.post(
                    target,
                    data=data,
                    timeout=self.config.timeout,
                    verify=False,
                    allow_redirects=False,
                    proxies=pd,
                )
            with self._lock:
                self.stats["ok"] += 1
            return resp, target
        except requests.exceptions.ProxyError:
            if proxy and self.config.proxy_pool:
                self.config.proxy_pool.mark_dead(proxy)
            with self._lock:
                self.stats["errors"] += 1
            return None, target
        except requests.RequestException:
            with self._lock:
                self.stats["errors"] += 1
            return None, target

    def _baseline(self, field: str) -> tuple[int, str]:
        resp, _ = self._request(field, "xomlsx_baseline")
        if resp is None:
            return 0, ""
        return len(resp.text or ""), resp.text or ""

    @staticmethod
    def _reflection_type(body: str, payload: str, marker: str) -> str:
        if not body:
            return "none"
        if payload in body:
            return "verbatim"
        # HTML-encoded reflection
        enc = html.escape(payload)
        if enc in body and enc != payload:
            return "encoded"
        # partial: unique marker or significant substring
        if marker in body:
            return "partial"
        if len(payload) >= 8:
            chunk = payload[: max(6, len(payload) // 3)]
            if chunk in body:
                return "partial"
        return "none"

    @staticmethod
    def _evidence(body: str, needle: str, radius: int = 40) -> str:
        i = body.find(needle)
        if i == -1:
            return ""
        start = max(0, i - radius)
        end = min(len(body), i + len(needle) + radius)
        return body[start:end].replace("\n", " ").replace("\r", " ")

    def _probe_context(self, field: str) -> str:
        """Inject a neutral marker once to guess reflection context."""
        token = f"XOMCTX{self.marker}XOM"
        resp, _ = self._request(field, token)
        if resp is None:
            return "unknown"
        return detect_context(resp.text or "", token)

    def _test_one(
        self,
        field: str,
        category: str,
        payload: str,
        baseline_len: int,
    ) -> Optional[Finding]:
        # embed marker for partial detection without breaking most payloads
        tagged = payload
        resp, req_url = self._request(field, tagged)
        if resp is None:
            return None

        body = resp.text or ""
        reflection = self._reflection_type(body, tagged, self.marker)
        if reflection == "none":
            # still note large length delta as weak signal — mark INFO only if delta huge
            if abs(len(body) - baseline_len) < 20:
                return None
            reflection = "none"

        ctx = detect_context(body, tagged if tagged in body else self.marker)
        if reflection == "none":
            severity = "INFO"
            evidence = ""
        else:
            evidence_needle = tagged if tagged in body else self.marker
            evidence = self._evidence(body, evidence_needle)
            severity = severity_for(ctx, reflection, confirmed=None)

        finding = Finding(
            url=self.config.url,
            method=self.config.method.upper(),
            field=field,
            payload=tagged,
            category=category,
            reflection=reflection,
            context=ctx,
            severity=severity,
            status_code=resp.status_code,
            evidence=evidence,
            baseline_len=baseline_len,
            response_len=len(body),
            request_url=req_url,
        )

        if reflection != "none":
            with self._lock:
                self.stats["reflected"] += 1

        # Playwright for HIGH+ candidates
        if (
            self.config.browser_verify
            and severity in ("HIGH", "CRITICAL", "MEDIUM")
            and reflection in ("verbatim", "encoded")
            and self.config.method.upper() == "GET"
        ):
            shot = None
            if self.config.screenshot_dir:
                import os

                os.makedirs(self.config.screenshot_dir, exist_ok=True)
                safe = "".join(c if c.isalnum() else "_" for c in field)[:20]
                shot = os.path.join(
                    self.config.screenshot_dir,
                    f"xss_{int(time.time())}_{safe}.png",
                )
            result = verify_xss(
                self.config.url,
                field,
                tagged,
                method="GET",
                headers=dict(self.session.headers),
                timeout=self.config.timeout,
                screenshot_path=shot,
            )
            finding.confirmed = result.get("fired")
            finding.screenshot = result.get("screenshot")
            if finding.confirmed is True:
                finding.severity = "CRITICAL"
                with self._lock:
                    self.stats["confirmed"] += 1
            elif finding.confirmed is False and finding.severity == "HIGH":
                # reflection without execution
                finding.severity = "MEDIUM"

        if finding.reflection == "none" and finding.severity == "INFO":
            return None

        with self._lock:
            self.findings.append(finding)
            if finding.reflection in ("verbatim", "encoded", "partial") or finding.confirmed is True:
                self.successful_payloads.append({
                    "payload": finding.payload,
                    "category": finding.category,
                    "field": finding.field,
                    "context": finding.context,
                    "reflection": finding.reflection,
                    "severity": finding.severity,
                    "confirmed": finding.confirmed,
                    "url": finding.url,
                })
        return finding

    def scan(self, on_finding: Optional[Callable[[Finding], None]] = None) -> list[Finding]:
        fields = self._fields()
        if not fields:
            raise ValueError(
                "No injectable parameters found. Provide query string or --data for POST."
            )

        # baseline per field
        baselines: dict[str, int] = {}
        guessed_ctx: dict[str, str] = {}
        for field in fields:
            blen, _ = self._baseline(field)
            baselines[field] = blen
            if self.config.smart_context:
                guessed_ctx[field] = self._probe_context(field)

        tasks: list[tuple[str, str, str, int]] = []
        for field in fields:
            cats = self.config.payload_categories
            if self.config.smart_context and not cats:
                cats = context_to_categories(guessed_ctx.get(field, "unknown"))
            payloads = all_payloads(self.marker, categories=cats)
            for category, payload in payloads:
                tasks.append((field, category, payload, baselines[field]))

        random.shuffle(tasks)
        workers = max(1, min(20, self.config.threads))

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(self._test_one, f, c, p, b) for f, c, p, b in tasks
            ]
            for fut in as_completed(futures):
                try:
                    finding = fut.result()
                    if finding and on_finding:
                        on_finding(finding)
                except Exception:
                    with self._lock:
                        self.stats["errors"] += 1

        # sort findings by severity weight
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.findings.sort(key=lambda x: (order.get(x.severity, 9), x.field))
        return self.findings
