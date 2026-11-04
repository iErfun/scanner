"""Optional Playwright confirmation for HIGH/CRITICAL candidates."""

from __future__ import annotations

import random
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
]


def _build_get_url(url: str, field: str, payload: str) -> str:
    parsed = urlparse(url)
    q = parse_qs(parsed.query, keep_blank_values=True)
    q[field] = [payload]
    return urlunparse(parsed._replace(query=urlencode(q, doseq=True)))


def verify_xss(
    url: str,
    field: str,
    payload: str,
    method: str = "GET",
    data: Optional[dict[str, str]] = None,
    headers: Optional[dict[str, str]] = None,
    proxy: Optional[str] = None,
    timeout: float = 12.0,
    screenshot_path: Optional[str] = None,
) -> dict[str, Any]:
    """
    Open payload in headless Chromium and watch for dialog / pageerror.

    Returns dict: fired (bool|None), error (str|None), screenshot (str|None)
    None fired means Playwright unavailable or skipped.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {
            "fired": None,
            "error": "playwright not installed (pip install playwright && playwright install chromium)",
            "screenshot": None,
        }

    hit = {"fired": False}
    ua = (headers or {}).get("User-Agent") or random.choice(USER_AGENTS)
    proxy_cfg = None
    if proxy:
        proxy_cfg = {"server": proxy}

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                proxy=proxy_cfg,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            context = browser.new_context(
                user_agent=ua,
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 720},
            )
            page = context.new_page()
            page.on("dialog", lambda d: (hit.update(fired=True), d.dismiss()))
            page.on("pageerror", lambda _e: hit.update(fired=True))

            try:
                if method.upper() == "GET":
                    target = _build_get_url(url, field, payload)
                    page.goto(target, timeout=int(timeout * 1000), wait_until="domcontentloaded")
                else:
                    # simple POST via form navigation is limited; use request + set content fallback
                    page.goto(url, timeout=int(timeout * 1000), wait_until="domcontentloaded")
                    page.evaluate(
                        """([field, payload]) => {
                            const f = document.createElement('form');
                            f.method = 'POST'; f.action = location.href;
                            const i = document.createElement('input');
                            i.name = field; i.value = payload;
                            f.appendChild(i); document.body.appendChild(f); f.submit();
                        }""",
                        [field, payload],
                    )
                page.wait_for_timeout(1500)
                if screenshot_path:
                    page.screenshot(path=screenshot_path, full_page=False)
            except Exception as exc:
                context.close()
                browser.close()
                return {"fired": hit["fired"], "error": str(exc)[:200], "screenshot": None}

            shot = screenshot_path if screenshot_path else None
            context.close()
            browser.close()
            return {"fired": hit["fired"], "error": None, "screenshot": shot}
    except Exception as exc:
        return {"fired": None, "error": str(exc)[:200], "screenshot": None}
