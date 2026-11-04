"""Simple same-origin crawler for discovering parameterized URLs."""

from __future__ import annotations

import re
from collections import deque
from typing import Optional, Set
from urllib.parse import parse_qs, urljoin, urlparse

import requests


_HREF_RE = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.I)


def crawl(
    start_url: str,
    depth: int = 1,
    session: Optional[requests.Session] = None,
    headers: Optional[dict[str, str]] = None,
    timeout: float = 10.0,
    max_urls: int = 50,
) -> list[str]:
    """
    BFS crawl limited to same host. Returns URLs that contain query parameters.
    """
    session = session or requests.Session()
    headers = headers or {}
    start = urlparse(start_url)
    origin = f"{start.scheme}://{start.netloc}"
    seen: Set[str] = set()
    found: list[str] = []
    q: deque[tuple[str, int]] = deque([(start_url, 0)])

    while q and len(seen) < max_urls:
        url, d = q.popleft()
        if url in seen:
            continue
        seen.add(url)

        parsed = urlparse(url)
        if parse_qs(parsed.query):
            if url not in found:
                found.append(url)

        if d >= depth:
            continue

        try:
            resp = session.get(
                url,
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
        except requests.RequestException:
            continue

        for match in _HREF_RE.findall(resp.text or ""):
            abs_url = urljoin(url, match.split("#")[0])
            p = urlparse(abs_url)
            if p.scheme not in ("http", "https"):
                continue
            if f"{p.scheme}://{p.netloc}" != origin:
                continue
            if abs_url not in seen:
                q.append((abs_url, d + 1))

    return found
