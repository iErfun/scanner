"""Proxy pool with optional Tor and simple rotation."""

from __future__ import annotations

import threading
from typing import Optional

import requests


class ProxyPool:
    """Round-robin proxy rotation with dead-marking."""

    def __init__(self, proxies: Optional[list[str]] = None, use_tor: bool = False):
        self._proxies: list[str] = list(proxies or [])
        if use_tor:
            tor = "socks5h://127.0.0.1:9050"
            if tor not in self._proxies:
                self._proxies.insert(0, tor)
        self._index = 0
        self._dead: set[str] = set()
        self._lock = threading.Lock()

    def add(self, proxy: str) -> None:
        with self._lock:
            if proxy and proxy not in self._proxies:
                self._proxies.append(proxy)

    def next(self) -> Optional[str]:
        with self._lock:
            alive = [p for p in self._proxies if p not in self._dead]
            if not alive:
                return None
            proxy = alive[self._index % len(alive)]
            self._index += 1
            return proxy

    def mark_dead(self, proxy: str) -> None:
        with self._lock:
            self._dead.add(proxy)

    def as_requests_dict(self, proxy: Optional[str]) -> Optional[dict[str, str]]:
        if not proxy:
            return None
        return {"http": proxy, "https": proxy}

    def alive_count(self) -> int:
        return len([p for p in self._proxies if p not in self._dead])

    def total(self) -> int:
        return len(self._proxies)

    def check_tor(self, timeout: float = 10.0) -> bool:
        proxy = "socks5h://127.0.0.1:9050"
        try:
            r = requests.get(
                "https://check.torproject.org/api/ip",
                proxies={"http": proxy, "https": proxy},
                timeout=timeout,
                verify=False,
            )
            return bool(r.json().get("IsTor"))
        except Exception:
            return False
