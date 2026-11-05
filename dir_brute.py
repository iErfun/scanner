#!/usr/bin/env python3
"""Directory / path brute-forcer with status filtering."""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Set
from urllib.parse import urljoin

from core_utils import C, get, normalize_url, pause, root_of, save_json_report, session

DEFAULT_PATHS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "dashboard",
    "api", "api/v1", "api/v2", "graphql", "swagger", "swagger-ui", "docs",
    "robots.txt", "sitemap.xml", ".env", ".git/HEAD", ".git/config",
    "backup", "backups", "old", "test", "dev", "staging", "config",
    "phpinfo.php", "info.php", "server-status", "server-info",
    "actuator", "actuator/health", "actuator/env", "console",
    "manager", "manager/html", "jmx-console", "web-console",
    "uploads", "upload", "files", "static", "assets", "images",
    "debug", "trace", "metrics", "health", "status",
    "admin.php", "login.php", "index.php.bak", "web.config",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "wp-content", "wp-includes", "xmlrpc.php",
    "api/swagger.json", "openapi.json", "v2/api-docs",
]


def load_paths(path: Optional[str]) -> List[str]:
    words = list(DEFAULT_PATHS)
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip().lstrip("/")
                if w and not w.startswith("#") and w not in words:
                    words.append(w)
    return words


def check(s, base: str, path: str, interesting: Set[int]):
    url = urljoin(base.rstrip("/") + "/", path)
    r = get(s, url, allow_redirects=False, timeout=8)
    if not r:
        return None
    if r.status_code in interesting:
        return {"path": path, "url": url, "status": r.status_code, "length": len(r.content or b"")}
    return None


def run(url: str = None):
    print(f"\n{C.PURP}{C.B}  Directory Brute{C.R}\n")
    url = normalize_url(url or input(f"{C.AQUA}[?] Base URL: {C.R}"))
    if not url:
        pause()
        return
    base = root_of(url)
    wl = input(f"{C.AQUA}[?] Wordlist path (Enter=built-in): {C.R}").strip()
    paths = load_paths(wl or None)
    threads = 30
    interesting = {200, 201, 204, 301, 302, 307, 401, 403, 405, 500}
    s = session(timeout=8)
    print(f"{C.GOLD}[*] {len(paths)} paths against {base} ...{C.R}")
    hits = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(check, s, base, p, interesting): p for p in paths}
        for fut in as_completed(futs):
            res = fut.result()
            if res:
                hits.append(res)
                color = C.GREEN if res["status"] < 400 else C.YEL
                print(f"  {color}[{res['status']}]{C.R} {res['path']}  {C.GRAY}len={res['length']}{C.R}")
    hits.sort(key=lambda x: x["path"])
    print(f"\n{C.NEON}[+] hits: {len(hits)}{C.R}")
    path = save_json_report("dir_brute", {"base": base, "hits": hits})
    print(f"{C.GREEN}[+] Saved: {path}{C.R}")
    pause()


if __name__ == "__main__":
    run()
