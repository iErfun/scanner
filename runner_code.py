#!/usr/bin/env python3
import os
import sys
import logging
import warnings
warnings.filterwarnings("ignore")
os.environ.setdefault("SCAPY_USE_PCAPDNET", "0")
for _n in ("scapy", "scapy.runtime", "scapy.loading", "scapy.layers"):
    logging.getLogger(_n).setLevel(logging.CRITICAL)
import re as _re
import socket
import subprocess
import urllib.request
import json

def _app_root():
    """Project root in source mode, PyInstaller extract dir when frozen."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))


BASE = _app_root()
if BASE not in sys.path:
    sys.path.insert(0, BASE)
# also keep the real exe dir for reports written next to the binary
EXE_DIR = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else BASE
if EXE_DIR not in sys.path:
    sys.path.insert(0, EXE_DIR)

# PyInstaller analysis anchors — keep modules in the frozen graph
try:
    import core_utils  # noqa: F401
    import subdomain_enum  # noqa: F401
    import dns_tools  # noqa: F401
    import header_audit  # noqa: F401
    import injection_pack  # noqa: F401
    import sqli_engine  # noqa: F401
    import js_secrets  # noqa: F401
    import dir_brute  # noqa: F401
    import tech_detect  # noqa: F401
    import attacks_modern  # noqa: F401
    import brute  # noqa: F401
    import word_list  # noqa: F401
    import xss  # noqa: F401
    import email_checker  # noqa: F401
    import username_finder  # noqa: F401
    import proxy_tester  # noqa: F401
    import scan_win  # noqa: F401
    import scanner  # noqa: F401
except Exception:
    pass


class Colors:
    R = '\033[0m'
    B = '\033[1m'
    D = '\033[2m'
    RED = '\033[91m'
    GRN = '\033[92m'
    YEL = '\033[93m'
    CYN = '\033[96m'
    WHT = '\033[97m'
    DIM_GRAY = '\033[38;2;137;151;171m'
    NEON_CYAN = '\033[38;2;82;190;255m'
    NEON_PURPLE = '\033[38;2;151;145;235m'
    CORNFLOWER = '\033[38;2;100;160;220m'
    CRIMSON = '\033[38;2;232;112;125m'
    GOLD = '\033[38;2;239;190;112m'
    NEON_LIME = '\033[38;2;111;204;166m'
    TEAL = '\033[38;2;82;190;255m'
    NEON_RED = '\033[38;2;232;112;125m'
    NEON_ORANGE = '\033[38;2;239;190;112m'


C = Colors
_ANSI = _re.compile(r'\033\[[0-9;]*m')


def _vlen(s):
    return len(_ANSI.sub('', s))


def clear():
    os.system("clear" if os.name == "posix" else "cls")


def pause():
    print(f"\n{C.DIM_GRAY}  Enter to continue...{C.R}", end="")
    input()


BOX_W = 58
BOX_C = C.CORNFLOWER


def _hline():
    return f"{BOX_C}{C.B}+{'-' * BOX_W}+{C.R}"


def box_top(title):
    pad = max(BOX_W - _vlen(title), 0)
    left = pad // 2
    right = pad - left
    return (
        _hline() + "\n" +
        f"{BOX_C}{C.B}|{C.R}"
        f"{' ' * left}{title}{' ' * right}"
        f"{BOX_C}{C.B}|{C.R}" + "\n" +
        _hline()
    )


def box_item(key, label):
    line = f" {C.GOLD}{key}{C.R}) {label}"
    space = BOX_W - _vlen(line) - 1
    if space < 1:
        space = 1
    return f"{BOX_C}{C.B}|{C.R}{line}{' ' * space}{BOX_C}{C.B}|{C.R}"


def box_bottom():
    return _hline()


def box_menu(title, items):
    out = [box_top(title)]
    for key, label in items:
        out.append(box_item(key, label))
    out.append(box_bottom())
    return "\n".join(out)


def banner():
    clear()
    print(f"\n{C.NEON_CYAN}{C.B}  X O M L S X  /  SECURITY WORKSPACE{C.R}")
    print(f"{C.DIM_GRAY}  Reconnaissance  •  Assessment  •  Intelligence{C.R}\n")
    print(box_menu("MAIN MENU", [
        ("1", f"{C.NEON_CYAN}Network Scanner{C.R}"),
        ("2", f"{C.NEON_CYAN}Attack & Assessment{C.R}"),
        ("3", f"{C.NEON_CYAN}OSINT & Intelligence{C.R}"),
        ("0", f"{C.DIM_GRAY}Exit{C.R}"),
    ]))
    print(f"\n  {C.DIM_GRAY}Select a workspace to continue.{C.R}")

def attack_banner():
    clear()
    print(f"\n{C.NEON_PURPLE}{C.B}  ATTACK & ASSESSMENT{C.R}")
    print(f"{C.DIM_GRAY}  Testing modules and security checks{C.R}\n")
    print(box_menu("MODULES", [
        ("1", f"{C.NEON_CYAN}Bruteforce{C.R}"),
        ("2", f"{C.NEON_CYAN}Wordlist Generator{C.R}"),
        ("3", f"{C.NEON_CYAN}XSS Scanner{C.R}"),
        ("4", f"{C.NEON_CYAN}Modern Assessment{C.R}"),
        ("5", f"{C.NEON_CYAN}SQL Injection Engine{C.R}"),
        ("6", f"{C.NEON_CYAN}Injection Pack{C.R}"),
        ("7", f"{C.NEON_CYAN}Header / Tech Audit{C.R}"),
        ("8", f"{C.NEON_CYAN}JavaScript Secret Hunter{C.R}"),
        ("9", f"{C.NEON_CYAN}Directory Discovery{C.R}"),
        ("10", f"{C.NEON_CYAN}Technology Detection{C.R}"),
        ("0", f"{C.DIM_GRAY}Back{C.R}"),
    ]))

def osint_banner():
    clear()
    print(f"\n{C.NEON_PURPLE}{C.B}  OSINT & INTELLIGENCE{C.R}")
    print(f"{C.DIM_GRAY}  Open-source information gathering{C.R}\n")
    print(box_menu("MODULES", [
        ("1", f"{C.NEON_CYAN}Username Finder{C.R}"),
        ("2", f"{C.NEON_CYAN}IP Intelligence{C.R}"),
        ("3", f"{C.NEON_CYAN}Metadata Extractor{C.R}"),
        ("4", f"{C.NEON_CYAN}Email Checker{C.R}"),
        ("0", f"{C.DIM_GRAY}Back{C.R}"),
    ]))

def _safe(label, fn):
    try:
        fn()
    except SystemExit:
        pass
    except KeyboardInterrupt:
        print(f"\n{C.CRIMSON}[!] Interrupted{C.R}")
        pause()
    except Exception as e:
        print(f"{C.CRIMSON}[!] {label} error: {e}{C.R}")
        import traceback
        traceback.print_exc()
        pause()


def run_scanner_direct():
    def _():
        import scanner
        scanner.main()
    _safe("Scanner", _)


def run_bruteforce():
    def _():
        import brute
        brute.run()
    _safe("Bruteforce", _)


def run_wordlist():
    def _():
        import word_list
        word_list.run()
    _safe("Wordlist", _)


def run_xss():
    def _():
        import xss
        xss.run()
    _safe("XSS", _)


def run_osint_module(name):
    def _():
        import importlib
        # email_checker lives at project root; others under osint/
        if name == "email_checker":
            mod = importlib.import_module("email_checker")
        else:
            mod = importlib.import_module(f"osint.{name}")
        if hasattr(mod, "run"):
            mod.run()
        elif hasattr(mod, "main"):
            mod.main()
        elif hasattr(mod, "main_menu"):
            mod.main_menu()
        else:
            print(f"{C.CRIMSON}[!] No run()/main()/main_menu() in {name}{C.R}")
            pause()
    _safe(name, _)



def attack_menu():
    while True:
        attack_banner()
        c = input(f"{C.GOLD}{C.B}>>{C.R} ").strip()
        if c == "0":
            return
        elif c == "1":
            _safe("brute", lambda: _run_module("brute"))
        elif c == "2":
            _safe("word_list", lambda: _run_module("word_list"))
        elif c == "3":
            _safe("xss", lambda: _run_module("xss"))
        elif c == "4":
            _safe("modern", lambda: _run_module("attacks_modern"))
        elif c == "5":
            _safe("sqli", lambda: _run_module("sqli_engine"))
        elif c == "6":
            _safe("injection", lambda: _run_module("injection_pack"))
        elif c == "7":
            _safe("headers", lambda: _run_module("header_audit"))
        elif c == "8":
            _safe("js_secrets", lambda: _run_module("js_secrets"))
        elif c == "9":
            _safe("dir_brute", lambda: _run_module("dir_brute"))
        elif c == "10":
            _safe("tech_detect", lambda: _run_module("tech_detect"))
        else:
            print(f"{C.CRIMSON}[!] Invalid{C.R}")
            pause()



def osint_menu():
    MODULES = {
        "1": "username_finder",
        "2": "osint.ip_intel",
        "3": "osint.metadata",
        "4": "email_checker",
    }
    while True:
        osint_banner()
        c = input(f"{C.GOLD}{C.B}>>{C.R} ").strip()
        if c == "0":
            return
        elif c in MODULES:
            name = MODULES[c]
            if name == "email_checker":
                _safe("email", lambda: _run_module("email_checker"))
            elif name.startswith("osint."):
                _safe(name, lambda n=name: _run_module(n))
            else:
                _safe(name, lambda n=name: _run_module(n))
        else:
            print(f"{C.CRIMSON}[!] Invalid{C.R}")
            pause()


def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def _get_public_ip():
    services = [
        "https://api.ipify.org?format=json",
        "https://ipinfo.io/json",
        "https://ifconfig.me/all.json",
    ]
    for url in services:
        try:
            with urllib.request.urlopen(url, timeout=4) as r:
                data = json.loads(r.read().decode())
                if "ip" in data:
                    return data["ip"]
        except Exception:
            continue
    return None


def _get_interfaces():
    interfaces = []
    try:
        if os.name == "posix":
            try:
                out = subprocess.check_output(
                    ["ip", "-o", "addr", "show"], stderr=subprocess.DEVNULL
                ).decode()
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] == "inet":
                        iface = parts[1]
                        ip = parts[3].split("/")[0]
                        if not ip.startswith("127."):
                            interfaces.append((iface, ip))
            except Exception:
                out = subprocess.check_output(
                    ["ifconfig"], stderr=subprocess.DEVNULL
                ).decode()
                current = None
                for line in out.splitlines():
                    if line and not line.startswith((" ", "\t")):
                        current = line.split(":")[0].split()[0]
                    if "inet " in line:
                        parts = line.split()
                        for i, p in enumerate(parts):
                            if p == "inet":
                                ip = parts[i + 1]
                                if not ip.startswith("127."):
                                    interfaces.append((current or "?", ip))
                                break
        else:
            out = subprocess.check_output(
                ["ipconfig"], stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            current = None
            for line in out.splitlines():
                line = line.strip()
                if "adapter" in line.lower():
                    current = line.rstrip(":")
                if "IPv4" in line and ":" in line:
                    ip = line.split(":")[-1].strip()
                    if ip and not ip.startswith("127."):
                        interfaces.append((current or "?", ip))
    except Exception as e:
        interfaces.append(("error", str(e)))
    return interfaces


def _ping(host="8.8.8.8"):
    try:
        if os.name == "posix":
            cmd = ["ping", "-c", "2", "-W", "2", host]
        else:
            cmd = ["ping", "-n", "2", "-w", "2000", host]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0, result.stdout
    except Exception as e:
        return False, str(e)


def check_internet_connection():
    clear()
    print(f"{C.NEON_CYAN}{C.B}* -Internet-Connection-Check- *{C.R}\n")

    print(f"{C.CORNFLOWER}{C.B}[ Network Interfaces ]{C.R}")
    ifaces = _get_interfaces()
    if ifaces:
        for name, ip in ifaces:
            print(f"  {C.GRN}●{C.R} {C.WHT}{name:<20}{C.R} {C.NEON_CYAN}{ip}{C.R}")
    else:
        print(f"  {C.CRIMSON}no interface detected{C.R}")
    print()

    print(f"{C.CORNFLOWER}{C.B}[ Private IP ]{C.R}")
    private_ip = _get_local_ip()
    if private_ip:
        print(f"  {C.GRN}●{C.R} {C.WHT}{private_ip}{C.R}")
    else:
        print(f"  {C.CRIMSON}unavailable{C.R}")
    print()

    print(f"{C.CORNFLOWER}{C.B}[ Public IP ]{C.R}")
    print(f"  {C.DIM_GRAY}querying...{C.R}", end="\r")
    public_ip = _get_public_ip()
    print(" " * 40, end="\r")
    if public_ip:
        print(f"  {C.GRN}●{C.R} {C.WHT}{public_ip}{C.R}")
    else:
        print(f"  {C.CRIMSON}unavailable (offline?){C.R}")
    print()

    print(f"{C.CORNFLOWER}{C.B}[ Ping Test -> 8.8.8.8 ]{C.R}")
    ok, out = _ping()
    if ok:
        for line in out.splitlines():
            low = line.lower()
            if ("packets transmitted" in low or "packet loss" in low
                    or "rtt" in low or "average" in low or "minimum" in low):
                print(f"  {C.DIM_GRAY}{line.strip()}{C.R}")
        print(f"  {C.GRN}[+] Reachable{C.R}")
    else:
        print(f"  {C.CRIMSON}[!] No response{C.R}")
    print()

    if not public_ip or not ok:
        print(f"{C.NEON_RED}{C.B}[!] No active Internet connection detected.{C.R}")
        print(f"{C.DIM_GRAY}This tool requires an Internet connection to run.{C.R}\n")
        print(f"{C.NEON_ORANGE}Press Enter to exit...{C.R}", end="")
        input()
        sys.exit(1)

    print(f"{C.NEON_LIME}{C.B}[+] Internet connection is active.{C.R}")
    print(f"{C.TEAL}Press Enter to continue to main menu...{C.R}", end="")
    input()


def _run_module(name):
    """Import and run a module entry. Works in source and PyInstaller frozen mode."""
    import importlib
    import importlib.util

    search_roots = []
    for r in (BASE, EXE_DIR, os.getcwd()):
        if r and r not in search_roots:
            search_roots.append(r)
            if r not in sys.path:
                sys.path.insert(0, r)

    mod = None
    last_err = None
    try:
        mod = importlib.import_module(name)
    except Exception as e:
        last_err = e
        # file fallback across frozen extract dir + cwd
        fname = name.replace(".", os.sep) + ".py"
        for root in search_roots:
            fpath = os.path.join(root, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                spec = importlib.util.spec_from_file_location(name, fpath)
                mod = importlib.util.module_from_spec(spec)
                sys.modules[name] = mod
                spec.loader.exec_module(mod)
                last_err = None
                break
            except Exception as e2:
                last_err = e2

    if mod is None:
        print(f"{C.CRIMSON}[!] import {name}: {last_err}{C.R}")
        for root in search_roots:
            print(f"{C.DIM_GRAY}    looked in: {os.path.join(root, name.replace('.', os.sep) + '.py')}{C.R}")
        pause()
        return

    for fn in ("run", "main", "show_modern_menu", "run_full_modern_scan", "main_menu"):
        if hasattr(mod, fn) and callable(getattr(mod, fn)):
            try:
                getattr(mod, fn)()
            except SystemExit as se:
                # modules sometimes call sys.exit after a scan — stay in launcher
                code = getattr(se, "code", None)
                if code not in (None, 0):
                    print(f"{C.DIM_GRAY}[module exit code {code}]{C.R}")
            except KeyboardInterrupt:
                print(f"\n{C.CRIMSON}[!] interrupted{C.R}")
                try:
                    pause()
                except Exception:
                    pass
            except Exception as e:
                print(f"{C.CRIMSON}[!] {name}.{fn}: {e}{C.R}")
                import traceback
                traceback.print_exc()
                pause()
            return
    print(f"{C.CRIMSON}[!] no entrypoint in {name}{C.R}")
    pause()


def main():
    while True:
        banner()
        choice = input(f"{C.GOLD}{C.B}>>{C.R} ").strip()

        if choice == "0":
            print(f"\n{C.CRIMSON}{C.B}Bye{C.R}\n")
            break
        elif choice == "1":
            run_scanner_direct()
        elif choice == "2":
            attack_menu()
        elif choice == "3":
            osint_menu()
        else:
            print(f"{C.CRIMSON}[!] Invalid option{C.R}")
            pause()


if __name__ == "__main__":
    try:
        check_internet_connection()
        main()
    except KeyboardInterrupt:
        print(f"\n{C.CRIMSON}Bye{C.R}")
