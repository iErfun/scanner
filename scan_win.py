import socket
import time
import sys
import os
import re
import random
import struct
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    sys.stdout.reconfigure(line_buffering=False, write_through=True)
except (AttributeError, ValueError):
    pass

from scapy.all import IP, TCP, ICMP, ARP, Ether, sr1, srp, RandShort

try:
    from impacket.smbconnection import SMBConnection

    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False


class WinColors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    DIM_GRAY = '\033[38;2;110;110;120m'
    NEON_CYAN = '\033[38;2;0;255;213m'
    GOLD = '\033[38;2;255;215;0m'
    CRIMSON = '\033[38;2;220;20;60m'
    AQUA = '\033[38;2;0;255;255m'
    ORANGE = '\033[38;2;255;165;0m'


print_lock = threading.Lock()

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 3306, 3389, 5432, 5900, 5985, 5986,
    8000, 8080, 8443, 8888
]

BUILD_MAP = {
    "7600": ("Windows 7", "RTM"),
    "7601": ("Windows 7", "SP1"),
    "9200": ("Windows 8", "RTM"),
    "9600": ("Windows 8.1", "Update 1"),
    "10240": ("Windows 10", "1507"),
    "10586": ("Windows 10", "1511"),
    "14393": ("Windows 10", "1607"),
    "15063": ("Windows 10", "1703"),
    "16299": ("Windows 10", "1709"),
    "17134": ("Windows 10", "1803"),
    "17763": ("Windows Server 2019 / Win10", "1809"),
    "18362": ("Windows 10", "1903"),
    "18363": ("Windows 10", "1909"),
    "19041": ("Windows 10", "2004"),
    "19042": ("Windows 10", "20H2"),
    "19043": ("Windows 10", "21H1"),
    "19044": ("Windows 10", "21H2"),
    "19045": ("Windows 10", "22H2"),
    "20348": ("Windows Server 2022", "21H2"),
    "22000": ("Windows 11", "21H2"),
    "22621": ("Windows 11", "22H2"),
    "22631": ("Windows 11", "23H2"),
    "26100": ("Windows 11", "24H2"),
}

OS_SIGNATURES = {
    ("MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK"): "Windows",
    ("MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK", "Timestamp"): "Windows",
    ("MSS", "NOP", "WScale", "NOP", "SAckOK", "Timestamp"): "Windows",
    ("MSS", "SAckOK", "Timestamp", "NOP", "WScale"): "Linux",
    ("MSS", "SAckOK", "Timestamp", "WScale"): "Linux",
    ("MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp", "SAckOK"): "macOS",
    ("MSS", "NOP", "WScale", "SAckOK", "Timestamp"): "FreeBSD",
}


def print_banner():
    os.system("clear" if os.name == "posix" else "cls")
    print(WinColors.CRIMSON + r"""
  ▄▄▄▄▄▄▄▄     ▄▄▄▄▄▄▄▄     ▄▄▄▄▄▄▄▄     ▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄▄▄     ▄▄▄▄▄▄▄▄   ▄▄▄▄▄       
▄▀▓▓▓▓▓▓▓▓▀▄ ▄▀▓▓▓▓▓▓▓▓▀▄ ▄▀▓▓▓▓▓▓▓▓▀▄ ▄▀▓▓▓▓▓▓▓▓▀▄      ▄▀▓▓▓▓▓▓▓▓▀▄ ▄▀▓▓▓▓▓▓▓▓▀▄ ▒▓▓▓▒       
█░░░▒▀▀█░░░█ █░░░▒▀▀█░░░█ █░░░▒▀▀█░░░█ █░░░▒▀▀█░░░█      █░░░▒▀▀█░░░█ █░░░▒▀▀█░░░█ █░░░░       
▓▒▒▒█▄▄▄▄▄   ▓▒▒▒█  █▒▒▒▓ ▓▒▒▒█▄▄█▒▒▒▓ ▓▒▒▒█  █▒▒▒▓      ▓▒▒▒█  █▒▒▒▓ ▓▒▒▒█▄▄█▒▒▒▓ ▓▒▒▒█       
▀▀▓▓▓▓▓▓▓▓▄▄ ▒▓▓▓█        ▒▓▓▓▓▓▓▓▓▓▓▒ ▒▓▓▓█  █▓▓▓▒      ▒▓▓▓█  █▓▓▓▒ ▒▓▓▓▓▓▓▓▓▓▓▒ ▒▓▓▓█       
  ▀▀▀▀▀█▓▓▓░ ░▓▓▓█  █▓▓▓░ ░▓▓▓█▀▀█▓▓▓░ ░▓▓▓█  █▓▓▓░      ░▓▓▓█  █▓▓▓░ ░▓▓▓█▀▀█▓▓▓░ ░▓▓▓█  █▓▓▓░
▒▒▒▒█▄▄█▒▒▒▒ ▒▒▒▒█▄▄█▒▒▒▒ ▒▒▒▒█  █▒▒▒▒ ▒▒▒▒█  █▒▒▒▒      ▒▒▒▒█  █▒▒▒▒ ▒▒▒▒█  █▒▒▒▒ ▒▒▒▒█▄▄█▒▒▒▒
▓░░░░░░░░░▄▀ ▀▄░░░░░░░░▄▀ ▓░░░█  █░░░▓ ▓░░░█  █░░░▓      ▓░░░█  █░░░▓ ▓░░░█  █░░░▓ ▀▄░░░░░░░░▄▀
▀▀▀▀▀▀▀▀▀▀     ▀▀▀▀▀▀▀▀   ▀▀▀▀▀  ▀▀▀▀▀ ▀▀▀▀▀  ▀▀▀▀▀      ▀▀▀▀▀  ▀▀▀▀▀ ▀▀▀▀▀  ▀▀▀▀▀   ▀▀▀▀▀▀▀▀  

""" + WinColors.RESET)
    print(WinColors.DIM_GRAY + "-" * 70 + WinColors.RESET)
    print(
        WinColors.YELLOW + "[[+]] This is mainly on scan windows -- it also can scan NETWORK Device  " + WinColors.RESET)
    print()


def parse_build_number(os_string):
    if not os_string:
        return None, None, None

    match = re.search(r'(\d{4,5})', os_string)
    if not match:
        return None, None, None

    build = match.group(1)

    if build in BUILD_MAP:
        name, version = BUILD_MAP[build]
        return build, name, version

    build_int = int(build)
    for b_str, (name, version) in BUILD_MAP.items():
        if abs(int(b_str) - build_int) <= 100:
            return build, name, version

    return build, "Windows (Unknown Version)", "Unknown"


def smb_fingerprint(target, port=445, timeout=8):
    result = {
        "success": False,
        "target": target,
        "os": None,
        "build": None,
        "version": None,
        "hostname": None,
        "domain": None,
        "dialect": None,
        "signing": None,
        "error": None,
    }

    if not HAS_IMPACKET:
        result["error"] = "impacket not installed"
        return result

    try:
        conn = SMBConnection(
            remoteName=target,
            remoteHost=target,
            sess_port=port,
            timeout=timeout
        )

        try:
            conn.login("", "")
        except Exception:
            pass

        try:
            os_string = conn.getServerOS()
        except Exception:
            os_string = None

        try:
            result["hostname"] = conn.getServerName()
        except Exception:
            pass

        try:
            result["domain"] = conn.getServerDNSDomainName() or conn.getServerDomain()
        except Exception:
            pass

        try:
            dialect_map = {
                0x0202: "SMB 2.0.2",
                0x0210: "SMB 2.1",
                0x0300: "SMB 3.0",
                0x0302: "SMB 3.0.2",
                0x0311: "SMB 3.1.1",
            }
            dial = conn.getDialect()
            result["dialect"] = dialect_map.get(dial, f"Unknown ({hex(dial)})")
        except Exception:
            pass

        try:
            result["signing"] = "Required" if conn.isSigningRequired() else "Not Required"
        except Exception:
            pass

        conn.close()

        if os_string:
            build, os_name, version = parse_build_number(os_string)
            result["os"] = os_string
            result["build"] = build
            result["version"] = f"{os_name} {version}" if os_name else None
            result["success"] = True
        else:
            result["error"] = "No OS info returned"

    except Exception as e:
        result["error"] = f"{type(e).__name__}: {str(e)[:100]}"

    return result


def ttl_fingerprint(target, timeout=3):
    try:
        pkt = IP(dst=target) / ICMP()
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp and resp.haslayer(IP):
            ttl = resp[IP].ttl
            if ttl <= 32:
                return {"os": "Windows 95/98", "ttl": ttl, "confidence": 60}
            elif ttl <= 64:
                return {"os": "Linux -- macOS -- android", "ttl": ttl, "confidence": 70}
            elif ttl <= 128:
                return {"os": "Windows", "ttl": ttl, "confidence": 75}
            elif ttl <= 200:
                return {"os": "IRIX", "ttl": ttl, "confidence": 60}
            elif ttl <= 254:
                return {"os": "Solaris", "ttl": ttl, "confidence": 60}
            elif ttl <= 255:
                return {"os": "Cisco -- Router", "ttl": ttl, "confidence": 60}
    except Exception:
        pass
    return {"os": "Unknown", "ttl": None, "confidence": 0}


def tcp_options_fingerprint(target, port, timeout=3):
    try:
        sport = RandShort()
        pkt = IP(dst=target) / TCP(sport=sport, dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)

        if not resp or not resp.haslayer(TCP):
            return None

        flags = int(resp[TCP].flags)

        if flags == 0x14:
            return {"port": port, "closed": True}

        if flags != 0x12:
            return None

        options = resp[TCP].options
        option_names = []
        for name, value in options:
            option_names.append(name)

        window = resp[TCP].window
        ttl = resp[IP].ttl

        try:
            rst = IP(dst=target) / TCP(sport=sport, dport=port,
                                       flags="R", seq=resp[TCP].ack)
            sr1(rst, timeout=1, verbose=0)
        except Exception:
            pass

        return {
            "port": port,
            "options": tuple(option_names),
            "window": window,
            "ttl": ttl,
            "closed": False,
        }
    except Exception:
        return None


def match_os_signature(signature):
    if signature in OS_SIGNATURES:
        return OS_SIGNATURES[signature], 95

    best_match = None
    best_score = 0

    for sig, os_name in OS_SIGNATURES.items():
        if len(sig) != len(signature):
            continue
        matches = sum(1 for a, b in zip(sig, signature) if a == b)
        score = (matches / len(sig)) * 100
        if score > best_score:
            best_score = score
            best_match = os_name

    if best_score >= 70:
        return best_match, int(best_score)
    return "Unknown", 0


def get_local_network():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        parts = local_ip.split(".")
        network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return local_ip, network
    except Exception:
        return None, None


def arp_scan(network):
    devices = []
    try:
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=3, verbose=0)[0]

        for sent, received in result:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
            })

        return devices
    except Exception:
        return []


def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        return "Unknown"


def get_vendor(mac):
    oui_map = {
        "00:50:56": "VMware",
        "00:0C:29": "VMware",
        "00:1C:42": "Parallels",
        "08:00:27": "VirtualBox",
        "52:54:00": "QEMU/KVM",
        "00:15:5D": "Hyper-V",
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
        "AC:84:C6": "TP-Link",
        "50:C7:BF": "TP-Link",
        "60:32:B1": "TP-Link",
        "F4:F2:6D": "TP-Link",
        "00:1F:E1": "Cisco",
        "00:24:97": "Cisco",
        "00:26:0B": "Cisco",
        "A4:5E:60": "Samsung",
        "3C:5A:B4": "Samsung",
        "8C:77:12": "Samsung",
        "F4:0F:24": "Intel",
        "E4:A4:71": "Intel",
        "F8:63:3F": "Intel",
        "00:1A:2B": "Apple",
        "00:1B:63": "Apple",
        "00:1E:C2": "Apple",
        "00:23:DF": "Apple",
        "3C:07:54": "Apple",
        "F0:18:98": "Apple",
    }

    mac_upper = mac.upper().replace("-", ":")
    prefix = mac_upper[:8]

    return oui_map.get(prefix, "Unknown")


def guess_device_type(ip, mac, hostname):
    mac_upper = mac.upper()
    hostname_lower = hostname.lower()

    if any(x in mac_upper for x in ["00:50:56", "00:0C:29", "08:00:27", "52:54:00", "00:15:5D"]):
        return "Virtual Machine"

    if any(x in mac_upper for x in ["B8:27:EB", "DC:A6:32", "E4:5F:01"]):
        return "Raspberry Pi"

    if ip.endswith(".1") or ip.endswith(".254"):
        return "Router/Gateway"

    if "android" in hostname_lower or "phone" in hostname_lower:
        return "Phone (Android)"

    if "iphone" in hostname_lower or "ipad" in hostname_lower:
        return "Apple Device"

    if "desktop" in hostname_lower or "laptop" in hostname_lower or "pc" in hostname_lower:
        return "Windows PC"

    if "server" in hostname_lower:
        return "Server"

    return "Device"


def run_network_discovery():
    print_banner()

    local_ip, network = get_local_network()

    if not local_ip:
        print(WinColors.RED + "[!] Could not detect local network" + WinColors.RESET)
        input(WinColors.DIM_GRAY + "\n[Press Enter to return] " + WinColors.RESET)
        return

    print(f"  {WinColors.NEON_CYAN}[+] Your IP:       {local_ip}{WinColors.RESET}")
    print(f"  {WinColors.NEON_CYAN}[+] Your Network:  {network}{WinColors.RESET}")
    print()

    custom = input(WinColors.AQUA + "[?] Use this network? [Y/n/custom]: " + WinColors.RESET).strip().lower()

    if custom == "n":
        input(WinColors.DIM_GRAY + "\n[Press Enter to return] " + WinColors.RESET)
        return
    elif custom in ("custom", "c"):
        network = input(WinColors.AQUA + "[?] Enter network (e.g. 192.168.1.0/24): " + WinColors.RESET).strip()
        if not network:
            return

    print(f"\n{WinColors.GOLD}[*] Scanning network {network}...{WinColors.RESET}")
    print(f"{WinColors.DIM_GRAY}[*] Sending ARP requests...{WinColors.RESET}")

    devices = arp_scan(network)

    if not devices:
        print(f"\n{WinColors.YELLOW}[!] No devices found{WinColors.RESET}")
        print(f"{WinColors.DIM_GRAY}[*] Try running as Administrator{WinColors.RESET}")
        input(WinColors.DIM_GRAY + "\n[Press Enter to return] " + WinColors.RESET)
        return

    print(f"\n{WinColors.GREEN}[+] Found {len(devices)} devices:{WinColors.RESET}\n")
    print(f"{WinColors.GOLD}{'=' * 95}{WinColors.RESET}")
    print(f"  {WinColors.BOLD}{'IP Address':<18}{'MAC Address':<20}{'Vendor':<18}{'Type':<20}{WinColors.RESET}")
    print(f"{WinColors.GOLD}{'=' * 95}{WinColors.RESET}")

    enriched_devices = []

    for dev in devices:
        ip = dev["ip"]
        mac = dev["mac"]
        vendor = get_vendor(mac)
        hostname = get_hostname(ip)
        device_type = guess_device_type(ip, mac, hostname)

        dev["vendor"] = vendor
        dev["hostname"] = hostname
        dev["type"] = device_type
        enriched_devices.append(dev)

        print(f"  {WinColors.NEON_CYAN}{ip[:17]:<18}{WinColors.WHITE}{mac[:19]:<20}"
              f"{WinColors.DIM_GRAY}{vendor[:17]:<18}{WinColors.GREEN}{device_type[:19]:<20}{WinColors.RESET}")

    print(f"{WinColors.GOLD}{'=' * 95}{WinColors.RESET}")

    print(f"\n{WinColors.BOLD}  Detailed Info:{WinColors.RESET}")
    for dev in enriched_devices:
        print(f"\n  {WinColors.NEON_CYAN}* {dev['ip']}{WinColors.RESET}")
        print(f"    MAC:      {dev['mac']}")
        print(f"    Hostname: {dev['hostname']}")
        print(f"    Vendor:   {dev['vendor']}")
        print(f"    Type:     {dev['type']}")

    save = input(WinColors.AQUA + "\n[?] Save to file? [y/n]: " + WinColors.RESET).strip().lower()
    if save == "y":
        filename = f"network_scan_{int(time.time())}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write("=" * 95 + "\n")
            f.write("  NETWORK DISCOVERY REPORT\n")
            f.write("=" * 95 + "\n\n")
            f.write(f"Local IP:  {local_ip}\n")
            f.write(f"Network:   {network}\n")
            f.write(f"Devices:   {len(enriched_devices)}\n\n")
            f.write("-" * 95 + "\n")
            for dev in enriched_devices:
                f.write(f"  IP:       {dev['ip']}\n")
                f.write(f"  MAC:      {dev['mac']}\n")
                f.write(f"  Hostname: {dev['hostname']}\n")
                f.write(f"  Vendor:   {dev['vendor']}\n")
                f.write(f"  Type:     {dev['type']}\n")
                f.write("-" * 95 + "\n")
        print(WinColors.GREEN + f"[+] Saved: {filename}" + WinColors.RESET)

    input(WinColors.DIM_GRAY + "\n[Press Enter to return] " + WinColors.RESET)


def full_scan(target, timeout=3):
    scan_result = {
        "target": target,
        "ttl": None,
        "ttl_os": None,
        "open_ports": [],
        "smb": None,
    }

    print(f"\n{WinColors.GOLD}[*] Starting full scan for {target}...{WinColors.RESET}")
    print(f"{WinColors.DIM_GRAY}{'-' * 70}{WinColors.RESET}")

    print(f"{WinColors.DIM_GRAY}[*] Phase 1: TTL detection...{WinColors.RESET}")
    ttl_result = ttl_fingerprint(target)
    if ttl_result["ttl"]:
        scan_result["ttl"] = ttl_result["ttl"]
        scan_result["ttl_os"] = ttl_result["os"]
        print(f"    {WinColors.GREEN}[+] TTL: {ttl_result['ttl']} -> {ttl_result['os']}{WinColors.RESET}")
    else:
        print(f"    {WinColors.YELLOW}[!] No ICMP response{WinColors.RESET}")

    print(f"{WinColors.DIM_GRAY}[*] Phase 2: TCP port scan...{WinColors.RESET}")
    for port in COMMON_PORTS:
        fp = tcp_options_fingerprint(target, port)
        if not fp:
            continue
        if fp.get("closed"):
            continue

        os_name, conf = match_os_signature(fp["options"])
        scan_result["open_ports"].append({
            "port": port,
            "os": os_name,
            "options": fp["options"],
            "window": fp["window"],
        })

        if os_name != "Unknown":
            print(f"    {WinColors.GREEN}[+] Port {port:5} OPEN | {os_name} ({conf}%){WinColors.RESET}")
        else:
            print(f"    {WinColors.YELLOW}[+] Port {port:5} OPEN{WinColors.RESET}")

    print(f"{WinColors.DIM_GRAY}[*] Phase 3: SMB fingerprint (if 445 open)...{WinColors.RESET}")
    if 445 in [p["port"] for p in scan_result["open_ports"]]:
        smb_result = smb_fingerprint(target)
        scan_result["smb"] = smb_result
        if smb_result["success"]:
            print(f"    {WinColors.GREEN}[+] SMB: {smb_result['os']}{WinColors.RESET}")
            print(
                f"    {WinColors.NEON_CYAN}[+] Build: {smb_result['build']} | {smb_result['version']}{WinColors.RESET}")
        else:
            print(f"    {WinColors.YELLOW}[!] SMB failed: {smb_result['error']}{WinColors.RESET}")
    else:
        print(f"    {WinColors.DIM_GRAY}[*] Port 445 closed, skipping SMB{WinColors.RESET}")

    return scan_result


def print_full_result(result):
    print()
    print(f"{WinColors.GOLD}{'=' * 70}{WinColors.RESET}")
    print(f"{WinColors.BOLD}  FULL SCAN RESULT{WinColors.RESET}")
    print(f"{WinColors.GOLD}{'=' * 70}{WinColors.RESET}")

    print(f"  Target:      {result['target']}")
    print(f"  TTL:         {result['ttl']} ({result['ttl_os']})")
    print(f"  Open Ports:  {len(result['open_ports'])}")

    if result["open_ports"]:
        print(f"\n{WinColors.BOLD}  Open Ports:{WinColors.RESET}")
        for p in result["open_ports"]:
            print(f"    - Port {p['port']:5} | {p['os']:15} | Window: {p['window']}")

    if result["smb"] and result["smb"]["success"]:
        smb = result["smb"]
        print(f"\n{WinColors.BOLD}  SMB Info:{WinColors.RESET}")
        print(f"    OS:       {WinColors.NEON_CYAN}{smb['os']}{WinColors.RESET}")
        print(f"    Build:    {WinColors.GOLD}{smb['build']}{WinColors.RESET}")
        print(f"    Version:  {WinColors.NEON_CYAN}{smb['version']}{WinColors.RESET}")
        print(f"    Hostname: {smb['hostname']}")
        print(f"    Domain:   {smb['domain']}")
        print(f"    Dialect:  {smb['dialect']}")
        print(f"    Signing:  {smb['signing']}")

    print(f"{WinColors.GOLD}{'=' * 70}{WinColors.RESET}")


def save_report(result, filename=None):
    if not filename:
        safe_target = re.sub(r'[^a-zA-Z0-9._-]', '_', result["target"])
        filename = f"winscan_{safe_target}_{int(time.time())}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("  WINDOWS SCANNER - REPORT\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Target:      {result['target']}\n")
        f.write(f"TTL:         {result['ttl']} ({result['ttl_os']})\n")
        f.write(f"Open Ports:  {len(result['open_ports'])}\n\n")

        if result["open_ports"]:
            f.write("-" * 70 + "\n")
            f.write("OPEN PORTS\n")
            f.write("-" * 70 + "\n")
            for p in result["open_ports"]:
                f.write(f"  Port {p['port']:5} | {p['os']:15} | Window: {p['window']}\n")
            f.write("\n")

        if result["smb"] and result["smb"]["success"]:
            smb = result["smb"]
            f.write("-" * 70 + "\n")
            f.write("SMB INFORMATION\n")
            f.write("-" * 70 + "\n")
            f.write(f"  OS String:  {smb['os']}\n")
            f.write(f"  Build:      {smb['build']}\n")
            f.write(f"  Version:    {smb['version']}\n")
            f.write(f"  Hostname:   {smb['hostname']}\n")
            f.write(f"  Domain:     {smb['domain']}\n")
            f.write(f"  Dialect:    {smb['dialect']}\n")
            f.write(f"  Signing:    {smb['signing']}\n\n")

        f.write("=" * 70 + "\n")
        f.write("Report generated by WinScanner v0.3\n")
        f.write("=" * 70 + "\n")

    return filename


def run_smb_scan():
    print_banner()
    target = input(WinColors.AQUA + "[?] Enter target IP: " + WinColors.RESET).strip()
    if not target:
        return

    print(f"\n{WinColors.GOLD}[*] SMB Fingerprint for {target}...{WinColors.RESET}\n")
    result = smb_fingerprint(target)

    print(f"{WinColors.GOLD}{'=' * 60}{WinColors.RESET}")
    if result["success"]:
        print(f"  {WinColors.GREEN}[+] SUCCESS{WinColors.RESET}\n")
        print(f"  OS String:   {WinColors.NEON_CYAN}{result['os']}{WinColors.RESET}")
        print(f"  Build:       {WinColors.GOLD}{result['build']}{WinColors.RESET}")
        print(f"  Version:     {WinColors.NEON_CYAN}{result['version']}{WinColors.RESET}")
        print(f"  Hostname:    {WinColors.WHITE}{result['hostname']}{WinColors.RESET}")
        print(f"  Domain:      {WinColors.WHITE}{result['domain']}{WinColors.RESET}")
        print(f"  Dialect:     {WinColors.WHITE}{result['dialect']}{WinColors.RESET}")
        print(f"  Signing:     {WinColors.WHITE}{result['signing']}{WinColors.RESET}")
    else:
        print(f"  {WinColors.RED}[-] FAILED: {result['error']}{WinColors.RESET}")
    print(f"{WinColors.GOLD}{'=' * 60}{WinColors.RESET}")

    input(WinColors.DIM_GRAY + "\n[Press Enter to return] " + WinColors.RESET)


def run_tcp_fingerprint():
    print_banner()
    target = input(WinColors.AQUA + "[?] Enter target IP: " + WinColors.RESET).strip()
    if not target:
        return

    print(f"\n{WinColors.GOLD}[*] TCP Fingerprint for {target}...{WinColors.RESET}")

    ttl_result = ttl_fingerprint(target)
    if ttl_result["ttl"]:
        print(f"    {WinColors.GREEN}[+] TTL: {ttl_result['ttl']} -> {ttl_result['os']}{WinColors.RESET}")

    open_count = 0
    for port in COMMON_PORTS:
        fp = tcp_options_fingerprint(target, port)
        if not fp or fp.get("closed"):
            continue

        open_count += 1
        os_name, conf = match_os_signature(fp["options"])
        if os_name != "Unknown":
            print(f"    {WinColors.GREEN}[+] Port {port:5} OPEN | {os_name} ({conf}%){WinColors.RESET}")
            print(f"        {WinColors.DIM_GRAY}Options: {fp['options']}{WinColors.RESET}")
        else:
            print(f"    {WinColors.YELLOW}[+] Port {port:5} OPEN{WinColors.RESET}")

    print(f"\n{WinColors.GOLD}[*] Found {open_count} open ports{WinColors.RESET}")
    input(WinColors.DIM_GRAY + "\n[Press Enter to return] " + WinColors.RESET)


def run_full_scan():
    print_banner()
    target = input(WinColors.AQUA + "[?] Enter target IP: " + WinColors.RESET).strip()
    if not target:
        return

    result = full_scan(target)
    print_full_result(result)

    save_choice = input(WinColors.AQUA + "\n[?] Save report? [y/n]: " + WinColors.RESET).strip().lower()
    if save_choice == "y":
        filename = save_report(result)
        print(WinColors.GREEN + f"[+] Saved: {filename}" + WinColors.RESET)

    input(WinColors.DIM_GRAY + "\n[Press Enter to return] " + WinColors.RESET)


def run_batch_scan():
    print_banner()
    print(WinColors.AQUA + "[*] Paste IPs (one per line, empty line to start):" + WinColors.RESET)
    targets = []
    while True:
        line = input().strip()
        if not line:
            break
        targets.append(line)

    if not targets:
        return

    print(f"\n{WinColors.GOLD}[*] Scanning {len(targets)} targets...{WinColors.RESET}")

    all_results = []
    for target in targets:
        result = full_scan(target)
        all_results.append(result)
        print_full_result(result)

    save_choice = input(WinColors.AQUA + "\n[?] Save all reports? [y/n]: " + WinColors.RESET).strip().lower()
    if save_choice == "y":
        for result in all_results:
            filename = save_report(result)
            print(WinColors.GREEN + f"[+] Saved: {filename}" + WinColors.RESET)

    input(WinColors.DIM_GRAY + "\n[Press Enter to return] " + WinColors.RESET)


def main_menu():
    while True:
        print_banner()
        print(
            f"  {WinColors.GREEN}1){WinColors.RESET} SMB Fingerprint    {WinColors.DIM_GRAY}(Build Number){WinColors.RESET}")
        print(
            f"  {WinColors.GREEN}2){WinColors.RESET} TCP Fingerprint    {WinColors.DIM_GRAY}(TTL + Options){WinColors.RESET}")
        print(
            f"  {WinColors.GREEN}3){WinColors.RESET} Full Scan          {WinColors.DIM_GRAY}(SMB + TCP + Report){WinColors.RESET}")
        print(
            f"  {WinColors.GREEN}4){WinColors.RESET} Batch Scan         {WinColors.DIM_GRAY}(multiple IPs){WinColors.RESET}")
        print(
            f"  {WinColors.GREEN}5){WinColors.RESET} Network Discovery  {WinColors.DIM_GRAY}(find all devices){WinColors.RESET}")
        print(f"  {WinColors.GREEN}0){WinColors.RESET} Exit")
        print()

        choice = input(WinColors.AQUA + "[?] Choose (0-5): " + WinColors.RESET).strip()

        if choice == "1":
            run_smb_scan()
        elif choice == "2":
            run_tcp_fingerprint()
        elif choice == "3":
            run_full_scan()
        elif choice == "4":
            run_batch_scan()
        elif choice == "5":
            run_network_discovery()
        elif choice == "0":
            print(WinColors.YELLOW + "[!] Bye" + WinColors.RESET)
            sys.exit(0)
        else:
            print(WinColors.RED + "[!] Invalid option" + WinColors.RESET)
            time.sleep(1)


if __name__ == "__main__":
    main_menu()