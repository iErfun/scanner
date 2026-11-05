<div align="center">

# 🩸 XOMLSX SCANNER 🩸

### Offensive Security Toolkit

**A powerful, modular framework for network reconnaissance, vulnerability assessment, and open-source intelligence.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Educational-red)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)]()
[![Status](https://img.shields.io/badge/Status-Active-success)]()

<br>

> **⚠️ AUTHORIZED USE ONLY**  
> This tool is designed exclusively for **authorized security testing**, **penetration testing engagements**, and **educational research**.  
> Unauthorized scanning or exploitation of systems is **illegal**. The developers accept **no responsibility** for misuse.

</div>

---

## ✨ Overview

**XOMLSX** is a comprehensive offensive security toolkit written in pure Python. It combines advanced network scanning techniques, attack modules, and OSINT capabilities into a single interactive interface.

Built for security researchers, red teamers, and ethical hackers who need a fast, flexible, and feature-rich toolkit without relying on heavy external frameworks.

---

## 🧩 Core Modules

<table>
<tr>
<td width="33%" valign="top">

### 🔍 Scanner
- TCP Connect Scan
- SYN / Stealth Scan
- UDP Scan
- FIN Scan
- Fragment Scan
- Decoy Scan
- Tor-routed Scanning
- OS Detection (TTL)
- Banner Grabbing
- Ping Sweep
- Subdomain Discovery
- Multi-target Support
- HTML & Text Reports

</td>
<td width="33%" valign="top">

### ⚔️ Attack
- **Bruteforce**
  - HTTP Basic Auth
  - SSH (Paramiko)
  - FTP
  - Form-based Login
- **Wordlist Generator**
- **XSS Scanner**
  - Payload mutation engine
  - WAF bypass techniques
  - Encoding variations
  - Event handler payloads
  - Playwright verification

</td>
<td width="33%" valign="top">

### 🕵️ OSINT
- Username Finder  
  (multi-platform)
- IP Intelligence
- Metadata Extractor
- Google Dork Assistant
- Domain Intelligence
- Email Intelligence
- Web Crawler

</td>
</tr>
</table>

---

## 📦 Project Structure

```text
Scanner/
├── runner_code.py          # Main interactive launcher
├── scanner.py              # Advanced network scanner engine
├── scan_win.py             # Windows / SMB focused scanning
├── brute.py                # Credential bruteforce module
├── xss.py                  # XSS detection & verification (UI + legacy + advanced)
├── xsspor/                 # Modular advanced XSS engine (3-layer detection)
│   ├── __init__.py
│   ├── engine.py           # DetectionEngine, ScanConfig, Finding
│   ├── payloads.py         # Categorized payload database
│   ├── context.py          # Reflection context detection
│   ├── browser.py          # Playwright verification
│   ├── proxy.py            # ProxyPool rotation
│   ├── crawler.py          # Same-origin param discovery
│   └── chain.py            # Crypto utilities (AES-GCM)
├── word_list.py            # Custom wordlist generator
├── proxy_tester.py         # Proxy validation utility
├── email_checker.py        # Email validation & checking
├── username_finder.py      # Standalone username OSINT
│
├── osint/
│   ├── username_finder.py
│   ├── ip_intel.py
│   └── metadata.py
│
└── ...
```

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/iErfun/scanner.git
cd scanner
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

**Required packages:**

| Package       | Purpose                          |
|---------------|----------------------------------|
| `requests`    | HTTP requests                    |
| `scapy`       | Packet crafting & raw sockets    |
| `PySocks`     | SOCKS proxy / Tor support        |
| `faker`       | Realistic User-Agent generation  |
| `paramiko`    | SSH bruteforce                   |
| `playwright`  | Browser-based XSS verification   |
| `cryptography`| AES-GCM / key derivation (chain) |

```bash
# Optional but recommended
playwright install chromium
```

> **Note:** Root / Administrator privileges are required for raw socket scans (SYN, FIN, Fragment, Decoy).

---

## 💻 Usage

Launch the interactive menu:

```bash
python runner_code.py
```

```text
MAIN MENU
┌──────────────────────────────────────────────────────────┐
│  1) Scanner                                              │
│  2) Attack                                               │
│  3) OSINT                                                │
│  0) Exit                                                 │
└──────────────────────────────────────────────────────────┘
```

### Direct module execution

```bash
# Network Scanner
python scanner.py

# XSS Scanner
python xss.py

# Bruteforce
python brute.py

# Username OSINT
python -m osint.username_finder
```

---

## ⚙️ Key Features in Detail

### Network Scanner
- Configurable thread count and delay (from stealthy to aggressive)
- Automatic service detection via common port mapping
- OS fingerprinting based on TTL values
- Decoy scanning with multiple spoofed source IPs
- Full Tor integration with circuit rotation support
- Export results as clean text or professional HTML reports

### XSS Engine

Menu options 7–9 add **Chain** features (Nested Chain with per-layer passwords, self-test, manual GET). Requires `cryptography`.

- Multiple payload categories: Basic, WAF Bypass, Event Handlers, Encoding, Special
- Intelligent payload mutation (case, HTML entities, percent-encoding, whitespace)
- Optional Playwright-based confirmation of successful XSS

### Bruteforce
- Multi-protocol support (HTTP, SSH, FTP)
- Threaded execution with rate control
- Custom wordlist support

---

## ⚠️ Important Notes

| Topic | Details |
|-------|---------|
| **Tor Limitation** | Raw socket scans (SYN / UDP / FIN / Fragment / Decoy) **bypass Tor**. Only TCP-connect scans and HTTP requests are routed through Tor. |
| **Privileges** | SYN and other stealth scans require root/admin privileges. |
| **Dependencies** | Missing optional packages are detected gracefully and reported to the user. |
| **Output** | Scan results are saved with timestamps for easy tracking. |

---

## 🛡️ Legal Disclaimer

```text
This software is provided for educational and authorized security testing purposes only.

By using this tool, you agree that:
• You will only target systems you own or have explicit written permission to test.
• You understand that unauthorized access to computer systems is a criminal offense.
• The authors and contributors shall not be held liable for any damages or legal consequences
  resulting from the use or misuse of this software.
```

**Use responsibly. Always obtain proper authorization.**

---

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

---

## 📄 License

This project is released for **educational and authorized research purposes**.  
See the disclaimer above for usage terms.

https://github.com/lololololmx083-wq

https://github.com/iErfun

## 

<div align="center">

<br>

</div>


---

## ⚡ Modern Attack Modules (NEW)

Added in `attacks_modern.py` and wired into **Web Scanning Tools**:

| # | Module | What it probes |
|---|--------|----------------|
| 1 | SSRF + Cloud IMDS | 127.0.0.1 variants, AWS/GCP/Azure metadata, decimal/hex IP bypasses |
| 2 | SSTI | Jinja2, Twig, Freemarker, Spring EL, Thymeleaf, ERB math + object probes |
| 3 | Log4Shell / JNDI | Classic + obfuscated `${jndi:ldap/rmi/dns}` emitters (pair with your OAST) |
| 4 | Advanced Traversal | Double-encoding, wrappers (`php://filter`, `expect://`, `data://`), win.ini |
| 5 | Open Redirect | `//`, `/\`, null-byte, fragment tricks |
| 6 | CORS | Origin reflection + `ACAO=*` with credentials |
| 7 | Host Header | Host / X-Forwarded-Host / X-Host injection |
| 8 | GraphQL | Introspection on common endpoints |
| 9 | JWT | Detect tokens, flag `alg=none`, craft none-candidate |
| 10 | Secrets / Actuator | Spring Actuator, `.env`, `.git/HEAD`, heapdump, Next.js paths |
| 11 | Request Smuggling | Light CL.TE / TE.CL desync signals |
| 12 | **Full Modern Scan** | Runs all of the above, optional report save |

**Menu path:** Main → `8) Web Scanning Tools` → `5) Modern Attack Modules` or `6) Full Modern Web Scan`

```bash
python scanner.py
# or standalone:
python attacks_modern.py
```


---

## 🆕 Expanded Modules (hardened pass)

| Module | Path | Menu |
|--------|------|------|
| Modern Attacks | `attacks_modern.py` | Attack → 4 / Web Tools → 5–6 |
| Injection Pack | `injection_pack.py` | Attack → 5 (CMDi / XXE / CRLF) |
| Header / Tech Audit | `header_audit.py` | Attack → 6 |
| JS Secret Hunter | `js_secrets.py` | Attack → 7 |
| Subdomain Enum | `subdomain_enum.py` | OSINT → 5 (crt.sh + DNS brute) |
| DNS Tools | `dns_tools.py` | OSINT → 6 (records, AXFR, takeover hints) |
| Shared core | `core_utils.py` | internal |

Build backend: **PyInstaller** (see `.github/workflows/build.yml`).
