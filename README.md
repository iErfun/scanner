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
├── xss.py                  # XSS detection & verification
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

https://github.com/iErfun

https://github.com/lololololmx083-wq


<div align="center">

<br>

</div>
