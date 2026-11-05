# XOMLSX Scanner Enhanced

Modular recon / attack / OSINT toolkit. Run from project root:

```bash
pip install -r requirements.txt
python3 runner_code.py
```

## Layout

| Path | Role |
|------|------|
| `runner_code.py` | Main menu / launcher |
| `scanner.py` | Core network scanner |
| `core_utils.py` | Shared session, colors, reports |
| `subdomain_enum.py` | crt.sh + ThreatCrowd + HackerTarget + DNS brute |
| `dns_tools.py` | Records / AXFR / reverse |
| `header_audit.py` | Security headers + leak headers |
| `injection_pack.py` | SQLi / XSS / SSTI / LFI probes |
| `js_secrets.py` | API key / token hunter in HTML+JS |
| `port_scan.py` | Fast TCP port scanner |
| `dir_brute.py` | Directory / path brute |
| `tech_detect.py` | Lightweight tech fingerprint |
| `attacks_modern.py` | SSRF / SSTI / Log4j / JWT suite |
| `brute.py` / `word_list.py` / `xss.py` | Attack modules |
| `osint/` | Username / IP intel / metadata |
| `reports/` | Auto-saved JSON/TXT outputs |

## Notes

- All modular tools expose `run()` and are launched via `_run_module` with forced `sys.path`.
- Reports land in `reports/`.
- Optional: `dnspython` for full DNS/AXFR; `scapy` for advanced scanner features.
