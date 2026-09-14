<p align="center">
  <img src="https://raw.githubusercontent.com/Denilson-franca/waspy/main/assets/waspy-logo.jpg" alt="Waspy Logo" width="200"/>
</p>

<p align="center">
  <a href="https://github.com/Denilson-franca/waspy/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"/>
  </a>
  <a href="https://www.python.org/downloads/">
    <img src="https://img.shields.io/badge/Python-3.10%2B-blue.svg" alt="Python 3.10+"/>
  </p>

<h1 align="center">Waspy</h1>

<p align="center"><strong>Automated OWASP Top 10 Web Application Security Pentest Scanner</strong></p>

<p align="center">
Self-hostable security scanner for mapping OWASP Top 10 (2021/2023) vulnerabilities in web applications. Built for pentesters, bug bounty hunters, security researchers, and authorized auditors who need reconnaissance, passive CVE detection, active injection testing, and professional reporting in one workflow.
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/Denilson-franca/waspy/main/assets/terminal-demo.jpg" alt="Waspy Terminal Demo" width="800"/>
</p>

---

## 🚀 Quick Start

```bash
# Install via pip (recommended)
pip install waspy

# Or clone and run locally
git clone https://github.com/Denilson-franca/waspy.git
cd waspy
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Quick scan - passive CVE detection (WAF-safe, ~80s)
python3 modules/scan_quick.py -u https://target.com --stealth --user-agent "Waspy/1.0" --no-nuclei

# Full OWASP Top 10 scan (~5-10 min stealth)
python3 modules/scan_full.py -u https://target.com --stealth --user-agent "Waspy/1.0" --skip-sqlmap

# Endpoints & design flaws scan
python3 modules/scan_endpoints.py -u https://target.com --stealth --user-agent "Waspy/1.0"

# Interactive visual interface
bash waspy.sh
```

### Docker (Self-Hosted Stack)
```bash
docker compose up -d
# Access web UI at http://localhost:8080
```

---

## 🎯 What It Does

| Capability | Description |
|------------|-------------|
| **Passive Reconnaissance** | Subdomain enumeration (crt.sh, subfinder), port scanning (nmap), technology fingerprinting (whatweb), DNS enumeration, WHOIS |
| **WAF-Aware Stealth Mode** | Rate limiting (10-50 req/s), custom User-Agent, retries on 403/429, infinite timeout for slow scans |
| **Passive CVE Detection** | 3-layer heuristic: Nuclei tech templates + WPScan/curl fallback + HTML raw regex — **zero exploit payloads**, works behind Cloudflare/WAF |
| **WordPress Intelligence** | Plugin enumeration with versions, user enumeration, 25+ plugin CVE database (Forminator, Elementor, WooCommerce, Contact Form 7, etc.) |
| **Active OWASP Testing** | SQLi (sqlmap), XSS/LFI/RCE/SSRF/IDOR payloads, security headers audit, SSL/TLS analysis (testssl.sh), Nikto misconfig checks |
| **Endpoint Discovery** | Directory fuzzing (ffuf/gobuster), robots.txt/sitemap.xml, WP REST API, GraphQL/OpenAPI, sensitive files (.env, .git, backups), debug endpoints (actuator, swagger, h2-console) |
| **IDOR Testing** | Automated numeric ID manipulation on discovered endpoints |
| **Professional Reporting** | ABNT-formatted Markdown, styled HTML, structured JSON with deduplication, risk scoring, remediation guidance |

---

## 🔄 Pipeline

| Stage | Action |
|-------|--------|
| 1 | **Target Validation** — URL normalization, connectivity check |
| 2 | **Reconnaissance** — Subdomains, ports, technologies, DNS, WHOIS, security headers |
| 3 | **WAF Detection** — Payload reflection test, Cloudflare/Akamai/AWS WAF identification |
| 4 | **Directory Fuzzing** — ffuf/gobuster with customizable wordlists |
| 5 | **WordPress Enum** — WPScan (plugins, users, versions) + passive Nuclei tech templates |
| 6 | **Passive CVE Correlation** | Cross-reference detected versions vs local CVE database (25+ plugins) |
| 7 | **HTML Raw Heuristic** | Regex search for plugin paths in raw HTML (WAF-proof fallback) |
| 8 | **Active Injection Tests** | SQLMap (SQLi), custom payloads (XSS, LFI, RCE, SSRF, IDOR) |
| 9 | **Security Configuration** | Headers audit, SSL/TLS (testssl.sh), Nikto misconfig scan |
| 10 | **Endpoint Analysis** | API discovery, sensitive files, debug endpoints, IDOR testing |
| 11 | **Report Generation** | ABNT Markdown, HTML, JSON with risk scoring and remediation |

---

## 🛡️ Vulnerability Coverage (OWASP Top 10 2021/2023)

| ID | Category | Waspy Coverage |
|----|----------|----------------|
| **A01** | Broken Access Control | IDOR testing, user enumeration, path traversal, method tampering |
| **A02** | Cryptographic Failures | SSL/TLS analysis, certificate validation, HSTS/HPKP headers |
| **A03** | Injection | SQLMap (SQLi), XSS payloads, LFI/RFI/RCE/SSRF/NoSQL/LDAP/Template injection |
| **A04** | Insecure Design | Debug endpoints, API docs exposure (Swagger/OpenAPI/GraphQL), sensitive paths in robots.txt |
| **A05** | Security Misconfiguration | Nikto scan, security headers audit (CSP, HSTS, X-Frame-Options), server tokens, CORS |
| **A06** | Vulnerable/Outdated Components | **Passive CVE detection** — WordPress core, 25+ plugins (Forminator, Elementor, WooCommerce, CF7, WPForms, Slider Revolution, etc.), Nuclei CVE templates |
| **A07** | Auth Failures | WP user enum, login form detection, session cookie analysis, JWT inspection, brute-force paths |
| **A08** | Software/Data Integrity | JWT signature validation, insecure deserialization, CI/CD config exposure |
| **A09** | Logging/Monitoring Failures | Error page exposure, verbose errors, missing security headers |
| **A10** | SSRF | Internal IP payloads, cloud metadata (169.254.169.254), open redirect chains |

---

## 🔍 Passive CVE Database (Built-in)

| Plugin | CVEs Detected | Max Version |
|--------|--------------|-------------|
| **Forminator** | CVE-2026-18328 (XSS), CVE-2026-19221 (RCE) | ≤ 1.36.0 |
| **AYS Popup Box** | CVE-2026-1165 (CSRF), CVE-2026-57631 (SQLi) | ≤ 5.3.0 |
| **Elementor/Pro** | CVE-2024-11456, CVE-2024-3493, CVE-2023-32243 | ≤ 3.24.0 |
| **WooCommerce** | CVE-2024-37085 (SQLi), CVE-2023-34000 (RCE) | ≤ 8.8.0 |
| **Contact Form 7** | CVE-2024-25112 (RCE), CVE-2023-49070 (XSS) | ≤ 5.9.0 |
| **WPForms** | CVE-2024-9012 (RCE) | ≤ 1.8.5 |
| **Slider Revolution** | CVE-2024-1111 (RCE) | ≤ 6.6.0 |
| **WP File Manager** | CVE-2020-25213 (RCE) | ≤ 6.9 |
| **...and 15+ more** | See `modules/scan_full.py` | — |

> **Extendable**: Add custom plugins to `WORDPRESS_PLUGIN_CVE_DB` in `scan_full.py` and `scan_quick.py`

---

## 📋 CLI Reference

### `scan_quick.py` — Fast CVE/Recon Scan
```bash
python3 modules/scan_quick.py -u https://target.com [OPTIONS]

Options:
  -u, --url           Target URL (required)
  -o, --output        Output directory
  -v, --verbose       Verbose logging
  --stealth           Enable stealth mode (rate limit, retries, custom UA)
  --user-agent        Custom User-Agent string
  --rate-limit        Requests/second in stealth (default: 10)
  --threads           Concurrent threads (default: 5)
  --no-nuclei         Skip Nuclei CVE scan
  --no-wpscan         Skip WPScan
  --no-whatweb        Skip WhatWeb
  --no-passive        Skip passive WordPress enumeration
```

### `scan_full.py` — Full OWASP Top 10 Scan
```bash
python3 modules/scan_full.py -u https://target.com [OPTIONS]

Options:
  -u, --url           Target URL (required)
  -o, --output        Output directory
  -v, --verbose       Verbose logging
  --stealth           Enable stealth mode
  --user-agent        Custom User-Agent
  --threads           Threads (default: 50)
  --wordlist          Custom wordlist path
  --skip-nuclei       Skip Nuclei scanning
  --skip-sqlmap       Skip SQLMap
  --skip-wpscan       Skip WPScan
  --skip-ffuf         Skip directory fuzzing
```

### `scan_endpoints.py` — Endpoints & Design Flaws
```bash
python3 modules/scan_endpoints.py -u https://target.com [OPTIONS]

Options:
  -u, --url           Target URL (required)
  -o, --output        Output directory
  -v, --verbose       Verbose logging
  --stealth           Enable stealth mode
  --user-agent        Custom User-Agent
  --threads           Threads (default: 50)
  --wordlist          Custom wordlist
```

### `wasp.py` / `ghost_gear.py` — Unified Entry Points
```bash
python3 wasp.py -u https://target.com --stealth --html --json
```

---

## 🐳 Self-Hosting with Docker Compose

```yaml
# docker-compose.yml (included)
version: '3.8'
services:
  waspy:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./relatorios:/app/relatorios
      - ./wordlists:/app/wordlists
    environment:
      - TARGET_URL=${TARGET_URL}
      - STEALTH_MODE=true
      - USER_AGENT=Waspy/1.0
```

```bash
# Quick start
TARGET_URL=https://target.com docker compose up --build

# Or run interactively
docker compose run --rm waspy bash waspy.sh
```

---

## 📊 Report Output

Reports saved to `./relatorios/<domain>_<type>_<timestamp>/`:

| Format | Description |
|--------|-------------|
| **`.md`** | ABNT-formatted Markdown (capa, sumário, metodologia, vulnerabilidades A01-A10, matriz de risco, recomendações, comandos, referências, aviso legal) |
| **`.html`** | Styled HTML with severity colors, collapsible findings, risk score dashboard |
| **`.json`** | Structured data for SIEM/SOAR integration, CI/CD parsing |

### Finding ID Prefixes
| Prefix | Source |
|--------|--------|
| `HEU-` | Heuristic (passive CVE database cross-reference) |
| `NUC-` | Nuclei technology template match |
| `CVE-` | Nuclei CVE-focused template (tags=cve) |
| `WPSCAN-` | WPScan enumeration (users, plugins) |
| `END-` | Endpoint scan (fuzzing, API, files, IDOR) |
| `A01-A10-` | Active OWASP injection/config tests |

---

## 🔧 Configuration

### Environment Variables
```bash
export HTTP_PROXY=http://127.0.0.1:8080   # Burp Suite proxy
export HTTPS_PROXY=http://127.0.0.1:8080
export NUCLEI_TEMPLATES=/path/to/templates # Custom Nuclei templates
```

### Wordlists
- Default: `wordlists/dirs.txt` (~5000 entries)
- Custom: `--wordlist /path/to/custom.txt`

### Nuclei Templates
- Uses ProjectDiscovery public templates
- Custom: `-t /path/to/custom/` in scan modules

---

## 📚 Links

| Resource | Link |
|----------|------|
| **Documentation** | [MANUAL.md](./MANUAL.md) |
| **Architecture** | [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) |
| **Self-Hosting Guide** | [docs/SELF_HOSTING.md](./docs/SELF_HOSTING.md) |
| **Contributing** | [CONTRIBUTING.md](./CONTRIBUTING.md) |
| **Security Policy** | [SECURITY.md](./SECURITY.md) |
| **Usage Policy** | [USAGE_POLICY.md](./USAGE_POLICY.md) |
| **PyPI Package** | [pypi.org/project/waspy](https://pypi.org/project/waspy) |
| **GitHub** | [github.com/Denilson-franca/waspy](https://github.com/Denilson-franca/waspy) |
| **Issues** | [github.com/Denilson-franca/waspy/issues](https://github.com/Denilson-franca/waspy/issues) |

---

## ⚖️ License

**MIT License** — See [LICENSE](./LICENSE) for details.

> **⚠️ AUTHORIZED USE ONLY**
>
> Waspy is designed for **authorized security assessments**, **bug bounty programs**, **internal audits**, and **educational purposes**. Unauthorized scanning of systems you do not own or have explicit written permission to test is **illegal** and may result in civil and/or criminal penalties.
>
> The authors and contributors of Waspy **are not responsible** for any misuse or damage caused by this tool. By using Waspy, you agree to comply with all applicable laws and regulations.

---

## 🤝 Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup, code standards, and pull request process.

---

<p align="center">
  <strong>Built with ❤️ for the security community by GearSec Security Team</strong><br/>
  <a href="https://github.com/Denilson-franca">GitHub</a> •
  <a href="mailto:gearsec_denilson@proton.me">Email</a> •
  <a href="https://linkedin.com/in/denilson-franca">LinkedIn</a>
</p>
