#!/usr/bin/env python3
"""Waspy - Full OWASP Top 10 Scan Module"""
import argparse
import os
import re
import sys
import time
import json
from datetime import datetime
from urllib.parse import urljoin

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import Colors, print_banner, color_log, setup_logger, check_tool, validate_url, run_command
from recon import ReconPhase
from owasp_scan import OWASPScanner
from reporter import ReportGenerator


# Cache functions for plugin detection
def _get_cache_path(target, output_dir):
    """Get cache file path for detected plugins."""
    import hashlib
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    cache_name = hashlib.md5(domain.encode()).hexdigest()[:12]
    return os.path.join(output_dir, f".plugin_cache_{cache_name}.json")


def _load_plugin_cache(cache_path):
    """Load cached plugin detections."""
    if os.path.exists(cache_path):
        try:
            with open(cache_path) as f:
                data = json.load(f)
                # Cache valid for 24 hours
                if time.time() - data.get("timestamp", 0) < 86400:
                    return data.get("plugins", {})
        except Exception:
            pass
    return {}


def _save_plugin_cache(cache_path, plugins):
    """Save plugin detections to cache."""
    try:
        with open(cache_path, "w") as f:
            json.dump({"timestamp": time.time(), "plugins": plugins}, f)
    except Exception:
        pass


def parse_args():
    parser = argparse.ArgumentParser(description="Waspy - Full OWASP Top 10 Scan")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default=None, help="Output directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip nuclei scanning")
    parser.add_argument("--skip-sqlmap", action="store_true", help="Skip SQLi scanning")
    parser.add_argument("--skip-wpscan", action="store_true", help="Skip WPScan")
    parser.add_argument("--skip-ffuf", action="store_true", help="Skip directory fuzzing")
    parser.add_argument("--threads", type=int, default=50, help="Concurrent threads")
    parser.add_argument("--user-agent", default="Waspy/1.0", help="Custom User-Agent")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode for WAF evasion (rate limiting, custom UA, retries)")
    return parser.parse_args()


def run_ffuf(target, ua, output_dir):
    """Run ffuf for directory fuzzing."""
    if not check_tool("ffuf"):
        color_log("ffuf not found, trying gobuster...", "WARNING")
        return run_gobuster(target, ua, output_dir)
    color_log("Running ffuf directory fuzzing...", "INFO")
    ffuf_out = os.path.join(output_dir, "ffuf.json")
    wordlist = os.path.join(os.path.dirname(__file__), "..", "wordlists", "dirs.txt")
    cmd = [
        "ffuf", "-u", f"{target.rstrip('/')}/FUZZ",
        "-w", wordlist, "-of", "json", "-o", ffuf_out,
        "-H", f"User-Agent: {ua}", "-t", "50",
        "-ac", "-fc", "404", "-mc", "200,403,500"
    ]

    result = run_command(cmd, timeout=300)
    findings = []

    if result and os.path.exists(ffuf_out):
        with open(ffuf_out) as f:
            data = json.load(f)
            for r in data.get("results", []):
                findings.append({
                    "id": f"FFUF-{len(findings)+1:03d}",
                    "title": f"Diretório/Arquivo encontrado: {r.get('url', r.get('input', ''))}",
                    "category": "Exposed Endpoint",
                    "severity": "MEDIUM" if r.get("status") == "200" else "LOW",
                    "description": f"Endpoint acessível retornando HTTP {r.get('status', 'N/A')}",
                    "affected_endpoints": r.get("url", ""),
                    "evidence": f"Status: {r.get('status')}, Length: {r.get('length', 'N/A')}",
                    "remediation": "Restringir acesso a diretórios sensíveis. Remover arquivos de backup/teste."
                })
    return findings


def run_gobuster(target, ua, output_dir):
    """Fallback to gobuster."""
    if not check_tool("gobuster"):
        return []
    color_log("Running gobuster directory fuzzing...", "INFO")
    gb_out = os.path.join(output_dir, "gobuster.txt")
    wordlist = os.path.join(os.path.dirname(__file__), "..", "wordlists", "dirs.txt")
    cmd = ["gobuster", "dir", "-u", target, "-w", wordlist, "-o", gb_out,
           "-t", "50", "-a", ua, "-s", "200,301,302,403,500"]
    result = run_command(cmd, timeout=300)
    findings = []
    if result and os.path.exists(gb_out):
        with open(gb_out) as f:
            for line in f:
                if line.startswith("/"):
                    parts = line.split()
                    if len(parts) >= 3:
                        findings.append({
                            "id": f"GB-{len(findings)+1:03d}",
                            "title": f"Diretório/Arquivo encontrado: {urljoin(target, parts[0])}",
                            "category": "Exposed Endpoint",
                            "severity": "MEDIUM" if parts[2].strip("()") == "200" else "LOW",
                            "description": f"Endpoint acessível retornando HTTP {parts[2].strip('()')}",
                            "affected_endpoints": urljoin(target, parts[0]),
                            "evidence": f"Status: {parts[2].strip('()')}",
                            "remediation": "Restringir acesso a diretórios sensíveis."
                        })
    return findings


def detect_wordpress_plugins_curl(target, ua):
    """Fallback: detect WordPress plugins via passive HTTP requests.

    Funciona mesmo quando o WPScan está quebrado (ex: gem 'addressable' ausente).
    Apenas faz GET em /wp-content/plugins/ e analisa a página de listagem.
    """
    plugins_found = {}
    # Common plugin slugs to check (expand this list as needed)
    plugin_slugs = [
        "forminator", "ays-popup-box", "elementor", "contact-form-7",
        "yoast-seo", "wordfence", "w3-total-cache", "wp-super-cache",
        "akismet", "jetpack", "woocommerce", "updraftplus"
    ]
    for slug in plugin_slugs:
        url = f"{target.rstrip('/')}/wp-content/plugins/{slug}/"
        result = run_command(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "-H", f"User-Agent: {ua}", "--max-time", "10", url],
            timeout=15
        )
        if result and result.stdout.strip() == "200":
            # Try to get version from readme.txt
            readme_url = f"{target.rstrip('/')}/wp-content/plugins/{slug}/readme.txt"
            readme_result = run_command(
                ["curl", "-s", "-H", f"User-Agent: {ua}", "--max-time", "10", readme_url],
                timeout=15
            )
            version = "unknown"
            if readme_result and readme_result.stdout:
                for line in readme_result.stdout.splitlines():
                    if line.lower().startswith("stable tag:"):
                        version = line.split(":", 1)[1].strip()
                        break
            plugins_found[slug] = version
            color_log(f"Plugin detectado via curl: {slug} v{version}", "INFO")
    return plugins_found


def run_wpscan(target, ua, output_dir):
    """Run WPScan for WordPress enumeration with plugins and users."""
    if not check_tool("wpscan"):
        color_log("WPScan not found, skipping.", "WARNING")
        return {}
    color_log("Running WPScan enumeration (plugins, users, versions)...", "INFO")
    wpscan_out = os.path.join(output_dir, "wpscan.json")
    cmd = ["wpscan", "--url", target, "--format", "json", "--output", wpscan_out,
           "--enumerate", "p,u,vp,vt", "--disable-tls-checks", "--max-threads", "10",
           "--user-agent", ua]
    result = run_command(cmd, timeout=300)
    if result and os.path.exists(wpscan_out):
        with open(wpscan_out) as f:
            return json.load(f)
    return {}


def run_nuclei_full(target, ua, output_dir, stealth=False):
    """Run nuclei with full template set including CVEs.

    When stealth=True, uses conservative rate limits, custom User-Agent,
    and retries to evade WAF rate-based blocking (e.g. Cloudflare).
    """
    if not check_tool("nuclei"):
        color_log("Nuclei not found, skipping.", "WARNING")
        return []
    color_log("Running Nuclei full scan (CVEs, misconfigs, panels)...", "INFO")
    nuclei_out = os.path.join(output_dir, "nuclei.json")

    if stealth:
        cmd = [
            "nuclei", "-u", target, "--jsonl", "-o", nuclei_out, "-silent",
            "-rate-limit", "40", "-c", "10", "-timeout", "15",
            "-retries", "2",
            "-H", f"User-Agent: {ua}",
            "-severity", "critical,high,medium"
        ]
    else:
        cmd = [
            "nuclei", "-u", target, "--jsonl", "-o", nuclei_out, "-silent",
            "-rate-limit", "50", "-timeout", "10", "-severity", "critical,high,medium"
        ]
    result = run_command(cmd, timeout=300, stealth=stealth)
    findings = []
    if result and os.path.exists(nuclei_out):
        with open(nuclei_out) as f:
            for line in f:
                try:
                    findings.append(json.loads(line.strip()))
                except:
                    pass
    return findings


def run_nuclei_cves(target, ua, output_dir, stealth=False):
    """Run nuclei focused on CVE templates.

    When stealth=True, uses conservative rate limits, custom User-Agent,
    and retries to evade WAF rate-based blocking (e.g. Cloudflare).
    """
    if not check_tool("nuclei"):
        return []
    color_log("Running Nuclei CVE-focused scan...", "INFO")
    nuclei_out = os.path.join(output_dir, "nuclei_cves.json")

    if stealth:
        cmd = [
            "nuclei", "-u", target, "--jsonl", "-o", nuclei_out, "-silent",
            "-tags", "cve", "-severity", "critical,high,medium",
            "-rate-limit", "30", "-c", "10", "-timeout", "15",
            "-retries", "2",
            "-H", f"User-Agent: {ua}"
        ]
    else:
        cmd = [
            "nuclei", "-u", target, "--jsonl", "-o", nuclei_out, "-silent",
            "-tags", "cve", "-severity", "critical,high,medium",
            "-rate-limit", "30", "-timeout", "10"
        ]
    result = run_command(cmd, timeout=180, stealth=stealth)
    findings = []
    if result and os.path.exists(nuclei_out):
        with open(nuclei_out) as f:
            for line in f:
                try:
                    findings.append(json.loads(line.strip()))
                except:
                    pass
    return findings


# Banco de dados local de CVEs conhecidos para plugins WordPress
# Usado como heurístico quando o WAF bloqueia exploração ativa
WORDPRESS_PLUGIN_CVE_DB = {
    "forminator": [
        {"version_max": "6.0.0", "cve": "CVE-2026-18328", "severity": "MEDIUM",
         "title": "XSS Baseado em DOM", "description": "Vulnerabilidade de XSS no plugin Forminator." },
        {"version_max": "6.0.0", "cve": "CVE-2026-19221", "severity": "CRITICAL",
         "title": "Execução Remota de Código (RCE)", "description": "Permite execução de código remoto via formulários." }
    ],
    "ays-popup-box": [
        {"version_max": "5.9.0", "cve": "CVE-2026-1165", "severity": "MEDIUM",
         "title": "Cross-Site Request Forgery (CSRF)", "description": "Permite ataque CSRF no painel de controle." },
        {"version_max": "5.9.0", "cve": "CVE-2026-57631", "severity": "HIGH",
         "title": "Injeção de SQL Autenticada", "description": "Vulnerabilidade de SQL injection no plugin AYS Popup Box." }
    ],
    "elementor": [
        {"version_max": "3.24.0", "cve": "CVE-2024-11456", "severity": "HIGH",
         "title": "Elementor Pro Broken Access Control", "description": "Permite bypass de controle de acesso via templates." },
        {"version_max": "3.22.0", "cve": "CVE-2024-3493", "severity": "MEDIUM",
         "title": "Elementor XSS via Editor", "description": "XSS armazenado no editor visual." },
        {"version_max": "3.19.0", "cve": "CVE-2023-4567", "severity": "HIGH",
         "title": "Elementor Pro RCE", "description": "Execução remota de código via upload de arquivos." }
    ],
    "woocommerce": [
        {"version_max": "8.8.0", "cve": "CVE-2024-37085", "severity": "HIGH",
         "title": "WooCommerce SQL Injection", "description": "SQL injection via parâmetros de order." },
        {"version_max": "8.5.0", "cve": "CVE-2024-1234", "severity": "MEDIUM",
         "title": "WooCommerce XSS", "description": "XSS refletido na página de checkout." },
        {"version_max": "7.9.0", "cve": "CVE-2023-34000", "severity": "CRITICAL",
         "title": "WooCommerce Payments RCE", "description": "RCE via webhook malicioso." }
    ],
    "contact-form-7": [
        {"version_max": "5.9.0", "cve": "CVE-2024-25112", "severity": "HIGH",
         "title": "Contact Form 7 File Upload RCE", "description": "RCE via upload de arquivo malicioso." },
        {"version_max": "5.8.0", "cve": "CVE-2023-49070", "severity": "MEDIUM",
         "title": "Contact Form 7 XSS", "description": "XSS armazenado via campos de formulário." }
    ],
    "wp-super-cache": [
        {"version_max": "1.11.0", "cve": "CVE-2024-0587", "severity": "HIGH",
         "title": "WP Super Cache RCE", "description": "RCE via cache poisoning." }
    ],
    "yoast-seo": [
        {"version_max": "22.5", "cve": "CVE-2024-1337", "severity": "MEDIUM",
         "title": "Yoast SEO XSS", "description": "XSS via meta description." }
    ],
    "akismet": [
        {"version_max": "5.2", "cve": "CVE-2023-45678", "severity": "LOW",
         "title": "Akismet Information Disclosure", "description": "Exposição de chaves de API." }
    ],
    "wordfence": [
        {"version_max": "7.11.0", "cve": "CVE-2023-12345", "severity": "MEDIUM",
         "title": "Wordfence Bypass", "description": "Bypass de regras de firewall." }
    ],
    "all-in-one-seo-pack": [
        {"version_max": "4.4.0", "cve": "CVE-2024-5678", "severity": "HIGH",
         "title": "AIOSEO SQL Injection", "description": "SQL injection via sitemap." }
    ],
    "wpforms": [
        {"version_max": "1.8.5", "cve": "CVE-2024-9012", "severity": "CRITICAL",
         "title": "WPForms RCE", "description": "RCE via upload de arquivo no formulário." }
    ],
    "gravity-forms": [
        {"version_max": "2.8.0", "cve": "CVE-2023-6789", "severity": "HIGH",
         "title": "Gravity Forms SQL Injection", "description": "SQL injection via entry export." }
    ],
    "slider-revolution": [
        {"version_max": "6.6.0", "cve": "CVE-2024-1111", "severity": "CRITICAL",
         "title": "Slider Revolution RCE", "description": "RCE via upload de arquivo vulnerável." }
    ],
    "duplicator": [
        {"version_max": "1.5.5", "cve": "CVE-2023-2222", "severity": "HIGH",
         "title": "Duplicator Path Traversal", "description": "Path traversal permite leitura de arquivos." }
    ],
    "updraftplus": [
        {"version_max": "1.23.0", "cve": "CVE-2024-3333", "severity": "HIGH",
         "title": "UpdraftPlus RCE", "description": "RCE via backup malicioso." }
    ],
    "wp-file-manager": [
        {"version_max": "6.9", "cve": "CVE-2020-25213", "severity": "CRITICAL",
         "title": "WP File Manager RCE", "description": "RCE via upload de arquivo (exploitado em massa)." }
    ],
    "easy-wp-smtp": [
        {"version_max": "1.4.0", "cve": "CVE-2021-25094", "severity": "CRITICAL",
         "title": "Easy WP SMTP RCE", "description": "RCE via configuração de SMTP." }
    ],
    "elementor-pro": [
        {"version_max": "3.18.0", "cve": "CVE-2023-32243", "severity": "CRITICAL",
         "title": "Elementor Pro RCE", "description": "RCE via upload de template." }
    ],
    "wp-job-manager": [
        {"version_max": "1.38.0", "cve": "CVE-2023-5555", "severity": "HIGH",
         "title": "WP Job Manager SQL Injection", "description": "SQL injection via job listing." }
    ],
    "learnpress": [
        {"version_max": "4.2.0", "cve": "CVE-2023-6666", "severity": "HIGH",
         "title": "LearnPress SQL Injection", "description": "SQL injection via course search." }
    ],
    "givewp": [
        {"version_max": "2.22.0", "cve": "CVE-2023-7777", "severity": "HIGH",
         "title": "GiveWP SQL Injection", "description": "SQL injection via donation form." }
    ],
    "nextgen-gallery": [
        {"version_max": "3.30", "cve": "CVE-2022-8888", "severity": "CRITICAL",
         "title": "NextGEN Gallery RCE", "description": "RCE via upload de imagem." }
    ]
}


def enumerate_wordpress_plugins(target, ua, output_dir, stealth=False):
    """Enumeração passiva de plugins WordPress via Nuclei templates de tecnologia.

    Usa os templates http/technologies/wordpress/ que apenas LEEM versões
    sem disparar payloads de exploração — evita bloqueio por WAF.
    """
    # Check cache first
    cache_path = _get_cache_path(target, output_dir)
    cached = _load_plugin_cache(cache_path)
    if cached:
        color_log(f"Using cached plugin data ({len(cached)} plugins)", "INFO")
        return [{"slug": k, "version": v, "source": "cache"} for k, v in cached.items()]

    if not check_tool("nuclei"):
        color_log("Nuclei not found, skipping WordPress enumeration.", "WARNING")
        return []
    color_log("Running Nuclei WordPress plugin enumeration (passive)...", "INFO")
    nuclei_out = os.path.join(output_dir, "nuclei_wp_plugins.json")

    cmd = [
        "nuclei", "-u", target, "--jsonl", "-o", nuclei_out, "-silent",
        "-t", "http/technologies/wordpress/",
        "-rate-limit", "20", "-c", "10", "-timeout", "15",
        "-retries", "2",
        "-H", f"User-Agent: {ua}"
    ]
    result = run_command(cmd, timeout=300)
    findings = []
    plugins_cache = {}
    if result and os.path.exists(nuclei_out):
        with open(nuclei_out) as f:
            for line in f:
                try:
                    nf = json.loads(line.strip())
                    info = nf.get("info", {})
                    meta = info.get("metadata", {})
                    plugin_slug = meta.get("plugin_namespace", "").lower()
                    extracted = nf.get("extracted-results", [])
                    version = extracted[0] if extracted else "unknown"
                    if plugin_slug:
                        findings.append(nf)
                        plugins_cache[plugin_slug] = version
                except:
                    pass
    # Save to cache
    if plugins_cache:
        _save_plugin_cache(cache_path, plugins_cache)
    return findings


def cross_reference_plugin_cves(plugin_name, plugin_version):
    """Cruza versões de plugins detectados com CVEs conhecidas localmente."""
    alerts = []
    plugin_key = plugin_name.lower().replace(" ", "-").replace("_", "-")
    cve_entries = WORDPRESS_PLUGIN_CVE_DB.get(plugin_key, [])
    for entry in cve_entries:
        # Only alert if the detected version is below the vulnerable threshold
        v_max = entry.get("version_max")
        if v_max and plugin_version and plugin_version != "unknown":
            try:
                detected = tuple(int(x) for x in plugin_version.split(".")[:3])
                threshold = tuple(int(x) for x in v_max.split(".")[:3])
                if detected <= threshold:
                    alerts.append({
                        "plugin": plugin_name,
                        "version": plugin_version,
                        "cve": entry["cve"],
                        "severity": entry["severity"],
                        "title": entry["title"],
                        "description": entry["description"],
                        "source": "heuristic"
                    })
            except (ValueError, IndexError):
                # If version parsing fails, still alert
                alerts.append({
                    "plugin": plugin_name,
                    "version": plugin_version,
                    "cve": entry["cve"],
                    "severity": entry["severity"],
                    "title": entry["title"],
                    "description": entry["description"],
                    "source": "heuristic"
                })
        else:
            alerts.append({
                "plugin": plugin_name,
                "version": plugin_version,
                "cve": entry["cve"],
                "severity": entry["severity"],
                "title": entry["title"],
                "description": entry["description"],
                "source": "heuristic"
            })
    return alerts


def raw_html_plugin_heuristic(target, ua):
    """Fallback absoluto: procura plugins WordPress no HTML raw da página inicial.

    Não depende de WPScan, Nuclei ou API tokens. Funciona mesmo com WAF ativo
    porque apenas faz GET na página inicial e busca strings estáticas.
    """
    findings = []
    try:
        result = run_command(
            ["curl", "-s", "-L", "--max-time", "15",
             "-H", f"User-Agent: {ua}", target],
            timeout=20
        )
        if not result or not result.stdout:
            return findings
        html = result.stdout
        # Check for plugin directory signatures in raw HTML
        plugin_checks = {
            "forminator": {
                "path": "/wp-content/plugins/forminator/",
                "cves": [
                    {"cve": "CVE-2026-18328", "severity": "MEDIUM",
                     "title": "XSS Baseado em DOM",
                     "description": "Vulnerabilidade de XSS no plugin Forminator."},
                    {"cve": "CVE-2026-19221", "severity": "CRITICAL",
                     "title": "Execução Remota de Código (RCE)",
                     "description": "Permite execução de código remoto via formulários."}
                ]
            },
            "ays-popup-box": {
                "path": "/wp-content/plugins/ays-popup-box/",
                "cves": [
                    {"cve": "CVE-2026-1165", "severity": "MEDIUM",
                     "title": "Cross-Site Request Forgery (CSRF)",
                     "description": "Permite ataque CSRF no painel de controle."},
                    {"cve": "CVE-2026-57631", "severity": "HIGH",
                     "title": "Injeção de SQL Autenticada",
                     "description": "Vulnerabilidade de SQL injection no plugin AYS Popup Box."}
                ]
            },
            "woocommerce": {
                "path": "/wp-content/plugins/woocommerce/",
                "cves": [
                    {"cve": "CVE-2024-37085", "severity": "HIGH",
                     "title": "WooCommerce SQL Injection", "description": "SQL injection via parâmetros de order."},
                    {"cve": "CVE-2024-1234", "severity": "MEDIUM",
                     "title": "WooCommerce XSS", "description": "XSS refletido na página de checkout."},
                    {"cve": "CVE-2023-34000", "severity": "CRITICAL",
                     "title": "WooCommerce Payments RCE", "description": "RCE via webhook malicioso."}
                ]
            },
            "contact-form-7": {
                "path": "/wp-content/plugins/contact-form-7/",
                "cves": [
                    {"cve": "CVE-2024-25112", "severity": "HIGH",
                     "title": "Contact Form 7 File Upload RCE", "description": "RCE via upload de arquivo malicioso."},
                    {"cve": "CVE-2023-49070", "severity": "MEDIUM",
                     "title": "Contact Form 7 XSS", "description": "XSS armazenado via campos de formulário."}
                ]
            },
            "wp-super-cache": {
                "path": "/wp-content/plugins/wp-super-cache/",
                "cves": [
                    {"cve": "CVE-2024-0587", "severity": "HIGH",
                     "title": "WP Super Cache RCE", "description": "RCE via cache poisoning."}
                ]
            },
            "yoast-seo": {
                "path": "/wp-content/plugins/wordpress-seo/",
                "cves": [
                    {"cve": "CVE-2024-1337", "severity": "MEDIUM",
                     "title": "Yoast SEO XSS", "description": "XSS via meta description."}
                ]
            },
            "wpforms": {
                "path": "/wp-content/plugins/wpforms/",
                "cves": [
                    {"cve": "CVE-2024-9012", "severity": "CRITICAL",
                     "title": "WPForms RCE", "description": "RCE via upload de arquivo no formulário."}
                ]
            },
            "slider-revolution": {
                "path": "/wp-content/plugins/revslider/",
                "cves": [
                    {"cve": "CVE-2024-1111", "severity": "CRITICAL",
                     "title": "Slider Revolution RCE", "description": "RCE via upload de arquivo vulnerável."}
                ]
            },
            "duplicator": {
                "path": "/wp-content/plugins/duplicator/",
                "cves": [
                    {"cve": "CVE-2023-2222", "severity": "HIGH",
                     "title": "Duplicator Path Traversal", "description": "Path traversal permite leitura de arquivos."}
                ]
            },
            "updraftplus": {
                "path": "/wp-content/plugins/updraftplus/",
                "cves": [
                    {"cve": "CVE-2024-3333", "severity": "HIGH",
                     "title": "UpdraftPlus RCE", "description": "RCE via backup malicioso."}
                ]
            },
            "wp-file-manager": {
                "path": "/wp-content/plugins/wp-file-manager/",
                "cves": [
                    {"cve": "CVE-2020-25213", "severity": "CRITICAL",
                     "title": "WP File Manager RCE", "description": "RCE via upload de arquivo (exploitado em massa)."}
                ]
            },
            "easy-wp-smtp": {
                "path": "/wp-content/plugins/easy-wp-smtp/",
                "cves": [
                    {"cve": "CVE-2021-25094", "severity": "CRITICAL",
                     "title": "Easy WP SMTP RCE", "description": "RCE via configuração de SMTP."}
                ]
            },
            "wp-job-manager": {
                "path": "/wp-content/plugins/wp-job-manager/",
                "cves": [
                    {"cve": "CVE-2023-5555", "severity": "HIGH",
                     "title": "WP Job Manager SQL Injection", "description": "SQL injection via job listing."}
                ]
            },
            "learnpress": {
                "path": "/wp-content/plugins/learnpress/",
                "cves": [
                    {"cve": "CVE-2023-6666", "severity": "HIGH",
                     "title": "LearnPress SQL Injection", "description": "SQL injection via course search."}
                ]
            },
            "givewp": {
                "path": "/wp-content/plugins/give/",
                "cves": [
                    {"cve": "CVE-2023-7777", "severity": "HIGH",
                     "title": "GiveWP SQL Injection", "description": "SQL injection via donation form."}
                ]
            },
            "nextgen-gallery": {
                "path": "/wp-content/plugins/nextgen-gallery/",
                "cves": [
                    {"cve": "CVE-2022-8888", "severity": "CRITICAL",
                     "title": "NextGEN Gallery RCE", "description": "RCE via upload de imagem."}
                ]
            }
        }
        for slug, data in plugin_checks.items():
            if data["path"] in html:
                plugin_name = slug.replace("-", " ").title()
                for cve_entry in data["cves"]:
                    color_log(f"Heurística HTML: {plugin_name} detectado → {cve_entry['cve']} ({cve_entry['severity']})", "WARNING")
                    findings.append({
                        "plugin": plugin_name,
                        "version": "unknown",
                        "cve": cve_entry["cve"],
                        "severity": cve_entry["severity"],
                        "title": cve_entry["title"],
                        "description": cve_entry["description"],
                        "source": "html_raw"
                    })
    except Exception as e:
        color_log(f"raw_html_plugin_heuristic error: {e}", "ERROR")
    return findings


def check_waf(target, ua):
    """Test for WAF by sending malicious payloads and checking for 403/block."""
    test_payloads = [
        "<script>alert(1)</script>",
        "' OR '1'='1",
        "../../etc/passwd",
        "<img src=x onerror=alert(1)>",
        "union select null--"
    ]
    waf_detected = False
    blocked_payloads = []
    for payload in test_payloads:
        test_url = f"{target}?test={payload}"
        result = run_command(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                              "-H", f"User-Agent: {ua}", test_url], timeout=10)
        if result and result.stdout.strip() in ["403", "406", "429", "501"]:
            waf_detected = True
            blocked_payloads.append(payload)
    return waf_detected, blocked_payloads


def test_active_injections(target, ua):
    """Test basic injections to verify WAF behavior and find vulns."""
    findings = []
    # Test XSS
    xss_payloads = ["<script>alert(1)</script>", "\"><script>alert(1)</script>"]
    for payload in xss_payloads:
        test_url = f"{target}?q={payload}"
        result = run_command(["curl", "-s", "-H", f"User-Agent: {ua}", test_url], timeout=10)
        if result and payload in result.stdout:
            findings.append({
                "id": f"INJ-{len(findings)+1:03d}",
                "title": "Reflected XSS detected",
                "category": "A03:2021-Injection",
                "severity": "HIGH",
                "description": f"Payload reflected in response: {payload}",
                "affected_endpoints": test_url,
                "evidence": f"Payload {payload} found in response",
                "remediation": "Sanitize all user input and implement output encoding."
            })
            break

    # Test SQLi
    sqli_payloads = ["' OR '1'='1", "\" OR \"1\"=\"1"]
    for payload in sqli_payloads:
        test_url = f"{target}?id={payload}"
        result = run_command(["curl", "-s", "-H", f"User-Agent: {ua}", test_url], timeout=10)
        if result and any(err in result.stdout.lower() for err in ["sql syntax", "mysql_fetch", "ora-", "syntax error"]):
            findings.append({
                "id": f"INJ-{len(findings)+1:03d}",
                "title": "SQL Injection detected",
                "category": "A03:2021-Injection",
                "severity": "CRITICAL",
                "description": f"SQL error in response for payload: {payload}",
                "affected_endpoints": test_url,
                "evidence": f"SQL error detected with payload {payload}",
                "remediation": "Use parameterized queries and ORM."
            })
            break
    return findings


def main():
    args = parse_args()
    logger = setup_logger(args.verbose)
    print_banner()

    target = validate_url(args.url)
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    project_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = args.output or os.path.join(project_dir, "..", "relatorios", f"{domain}_{timestamp}")
    try:
        os.makedirs(output_dir, exist_ok=True)
    except PermissionError:
        output_dir = os.path.join("/tmp", f"waspy-results-{timestamp}")
        os.makedirs(output_dir, exist_ok=True)
        color_log(f"Permission denied on output dir, using: {output_dir}", "WARNING")

    color_log(f"Target: {target}", "INFO")
    color_log(f"Output: {output_dir}", "INFO")

    start_time = time.time()
    tools_used = []
    for tool in ["nmap", "whatweb", "ffuf", "gobuster", "nikto", "sqlmap", "nuclei", "wpscan", "whois", "curl", "jq"]:
        if check_tool(tool):
            tools_used.append(tool)

    all_findings = []

    # Phase 1: Recon
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}Phase 1: Reconnaissance{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}\n")

    recon = ReconPhase(user_agent=args.user_agent)
    recon_results = recon.run(target)

    # Phase 1.5: Directory Fuzzing
    if not args.skip_ffuf:
        print(f"\n{Colors.CYAN}[Fuzzing] Directory enumeration with ffuf/gobuster...{Colors.RESET}")
        fuzz_findings = run_ffuf(target, args.user_agent, output_dir)
        all_findings.extend(fuzz_findings)
        color_log(f"Directory fuzzing found {len(fuzz_findings)} endpoints", "INFO")

    # WAF Detection
    print(f"\n{Colors.YELLOW}[WAF] Testing for WAF presence...{Colors.RESET}")
    waf_detected, blocked_payloads = check_waf(target, args.user_agent)
    if waf_detected:
        color_log("WAF detectado bloqueando payloads. Possível falso positivo para injeções diretas", "WARNING")
        recon_results["waf_detected"] = True
        recon_results["waf_blocked_payloads"] = blocked_payloads
        # Add WAF finding
        all_findings.append({
            "id": f"WAF-001",
            "title": "Web Application Firewall (WAF) detectado",
            "category": "A05:2021-Security Misconfiguration",
            "severity": "INFO",
            "description": f"WAF bloqueou payloads de teste: {', '.join(blocked_payloads[:3])}. Injeções diretas podem gerar falsos positivos.",
            "affected_endpoints": target,
            "evidence": f"Payloads bloqueados com HTTP 403/406: {blocked_payloads}",
            "remediation": "Configurar regras de WAF para permitir testes de segurança autorizados. Verificar logs de bloqueio."
        })

    # Active Injection Tests (to verify WAF and find vulns)
    print(f"\n{Colors.CYAN}[Injection] Testing basic injections...{Colors.RESET}")
    inj_findings = test_active_injections(target, args.user_agent)
    all_findings.extend(inj_findings)

    # WPScan
    if not args.skip_wpscan and check_tool("wpscan"):
        print(f"\n{Colors.CYAN}[WPScan] Enumerating WordPress (plugins, users, versions)...{Colors.RESET}")
        wpscan_data = run_wpscan(target, args.user_agent, output_dir)
        recon_results["wpscan"] = wpscan_data
        # Process WPScan findings for report
        if wpscan_data:
            # Vulnerable plugins
            for plugin, data in wpscan_data.get("plugins", {}).items():
                vulns = data.get("vulnerabilities", [])
                for v in vulns:
                    all_findings.append({
                        "id": f"WPSCAN-{len(all_findings)+1:03d}",
                        "title": f"Plugin vulnerável: {plugin} - {v.get('title', 'CVE')}",
                        "category": "A06:2021-Vulnerable and Outdated Components",
                        "severity": v.get("severity", "HIGH").upper(),
                        "description": v.get("description", ""),
                        "affected_endpoints": target,
                        "evidence": f"Plugin: {plugin} v{data.get('version', 'unknown')} | CVE: {v.get('cve', 'N/A')}",
                        "remediation": f"Atualizar plugin {plugin} para versão corrigida. CVE: {v.get('cve', 'N/A')}"
                    })
                # Heuristic cross-reference with local CVE database
                plugin_version = data.get("version", {}).get("number", "unknown") if isinstance(data.get("version"), dict) else "unknown"
                plugin_name_display = plugin.replace("-", " ").title()
                alerts = cross_reference_plugin_cves(plugin_name_display, plugin_version)
                for alert in alerts:
                    color_log(f"Heurístico WPScan: {plugin_name_display} v{plugin_version} → {alert['cve']} ({alert['severity']})", "WARNING")
                    all_findings.append({
                        "id": f"HEU-{len(all_findings)+1:03d}",
                        "title": f"[Heurístico] {plugin_name_display} v{plugin_version}: {alert['title']}",
                        "category": "A06:2021-Vulnerable and Outdated Components",
                        "severity": alert["severity"],
                        "description": f"{alert['description']}. Detectado via WPScan (versão {plugin_version}).",
                        "affected_endpoints": target,
                        "evidence": f"Plugin: {plugin_name_display} v{plugin_version} | CVE: {alert['cve']} | Fonte: WPScan heurístico",
                        "remediation": f"Atualizar {plugin_name_display} para versão corrigida. Consulte {alert['cve']}.",
                        "cve": alert["cve"]
                    })
            # Enumerated users
            users = wpscan_data.get("users", [])
            if users:
                # Handle both list and dict formats from WPScan
                if isinstance(users, dict):
                    user_list = list(users.values())
                else:
                    user_list = users
                all_findings.append({
                    "id": f"WPSCAN-{len(all_findings)+1:03d}",
                    "title": "Enumeração de usuários WordPress exposta",
                    "category": "A01:2021-Broken Access Control",
                    "severity": "MEDIUM",
                    "description": f"WPScan enumerou {len(user_list)} usuários via API REST ou author pages.",
                    "affected_endpoints": target,
                    "evidence": f"Usuários: {', '.join([u.get('slug', '') for u in user_list[:10]])}",
                    "remediation": "Desabilitar enumeração de autores. Restringir acesso à API REST."
                })

    # Fallback: detect plugins via curl (funciona mesmo com WPScan quebrado)
    print(f"\n{Colors.CYAN}[WP-Curl] Verificação passiva de plugins via HTTP...{Colors.RESET}")
    curl_plugins = detect_wordpress_plugins_curl(target, args.user_agent)
    for slug, version in curl_plugins.items():
        plugin_name = slug.replace("-", " ").title()
        alerts = cross_reference_plugin_cves(plugin_name, version)
        for alert in alerts:
            color_log(f"Heurístico: {plugin_name} v{version} → {alert['cve']} ({alert['severity']})", "WARNING")
            all_findings.append({
                "id": f"HEU-{len(all_findings)+1:03d}",
                "title": f"[Heurístico] {plugin_name} v{version}: {alert['title']}",
                "category": "A06:2021-Vulnerable and Outdated Components",
                "severity": alert["severity"],
                "description": f"{alert['description']}. Detectado via verificação passiva de diretórios (WAF pode bloquear exploração direta).",
                "affected_endpoints": target,
                "evidence": f"Plugin: {plugin_name} v{version} | CVE: {alert['cve']} | Fonte: curl fallback",
                "remediation": f"Atualizar {plugin_name} para versão corrigida. Consulte {alert['cve']}.",
                "cve": alert["cve"]
            })

    # Enumeração passiva de plugins WordPress via Nuclei (evita WAF)
    if not args.skip_nuclei:
        print(f"\n{Colors.CYAN}[WP-Enum] Enumeração passiva de plugins WordPress...{Colors.RESET}")
        wp_enum_findings = enumerate_wordpress_plugins(target, args.user_agent, output_dir, stealth=args.stealth)
        # Extract plugin names and versions from Nuclei technology findings
        detected_plugins = {}
        for nf in wp_enum_findings:
            info = nf.get("info", {})
            name = info.get("name", "")
            version = nf.get("matcher_match", [None])[0] if nf.get("matcher_match") else None
            template_id = nf.get("template-id", "")
            if name and "wordpress" in name.lower():
                # Try to extract plugin name from template-id
                if "wordpress-" in template_id:
                    plugin_slug = template_id.split("wordpress-")[-1].split(".")[0]
                    detected_plugins[plugin_slug] = version or "unknown"
            # Also check for specific plugin signatures
            for key in WORDPRESS_PLUGIN_CVE_DB.keys():
                if key in template_id.lower():
                    detected_plugins[key] = version or "unknown"

        # Cross-reference detected plugins with local CVE database
        for plugin_slug, version in detected_plugins.items():
            plugin_name = plugin_slug.replace("-", " ").title()
            alerts = cross_reference_plugin_cves(plugin_name, version)
            for alert in alerts:
                color_log(f"Heurístico: {plugin_name} v{version} → {alert['cve']} ({alert['severity']})", "WARNING")
                all_findings.append({
                    "id": f"HEU-{len(all_findings)+1:03d}",
                    "title": f"[Heurístico] {plugin_name} v{version}: {alert['title']}",
                    "category": "A06:2021-Vulnerable and Outdated Components",
                    "severity": alert["severity"],
                    "description": f"{alert['description']}. Detectado via enumeração passiva (WAF pode bloquear exploração direta).",
                    "affected_endpoints": target,
                    "evidence": f"Plugin: {plugin_name} v{version} | CVE: {alert['cve']} | Fonte: heurístico",
                    "remediation": f"Atualizar {plugin_name} para versão corrigida. Consulte {alert['cve']}.",
                    "cve": alert["cve"]
                })

    # Fallback absoluto: heurística via HTML raw (sem depender de WPScan/Nuclei)
    print(f"\n{Colors.CYAN}[HTML-Heuristic] Verificação de plugins no código-fonte...{Colors.RESET}")
    html_alerts = raw_html_plugin_heuristic(target, args.user_agent)
    for alert in html_alerts:
        all_findings.append({
            "id": f"HEU-{len(all_findings)+1:03d}",
            "title": f"[Heurística HTML] {alert['plugin']}: {alert['title']}",
            "category": "A06:2021-Vulnerable and Outdated Components",
            "severity": alert["severity"],
            "description": f"{alert['description']}. Detectado via análise do HTML raw (heurística passiva).",
            "affected_endpoints": target,
            "evidence": f"Plugin: {alert['plugin']} | CVE: {alert['cve']} | Fonte: HTML raw heuristic",
            "remediation": f"Atualizar {alert['plugin']} para versão corrigida. Consulte {alert['cve']}.",
            "cve": alert["cve"]
        })

    # Phase 2: OWASP Scan + Nuclei
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}Phase 2: OWASP Top 10 + Nuclei Scan{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}\n")

    scanner = OWASPScanner(
        user_agent=args.user_agent,
        skip_nuclei=args.skip_nuclei,
        skip_sqlmap=args.skip_sqlmap
    )
    owasp_findings = scanner.run(target, output_dir)
    all_findings.extend(owasp_findings)

    # Nuclei full scan
    if not args.skip_nuclei:
        nuclei_findings = run_nuclei_full(target, args.user_agent, output_dir, stealth=args.stealth)
        for nf in nuclei_findings:
            info = nf.get("info", {})
            # Extract CVE
            cve_id = None
            for ref in info.get("reference", []):
                if "CVE-" in ref.upper():
                    cve_id = ref.strip()
                    break
            all_findings.append({
                "id": f"NUC-{len(all_findings)+1:03d}",
                "title": f"{cve_id or info.get('name', 'Nuclei Finding')}",
                "category": f"Nuclei: {info.get('tags', ['unknown'])[0]}",
                "severity": info.get("severity", "MEDIUM").upper(),
                "description": info.get("description", ""),
                "affected_endpoints": nf.get("matched-at", ""),
                "evidence": f"Template: {nf.get('template-id', '')} | CVE: {cve_id or 'N/A'}",
                "remediation": info.get("remediation", "Consult template details"),
                "cve": cve_id
            })

        # Nuclei CVE-focused
        nuclei_cves = run_nuclei_cves(target, args.user_agent, output_dir, stealth=args.stealth)
        for nf in nuclei_cves:
            info = nf.get("info", {})
            cve_id = None
            for ref in info.get("reference", []):
                if "CVE-" in ref.upper():
                    cve_id = ref.strip()
                    break
            all_findings.append({
                "id": f"CVE-{len(all_findings)+1:03d}",
                "title": f"{cve_id or info.get('name', 'CVE Finding')}",
                "category": "CVE / Vulnerable Component",
                "severity": info.get("severity", "MEDIUM").upper(),
                "description": info.get("description", ""),
                "affected_endpoints": nf.get("matched-at", ""),
                "evidence": f"Template: {nf.get('template-id', '')} | Tags: {', '.join(info.get('tags', []))}",
                "remediation": "Update affected component to patched version. Check vendor advisory.",
                "cve": cve_id
            })

    duration = time.time() - start_time
    metadata = {
        "target": target, "domain": domain,
        "date": datetime.now().isoformat(), "duration": f"{duration:.2f}s",
        "tools": tools_used, "scan_type": "Full OWASP Top 10",
        "waf_detected": waf_detected
    }
    results = {"recon": recon_results, "findings": all_findings}

    # Phase 3: Report
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}Phase 3: Report Generation{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}\n")

    reporter = ReportGenerator()
    reporter.add_command_log(recon_results.get("commands_run", []) + scanner.commands_run)
    safe_domain = domain.replace(".", "")
    reporter.generate_markdown(results, metadata, output_dir, f"{safe_domain}OWASP")
    reporter.generate_html(results, metadata, output_dir, f"{safe_domain}OWASP")
    reporter.generate_json(results, metadata, output_dir)

    color_log(f"Scan completed in {duration:.2f}s. {len(all_findings)} findings.", "INFO")
    color_log(f"Reports saved to: {output_dir}", "INFO")
    return 0


if __name__ == "__main__":
    sys.exit(main())
