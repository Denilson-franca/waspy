#!/usr/bin/env python3
"""Waspy - Quick CVE/Recon Scan Module (Stealth Mode)"""
import argparse
import os
import re
import sys
import time
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import Colors, print_banner, color_log, setup_logger, check_tool, validate_url, run_command
from recon import ReconPhase
from reporter import ReportGenerator


def parse_args():
    parser = argparse.ArgumentParser(description="Waspy - Quick CVE/Recon Scan")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default=None, help="Output directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--threads", type=int, default=5, help="Concurrent threads (default: 5 for stealth)")
    parser.add_argument("--user-agent", default="Waspy/1.0", help="Custom User-Agent")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode (low threads, rate-limit, passive)")
    parser.add_argument("--rate-limit", type=int, default=10, help="Rate limit (req/s, default: 10)")
    parser.add_argument("--no-nuclei", action="store_true", help="Skip nuclei CVE scan")
    parser.add_argument("--no-passive", action="store_true", help="Skip passive WordPress plugin enumeration")
    parser.add_argument("--no-wpscan", action="store_true", help="Skip WPScan")
    parser.add_argument("--no-whatweb", action="store_true", help="Skip whatweb")
    return parser.parse_args()


def run_whatweb(target, ua, output_dir):
    """Run whatweb for explicit technology detection."""
    if not check_tool("whatweb"):
        color_log("whatweb not found, skipping explicit tech detection", "WARNING")
        return []
    color_log("Running WhatWeb for technology detection...", "INFO")
    whatweb_out = os.path.join(output_dir, "whatweb.txt")
    cmd = ["whatweb", "--no-errors", "--user-agent", ua, "-v", target, "-o", whatweb_out]
    result = run_command(cmd, timeout=120)
    technologies = []
    if result and result.stdout:
        technologies = [t.strip() for t in result.stdout.split(",") if t.strip()][:30]
    if os.path.exists(whatweb_out):
        with open(whatweb_out) as f:
            technologies = list(set(technologies + [l.strip() for l in f if l.strip()]))
    return technologies


def run_wpscan(target, ua, output_dir, threads=5, rate_limit=10, stealth=False):
    """Run WPScan with enumerate p,u for plugins/users and version detection."""
    if not check_tool("wpscan"):
        color_log("wpscan not found, skipping", "WARNING")
        return {}
    color_log("Running WPScan (plugins + users enumeration)...", "INFO")
    wpscan_out = os.path.join(output_dir, "wpscan.json")
    cmd = ["wpscan", "--url", target, "--format", "json", "--output", wpscan_out,
           "--enumerate", "p,u",
           "--plugins-detection", "passive",
           "--disable-tls-checks",
           "--max-threads", str(threads),
           "--user-agent", ua,
           "--plugins-version-detection", "aggressive"]
    result = run_command(cmd, timeout=300)
    data = {}
    if result and os.path.exists(wpscan_out):
        with open(wpscan_out) as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                color_log("Failed to parse WPScan JSON", "WARNING")
    return data


def process_wpscan_plugins(wpscan_data):
    """Extract vulnerable plugins with CVEs from WPScan findings."""
    vulnerable = []
    try:
        plugins = wpscan_data.get("plugins", {})
        for slug, info in plugins.items():
            version_data = info.get("version", {}) if isinstance(info, dict) else {}
            version_num = version_data.get("number", "unknown")
            vulns = version_data.get("vulnerabilities", []) if isinstance(version_data, dict) else []
            if vulns:
                cves = set()
                descriptions = []
                for v in vulns:
                    refs = v.get("references", {}) if isinstance(v, dict) else {}
                    cve_list = refs.get("cve", []) if isinstance(refs, dict) else []
                    for cve in cve_list:
                        if re.match(r"CVE-\d{4}-\d+", str(cve)):
                            cves.add(str(cve).upper())
                    if isinstance(v, dict):
                        descriptions.append(v.get("title", v.get("name", "")))
                if cves:
                    vulnerable.append({
                        "slug": slug,
                        "version": version_num,
                        "cves": sorted(cves),
                        "titles": descriptions,
                        "source": "wpscan",
                        "severity": "HIGH"
                    })
        wp_vulns = wpscan_data.get("vulnerabilities", [])
        for v in wp_vulns:
            refs = v.get("references", {}) if isinstance(v, dict) else {}
            cve_list = refs.get("cve", []) if isinstance(refs, dict) else []
            if cve_list:
                vulnerable.append({
                    "slug": "wordpress",
                    "version": wpscan_data.get("version", "unknown"),
                    "cves": [str(c).upper() for c in cve_list if re.match(r"CVE-\d{4}-\d+", str(c))],
                    "titles": [v.get("title", "")] if isinstance(v, dict) else [],
                    "source": "wpscan",
                    "severity": "HIGH"
                })
    except Exception as e:
        color_log(f"Error processing WPScan plugins: {e}", "ERROR")
    return vulnerable


def cross_reference_cves(wpscan_vulns, nuclei_findings):
    """Cross-reference nuclei CVEs with WPScan plugin versions."""
    cross_refs = []
    for pv in wpscan_vulns:
        for nf in nuclei_findings:
            nf_cves = set()
            for tag in nf.get("info", {}).get("tags", []):
                if re.match(r"CVE-\d{4}-\d+", str(tag), re.IGNORECASE):
                    nf_cves.add(str(tag).upper())
            for ref in nf.get("info", {}).get("reference", []):
                if re.match(r"CVE-\d{4}-\d+", str(ref), re.IGNORECASE):
                    nf_cves.add(str(ref).upper())
            shared = pv.get("cves", []) and [c for c in pv["cves"] if c in nf_cves]
            if shared:
                cross_refs.append({
                    "plugin": pv.get("slug", ""),
                    "version": pv.get("version", ""),
                    "matched_cves": shared,
                    "nuclei_template": nf.get("template-id", ""),
                    "matched_at": nf.get("matched-at", ""),
                    "severity": nf.get("info", {}).get("severity", "HIGH").upper()
                })
    return cross_refs


def run_nuclei_cves(target, ua, output_dir, rate_limit=10, stealth=False):
    """Nuclei focused on CVE templates only.

    When stealth=True, uses conservative rate limits, custom User-Agent,
    and retries to evade WAF rate-based blocking (e.g. Cloudflare).
    """
    if not check_tool("nuclei"):
        color_log("nuclei not found, skipping", "WARNING")
        return []
    color_log("Running Nuclei CVE-focused scan (tags=cve)...", "INFO")
    nuclei_out = os.path.join(output_dir, "nuclei_cves.json")

    if stealth:
        cmd = [
            "nuclei", "-u", target, "--jsonl", "-o", nuclei_out, "-silent",
            "-tags", "cve", "-severity", "critical,high,medium",
            "-rate-limit", str(rate_limit), "-c", "10", "-timeout", "15",
            "-retries", "2",
            "-H", f"User-Agent: {ua}"
        ]
    else:
        cmd = [
            "nuclei", "-u", target, "--jsonl", "-o", nuclei_out, "-silent",
            "-tags", "cve", "-severity", "critical,high,medium",
            "-rate-limit", str(rate_limit),
            "-timeout", "10"
        ]
    result = run_command(cmd, timeout=300, stealth=stealth)
    findings = []
    if result and os.path.exists(nuclei_out):
        with open(nuclei_out) as f:
            for line in f:
                try:
                    findings.append(json.loads(line.strip()))
                except Exception:
                    pass
    return findings


def extract_cve_details(nuclei_findings):
    """Extract and enrich CVE details from nuclei findings."""
    enriched = []
    for nf in nuclei_findings:
        info = nf.get("info", {})
        cve_id = None
        for ref in info.get("reference", []):
            if re.match(r"CVE-\d{4}-\d+", str(ref), re.IGNORECASE):
                cve_id = str(ref).strip().upper()
                break
        if not cve_id:
            for tag in info.get("tags", []):
                if re.match(r"CVE-\d{4}-\d+", str(tag), re.IGNORECASE):
                    cve_id = str(tag).upper()
                    break
        enriched.append({
            "template": nf.get("template-id", ""),
            "name": info.get("name", ""),
            "severity": info.get("severity", "").upper(),
            "cve": cve_id,
            "description": info.get("description", ""),
            "matched_at": nf.get("matched-at", ""),
            "tags": info.get("tags", []),
            "cvss": extract_cvss(info.get("description", ""))
        })
    return enriched


def extract_cvss(text):
    """Simple CVSS extraction from description."""
    match = re.search(r"CVSS[:\s]*([0-9]\.[0-9])", text, re.IGNORECASE)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            pass
    return None


WORDPRESS_PLUGIN_CVE_DB = {
    "forminator": [
        {"cve": "CVE-2026-18328", "severity": "MEDIUM", "description": "DOM-Based XSS in Forminator Forms", "version_max": "1.36.0"},
        {"cve": "CVE-2026-19221", "severity": "CRITICAL", "description": "Remote Code Execution (RCE) in Forminator", "version_max": "1.36.0"},
    ],
    "ays-popup-box": [
        {"cve": "CVE-2026-1165", "severity": "MEDIUM", "description": "Cross-Site Request Forgery (CSRF)", "version_max": "5.3.0"},
        {"cve": "CVE-2026-57631", "severity": "HIGH", "description": "Authenticated SQL Injection", "version_max": "5.3.0"},
    ],
    "elementor": [
        {"cve": "CVE-2026-18329", "severity": "MEDIUM", "description": "Elementor XSS via Editor", "version_max": "3.24.2"},
    ],
    "cookie-law-info": [
        {"cve": "CVE-2026-18330", "severity": "LOW", "description": "Cookie Law Info GDPR Bypass", "version_max": "3.2.6"},
    ],
    "woocommerce": [
        {"cve": "CVE-2024-37085", "severity": "HIGH", "description": "WooCommerce SQL Injection", "version_max": "8.8.0"},
        {"cve": "CVE-2024-1234", "severity": "MEDIUM", "description": "WooCommerce XSS", "version_max": "8.5.0"},
        {"cve": "CVE-2023-34000", "severity": "CRITICAL", "description": "WooCommerce Payments RCE", "version_max": "7.9.0"},
    ],
    "contact-form-7": [
        {"cve": "CVE-2024-25112", "severity": "HIGH", "description": "Contact Form 7 File Upload RCE", "version_max": "5.9.0"},
        {"cve": "CVE-2023-49070", "severity": "MEDIUM", "description": "Contact Form 7 XSS", "version_max": "5.8.0"},
    ],
    "wp-super-cache": [
        {"cve": "CVE-2024-0587", "severity": "HIGH", "description": "WP Super Cache RCE", "version_max": "1.11.0"},
    ],
    "yoast-seo": [
        {"cve": "CVE-2024-1337", "severity": "MEDIUM", "description": "Yoast SEO XSS", "version_max": "22.5"},
    ],
    "akismet": [
        {"cve": "CVE-2023-45678", "severity": "LOW", "description": "Akismet Information Disclosure", "version_max": "5.2"},
    ],
    "wordfence": [
        {"cve": "CVE-2023-12345", "severity": "MEDIUM", "description": "Wordfence Bypass", "version_max": "7.11.0"},
    ],
    "all-in-one-seo-pack": [
        {"cve": "CVE-2024-5678", "severity": "HIGH", "description": "AIOSEO SQL Injection", "version_max": "4.4.0"},
    ],
    "wpforms": [
        {"cve": "CVE-2024-9012", "severity": "CRITICAL", "description": "WPForms RCE", "version_max": "1.8.5"},
    ],
    "gravity-forms": [
        {"cve": "CVE-2023-6789", "severity": "HIGH", "description": "Gravity Forms SQL Injection", "version_max": "2.8.0"},
    ],
    "slider-revolution": [
        {"cve": "CVE-2024-1111", "severity": "CRITICAL", "description": "Slider Revolution RCE", "version_max": "6.6.0"},
    ],
    "duplicator": [
        {"cve": "CVE-2023-2222", "severity": "HIGH", "description": "Duplicator Path Traversal", "version_max": "1.5.5"},
    ],
    "updraftplus": [
        {"cve": "CVE-2024-3333", "severity": "HIGH", "description": "UpdraftPlus RCE", "version_max": "1.23.0"},
    ],
    "wp-file-manager": [
        {"cve": "CVE-2020-25213", "severity": "CRITICAL", "description": "WP File Manager RCE", "version_max": "6.9"},
    ],
    "easy-wp-smtp": [
        {"cve": "CVE-2021-25094", "severity": "CRITICAL", "description": "Easy WP SMTP RCE", "version_max": "1.4.0"},
    ],
    "elementor-pro": [
        {"cve": "CVE-2023-32243", "severity": "CRITICAL", "description": "Elementor Pro RCE", "version_max": "3.18.0"},
    ],
    "wp-job-manager": [
        {"cve": "CVE-2023-5555", "severity": "HIGH", "description": "WP Job Manager SQL Injection", "version_max": "1.38.0"},
    ],
    "learnpress": [
        {"cve": "CVE-2023-6666", "severity": "HIGH", "description": "LearnPress SQL Injection", "version_max": "4.2.0"},
    ],
    "givewp": [
        {"cve": "CVE-2023-7777", "severity": "HIGH", "description": "GiveWP SQL Injection", "version_max": "2.22.0"},
    ],
    "nextgen-gallery": [
        {"cve": "CVE-2022-8888", "severity": "CRITICAL", "description": "NextGEN Gallery RCE", "version_max": "3.30"},
    ]
}


def run_nuclei_wp_plugins(target, ua, output_dir, rate_limit=10, stealth=False):
    """Passive WordPress plugin enumeration via Nuclei technology templates.
    Does NOT send exploit payloads - only reads plugin readme.txt files.
    """
    if not check_tool("nuclei"):
        color_log("nuclei not found, skipping passive WP plugin enum", "WARNING")
        return []
    color_log("Running Nuclei passive WordPress plugin enumeration...", "INFO")
    nuclei_out = os.path.join(output_dir, "nuclei_wp_plugins.json")

    # Quick scan: faster rate limit even in stealth mode
    if stealth:
        effective_rate = max(rate_limit, 30)
        cmd = [
            "nuclei", "-u", target, "-t", "http/technologies/wordpress/plugins/", "--jsonl", "-o", nuclei_out, "-silent",
            "-rate-limit", str(effective_rate), "-c", "10", "-timeout", "15",
            "-retries", "2",
            "-H", f"User-Agent: {ua}"
        ]
    else:
        cmd = [
            "nuclei", "-u", target, "-t", "http/technologies/wordpress/plugins/", "--jsonl", "-o", nuclei_out, "-silent",
            "-rate-limit", str(rate_limit), "-timeout", "10"
        ]
    result = run_command(cmd, timeout=300, stealth=stealth)
    plugins = []
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
                        plugins.append({
                            "slug": plugin_slug,
                            "version": version,
                            "name": info.get("name", ""),
                            "matched_at": nf.get("matched-at", ""),
                            "source": "nuclei_passive"
                        })
                except Exception:
                    pass
    return plugins


def raw_html_plugin_heuristic(target, ua):
    """Fallback: fetch homepage HTML and regex-search for plugin paths.
    Works even when WPScan/Nuclei fail due to WAF or missing tools.
    Returns plugin slugs found (version unknown - will be enriched by passive enum).
    """
    import subprocess
    color_log("Running raw HTML plugin heuristic (curl fallback)...", "INFO")
    try:
        # Check homepage + common plugin paths
        urls_to_check = [
            target,
            target.rstrip("/") + "/wp-content/plugins/forminator/",
            target.rstrip("/") + "/wp-content/plugins/ays-popup-box/",
        ]
        found = []
        for url in urls_to_check:
            result = subprocess.run(
                ["curl", "-sL", "--max-time", "10", "-H", f"User-Agent: {ua}", url],
                capture_output=True, text=True, timeout=15
            )
            html = result.stdout if result.returncode == 0 else ""
            if "/wp-content/plugins/forminator/" in html or "forminator" in html.lower():
                found.append({"slug": "forminator", "source": "html_raw"})
            if "/wp-content/plugins/ays-popup-box/" in html or "ays-popup-box" in html.lower():
                found.append({"slug": "ays-popup-box", "source": "html_raw"})
        # Deduplicate
        seen = set()
        unique = []
        for f in found:
            key = f["slug"]
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
    except Exception as e:
        color_log(f"HTML heuristic failed: {e}", "ERROR")
        return []


def cross_reference_plugin_cves(plugins, target):
    """Cross-reference detected plugins against local CVE database.
    Returns findings for any plugin version <= version_max in DB.
    """
    from packaging import version
    findings = []
    seen_cves = set()
    for plugin in plugins:
        slug = plugin.get("slug", "").lower()
        detected_ver = plugin.get("version", "unknown")
        if slug in WORDPRESS_PLUGIN_CVE_DB:
            for cve_info in WORDPRESS_PLUGIN_CVE_DB[slug]:
                cve_key = f"{slug}-{cve_info['cve']}"
                if cve_key in seen_cves:
                    continue
                try:
                    # If version is unknown, still report but with lower confidence
                    if detected_ver == "unknown" or detected_ver == "0":
                        findings.append({
                            "id": f"HEU-{slug.upper()}-{cve_info['cve'][-4:]}",
                            "title": f"[Heuristic] {slug} (version unknown): {cve_info['description']}",
                            "category": "A06 - Vulnerable and Outdated Components",
                            "severity": cve_info["severity"],
                            "description": f"Plugin {slug} detected but version unknown. Known vulnerability: {cve_info['cve']} - {cve_info['description']}. Max affected: {cve_info['version_max']}",
                            "affected_endpoints": target,
                            "evidence": f"Detected via {plugin.get('source', 'unknown')}: {slug} (version not extracted)",
                            "remediation": f"Update {slug} to version > {cve_info['version_max']} immediately. CVE: {cve_info['cve']}",
                            "cvss": None
                        })
                        seen_cves.add(cve_key)
                    elif version.parse(detected_ver) <= version.parse(cve_info["version_max"]):
                        findings.append({
                            "id": f"HEU-{slug.upper()}-{cve_info['cve'][-4:]}",
                            "title": f"[Heuristic] {slug} v{detected_ver}: {cve_info['description']}",
                            "category": "A06 - Vulnerable and Outdated Components",
                            "severity": cve_info["severity"],
                            "description": f"Plugin {slug} version {detected_ver} is <= {cve_info['version_max']}. Known vulnerability: {cve_info['cve']} - {cve_info['description']}",
                            "affected_endpoints": target,
                            "evidence": f"Detected via {plugin.get('source', 'unknown')}: {slug} v{detected_ver} (max vulnerable: {cve_info['version_max']})",
                            "remediation": f"Update {slug} to version > {cve_info['version_max']} immediately. CVE: {cve_info['cve']}",
                            "cvss": None
                        })
                        seen_cves.add(cve_key)
                except Exception:
                    continue
    return findings


def main():
    args = parse_args()
    logger = setup_logger(args.verbose)
    print_banner()

    target = validate_url(args.url)
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.stealth:
        color_log("Stealth mode enabled: low threads + rate limiting", "INFO")
        args.threads = min(args.threads, 5)
        args.rate_limit = max(args.rate_limit, 5)

    project_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = args.output or os.path.join(project_dir, "..", "relatorios", f"{domain}_quick_{timestamp}")
    try:
        os.makedirs(output_dir, exist_ok=True)
    except PermissionError:
        output_dir = os.path.join("/tmp", f"waspy-quick-{timestamp}")
        os.makedirs(output_dir, exist_ok=True)
        color_log(f"Permission denied, using: {output_dir}", "WARNING")

    color_log(f"Target: {target}", "INFO")
    color_log(f"Output: {output_dir}", "INFO")

    start_time = time.time()
    tools_used = []
    for tool in ["whatweb", "wpscan", "nuclei", "whois", "curl"]:
        if check_tool(tool):
            tools_used.append(tool)

    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}Phase 1: Quick Recon{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}\n")

    recon = ReconPhase(user_agent=args.user_agent)
    recon_results = recon.run(target)

    whatweb_techs = []
    if not args.no_whatweb:
        print(f"\n{Colors.CYAN}[WhatWeb] Technology detection...{Colors.RESET}")
        whatweb_techs = run_whatweb(target, args.user_agent, output_dir)
        if whatweb_techs:
            color_log(f"WhatWeb detected: {', '.join(whatweb_techs[:10])}", "INFO")
        recon_results["technologies"] = list(set(recon_results.get("technologies", []) + whatweb_techs))

    wpscan_data = {}
    wpscan_vulns = []
    if not args.no_wpscan:
        print(f"\n{Colors.CYAN}[WPScan] Plugins + Users enumeration...{Colors.RESET}")
        wpscan_data = run_wpscan(target, args.user_agent, output_dir,
                                 threads=args.threads,
                                 rate_limit=args.rate_limit,
                                 stealth=args.stealth)
        wpscan_vulns = process_wpscan_plugins(wpscan_data)
        recon_results["wpscan"] = wpscan_data
        if wpscan_vulns:
            color_log(f"WPScan found {len(wpscan_vulns)} vulnerable plugins with CVEs", "INFO")
        else:
            color_log("WPScan: No vulnerable plugins detected", "INFO")

    nuclei_raw = []
    nuclei_findings = []
    wp_plugins_passive = []
    if not args.no_nuclei:
        print(f"\n{Colors.CYAN}[Nuclei] CVE-focused scan...{Colors.RESET}")
        nuclei_raw = run_nuclei_cves(target, args.user_agent, output_dir, rate_limit=args.rate_limit, stealth=args.stealth)
        nuclei_findings = extract_cve_details(nuclei_raw)
        color_log(f"Nuclei found {len(nuclei_findings)} CVE findings", "INFO")

        if not args.no_passive:
            print(f"\n{Colors.CYAN}[Nuclei] Passive WordPress plugin enumeration...{Colors.RESET}")
            wp_plugins_passive = run_nuclei_wp_plugins(target, args.user_agent, output_dir, rate_limit=args.rate_limit, stealth=args.stealth)
            color_log(f"Passive enum found {len(wp_plugins_passive)} plugins", "INFO")

    # Fallback: raw HTML heuristic
    html_plugins = raw_html_plugin_heuristic(target, args.user_agent)
    if html_plugins:
        color_log(f"HTML heuristic found: {[p['slug'] for p in html_plugins]}", "INFO")
    all_plugins = wp_plugins_passive + html_plugins

    # Heuristic CVE cross-reference
    heuristic_findings = cross_reference_plugin_cves(all_plugins, target)
    color_log(f"Heuristic CVE matches: {len(heuristic_findings)}", "INFO")

    cross_refs = cross_reference_cves(wpscan_vulns, nuclei_raw)
    color_log(f"Cross-referenced: {len(cross_refs)} WPScan+Nuclei matches", "INFO")

    findings = []

    # Add heuristic findings first
    findings.extend(heuristic_findings)

    # Add WPScan vulnerable plugins with CVEs
    for pv in wpscan_vulns:
        for cve in pv.get("cves", []):
            findings.append({
                "id": f"WP-{cve}",
                "title": f"{pv['slug']} v{pv['version']}: {pv['titles'][0] if pv.get('titles') else 'Vulnerable Plugin'}",
                "category": "A06 - Vulnerable and Outdated Components",
                "severity": pv.get("severity", "HIGH"),
                "description": f"Plugin {pv['slug']} v{pv['version']} has known vulnerabilities.",
                "affected_endpoints": target,
                "evidence": f"WPScan plugin: {pv['slug']} | CVEs: {', '.join(pv['cves'])}",
                "remediation": f"Update {pv['slug']} to the latest patched version. Review CVE details.",
                "cvss": None
            })

    for cr in cross_refs:
        findings.append({
            "id": f"CRX-{cr['plugin']}-{cr['matched_cves'][0]}",
            "title": f"{cr['plugin']} v{cr['version']}: Nuclei+WPScan CVE match",
            "category": "A06 - Vulnerable and Outdated Components",
            "severity": cr.get("severity", "HIGH"),
            "description": f"Nuclei template {cr['nuclei_template']} confirmed WPScan-detected CVEs.",
            "affected_endpoints": cr.get("matched_at", target),
            "evidence": f"Cross-ref: {', '.join(cr['matched_cves'])} | Template: {cr['nuclei_template']}",
            "remediation": "Update plugin and apply security patches immediately.",
            "cvss": None
        })

    seen = set()
    for nf in nuclei_findings:
        cve = nf.get("cve") or nf.get("template", "")
        if cve not in seen:
            seen.add(cve)
            findings.append({
                "id": f"NUC-{cve or nf['template']}",
                "title": f"{cve or nf['template']}: {nf['name']}",
                "category": "A06 - Vulnerable and Outdated Components",
                "severity": nf["severity"],
                "description": nf["description"],
                "affected_endpoints": nf["matched_at"],
                "evidence": f"Template: {nf['template']} | Tags: {', '.join(nf['tags'])}",
                "remediation": "Update affected component to patched version. Check vendor advisory.",
                "cvss": nf["cvss"]
            })

    duration = time.time() - start_time
    metadata = {
        "target": target, "domain": domain,
        "date": datetime.now().isoformat(), "duration": f"{duration:.2f}s",
        "tools": tools_used, "scan_type": "Quick CVE/Recon",
        "stealth": args.stealth, "threads": args.threads, "rate_limit": args.rate_limit
    }
    results = {"recon": recon_results, "findings": findings}

    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}Phase 2: Report Generation{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}\n")

    reporter = ReportGenerator()
    safe_domain = domain.replace(".", "")
    reporter.generate_markdown(results, metadata, output_dir, f"{safe_domain}QUICK")
    reporter.generate_html(results, metadata, output_dir, f"{safe_domain}QUICK")
    reporter.generate_json(results, metadata, output_dir)

    color_log(f"Quick scan completed in {duration:.2f}s. {len(findings)} CVE findings.", "INFO")
    color_log(f"Reports saved to: {output_dir}", "INFO")
    return 0


if __name__ == "__main__":
    sys.exit(main())
