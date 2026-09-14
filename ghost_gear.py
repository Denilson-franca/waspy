#!/usr/bin/env python3
import argparse
import os
import sys
import time
from datetime import datetime
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.utils import Colors, print_banner, color_log, setup_logger, check_tool, require_tool, validate_url
from modules.recon import ReconPhase
from modules.owasp_scan import OWASPScanner
from modules.reporter import ReportGenerator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Waspy - Advanced Pentest Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default=None, help="Output directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--threads", type=int, default=50, help="Concurrent threads")
    parser.add_argument("--wordlist", default=None, help="Custom directory wordlist")
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip nuclei scanning")
    parser.add_argument("--skip-sqlmap", action="store_true", help="Skip SQLi scanning")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    parser.add_argument("--html", action="store_true", help="Output HTML report")
    parser.add_argument("--quick", action="store_true", help="Fast mode (limited wordlists)")
    parser.add_argument("--user-agent", default="Waspy/1.0", help="Custom User-Agent")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode for WAF evasion (rate limiting, custom UA, retries)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logger = setup_logger(args.verbose)

    print_banner()

    target = validate_url(args.url)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    project_dir = os.path.dirname(os.path.abspath(__file__))
    default_output = os.path.join(project_dir, "relatorios", f"{target.replace('https://', '').replace('http://', '').split('/')[0]}_{timestamp}")
    output_dir = args.output or default_output
    try:
        os.makedirs(output_dir, exist_ok=True)
    except PermissionError:
        output_dir = os.path.join("/tmp", f"waspy-results_{timestamp}")
        os.makedirs(output_dir, exist_ok=True)
        color_log(f"Permission denied on output dir, using: {output_dir}", "WARNING")

    color_log(f"Target: {target}", "INFO")
    color_log(f"Output: {output_dir}", "INFO")
    color_log(f"Threads: {args.threads}", "INFO")

    start_time = time.time()

    tools_used = []
    for tool in ["subfinder", "nmap", "whatweb", "nikto", "sqlmap", "nuclei"]:
        if check_tool(tool):
            tools_used.append(tool)

    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}Phase 1: Reconnaissance{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}\n")

    recon = ReconPhase(user_agent=args.user_agent)
    recon_results = recon.run(target)

    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}Phase 2: OWASP Top 10 Scan{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}\n")

    scanner = OWASPScanner(
        user_agent=args.user_agent,
        skip_nuclei=args.skip_nuclei,
        skip_sqlmap=args.skip_sqlmap,
        stealth=args.stealth
    )
    findings = scanner.run(target, output_dir)

    duration = time.time() - start_time
    metadata = {
        "target": target,
        "date": datetime.now().isoformat(),
        "duration": f"{duration:.2f}s",
        "tools": tools_used
    }

    results = {
        "recon": recon_results,
        "findings": findings
    }

    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}Phase 3: Report Generation{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}\n")

    reporter = ReportGenerator()
    reporter.add_command_log(recon_results.get("commands_run", []) + scanner.commands_run)

    reporter.generate_markdown(results, metadata, output_dir)

    if args.html:
        reporter.generate_html(results, metadata, output_dir)
    if args.json:
        reporter.generate_json(results, metadata, output_dir)

    color_log(f"Scan completed in {duration:.2f}s. {len(findings)} findings.", "INFO")
    color_log(f"Reports saved to: {output_dir}", "INFO")

    return 0


if __name__ == "__main__":
    sys.exit(main())
