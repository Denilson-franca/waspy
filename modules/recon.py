import os
import re
import json
import socket
import requests
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from utils import run_command, color_log, check_tool


class ReconPhase:
    def __init__(self, user_agent: str = "Waspy/1.0") -> None:
        self.user_agent = user_agent
        self.commands_run: List[str] = []

    def _log_cmd(self, cmd: str) -> None:
        self.commands_run.append(cmd)

    def enumerate_subdomains(self, domain: str) -> List[str]:
        subdomains: List[str] = []

        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"User-Agent": self.user_agent},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip()
                        if sub and sub.endswith(domain):
                            subdomains.append(sub)
        except Exception as e:
            color_log(f"crt.sh lookup failed: {e}", "WARNING")

        if not subdomains:
            if check_tool("subfinder"):
                self._log_cmd(f"subfinder -d {domain} -silent")
                result = run_command(["subfinder", "-d", domain, "-silent"])
                if result and result.stdout:
                    subdomains = [s.strip() for s in result.stdout.splitlines() if s.strip()]
            elif check_tool("amass"):
                self._log_cmd(f"amass enum -d {domain}")
                result = run_command(["amass", "enum", "-d", domain])
                if result and result.stdout:
                    subdomains = [s.strip() for s in result.stdout.splitlines() if s.strip()]

        return list(set(subdomains))

    def scan_ports(self, target: str) -> List[Dict[str, str]]:
        open_ports: List[Dict[str, str]] = []
        xml_path = "/tmp/ghost_gear_nmap.xml"

        if check_tool("nmap"):
            self._log_cmd(f"nmap -sV -T4 -F {target} -oX {xml_path}")
            result = run_command(["nmap", "-sV", "-T4", "-F", target, "-oX", xml_path])
            if result and os.path.exists(xml_path):
                try:
                    tree = ET.parse(xml_path)
                    root = tree.getroot()
                    for port in root.iter("port"):
                        port_num = port.get("portid", "")
                        protocol = port.get("protocol", "tcp")
                        state_el = port.find("state")
                        if state_el is not None and state_el.get("state") == "open":
                            service_el = port.find("service")
                            service = service_el.get("name", "") if service_el is not None else ""
                            open_ports.append(
                                {
                                    "port": int(port_num),
                                    "protocol": protocol,
                                    "service": service,
                                }
                            )
                except Exception as e:
                    color_log(f"nmap XML parsing failed: {e}", "WARNING")
        else:
            color_log("nmap not found, skipping port scan", "WARNING")

        return open_ports

    def detect_technologies(self, url: str) -> List[str]:
        technologies: List[str] = []

        if check_tool("whatweb"):
            self._log_cmd(f"whatweb --no-errors {url}")
            result = run_command(["whatweb", "--no-errors", url])
            if result and result.stdout:
                technologies = [t.strip() for t in result.stdout.split(",") if t.strip()][:20]

        if not technologies and check_tool("httpx"):
            self._log_cmd(f"httpx -u {url} -json")
            result = run_command(["httpx", "-u", url, "-json"])
            if result and result.stdout:
                try:
                    data = json.loads(result.stdout)
                    if isinstance(data, dict):
                        technologies = data.get("technologies", [])
                except Exception:
                    pass

        return technologies

    def gather_dns(self, domain: str) -> Dict[str, List[str]]:
        dns: Dict[str, List[str]] = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "SOA": []}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]
        for rtype in record_types:
            self._log_cmd(f"dig +short {rtype} {domain}")
            result = run_command(["dig", "+short", rtype, domain])
            if result and result.stdout:
                dns[rtype] = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return dns

    def run_whois(self, domain: str) -> str:
        if not check_tool("whois"):
            color_log("whois not found, skipping.", "WARNING")
            return ""
        self._log_cmd(f"whois {domain}")
        result = run_command(["whois", domain], timeout=30)
        if result and result.stdout:
            return result.stdout
        return ""

    def check_http_headers(self, url: str) -> Dict[str, List[str]]:
        headers: Dict[str, List[str]] = {"missing": [], "present": [], "raw": []}
        try:
            resp = requests.get(url, headers={"User-Agent": self.user_agent}, timeout=10, allow_redirects=True)
            headers["raw"] = [f"{k}: {v}" for k, v in resp.headers.items()]
            required = [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "X-XSS-Protection",
                "X-Powered-By",
                "Server",
            ]
            present_keys = [k.lower() for k in resp.headers.keys()]
            for h in required:
                if h.lower() in present_keys:
                    headers["present"].append(h)
                else:
                    headers["missing"].append(h)
        except Exception as e:
            color_log(f"Header check failed: {e}", "WARNING")
        return headers

    def get_page_title(self, url: str) -> Optional[str]:
        try:
            resp = requests.get(url, headers={"User-Agent": self.user_agent}, timeout=10, allow_redirects=True)
            if resp.status_code == 200:
                match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                if match:
                    return match.group(1).strip()
        except Exception as e:
            color_log(f"Failed to get page title: {e}", "WARNING")
        return None

    def run(self, url: str) -> Dict[str, Any]:
        from utils import validate_url

        url = validate_url(url)
        parsed = urlparse(url)
        domain = parsed.netloc

        color_log(f"Starting reconnaissance on {url}", "INFO")

        subdomains = self.enumerate_subdomains(domain)
        color_log(f"Found {len(subdomains)} subdomains", "INFO")

        open_ports = self.scan_ports(domain)
        color_log(f"Found {len(open_ports)} open ports", "INFO")

        technologies = self.detect_technologies(url)
        color_log(f"Detected {len(technologies)} technologies", "INFO")

        dns = self.gather_dns(domain)
        color_log("DNS records gathered", "INFO")

        whois = self.run_whois(domain)
        color_log("WHOIS lookup completed", "INFO")

        http_headers = self.check_http_headers(url)
        color_log(f"Security headers checked: {len(http_headers['missing'])} missing", "INFO")

        page_title = self.get_page_title(url)
        color_log(f"Page title: {page_title}", "INFO")

        return {
            "target": url,
            "subdomains": subdomains,
            "open_ports": open_ports,
            "technologies": technologies,
            "dns": dns,
            "whois": whois,
            "http_headers": http_headers,
            "page_title": page_title,
            "commands_run": self.commands_run,
        }
