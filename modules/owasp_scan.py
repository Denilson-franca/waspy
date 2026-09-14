import os
import json
import re
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

from utils import run_command, validate_url, color_log, check_tool, require_tool

class OWASPScanner:
    def __init__(self, user_agent: str = "GhostGear/1.0", skip_nuclei: bool = False, skip_sqlmap: bool = False, stealth: bool = False):
        self.user_agent = user_agent
        self.skip_nuclei = skip_nuclei
        self.skip_sqlmap = skip_sqlmap
        self.stealth = stealth
        self.findings: List[Dict] = []
        self.commands_run: List[str] = []

    def _log_cmd(self, cmd: str) -> None:
        self.commands_run.append(cmd)

    def _add_finding(self, finding_id: str, title: str, category: str, severity: str,
                     description: str, request: str = "", response: str = "", remediation: str = "") -> None:
        self.findings.append({
            "id": finding_id,
            "title": title,
            "category": category,
            "severity": severity,
            "description": description,
            "request": request,
            "response": response,
            "remediation": remediation
        })

    def _check_broken_access_control(self, url: str) -> None:
        paths = ["/admin", "/dashboard", "/config", "/backup", "/.env", "/api/v1/users"]
        for path in paths:
            full_url = urljoin(url, path)
            try:
                resp = requests.get(full_url, headers={"User-Agent": self.user_agent}, timeout=5, allow_redirects=False)
                if resp.status_code in [200, 301, 302, 403]:
                    severity = "HIGH" if resp.status_code == 200 else "MEDIUM"
                    self._add_finding(
                        f"A01-{len(self.findings)+1:03d}",
                        f"Unauthenticated access to sensitive path: {path}",
                        "A01:2021-Broken Access Control",
                        severity,
                        f"Path {path} returned status {resp.status_code}. Potential broken access control.",
                        request=f"GET {full_url}",
                        response=f"Status: {resp.status_code}\nSize: {len(resp.content)}",
                        remediation="Implement proper authentication and authorization checks."
                    )
            except Exception:
                pass
        parsed = urlparse(url)
        for param in ["user_id", "id", "uid", "account"]:
            test_url = f"{url}?{param}=1"
            test_url2 = f"{url}?{param}=2"
            try:
                r1 = requests.get(test_url, headers={"User-Agent": self.user_agent}, timeout=5)
                r2 = requests.get(test_url2, headers={"User-Agent": self.user_agent}, timeout=5)
                if r1.status_code == 200 and r2.status_code == 200 and r1.text != r2.text:
                    self._add_finding(
                        f"A01-{len(self.findings)+1:03d}",
                        f"Potential IDOR on parameter {param}",
                        "A01:2021-Broken Access Control",
                        "HIGH",
                        f"Different responses observed for {param}=1 and {param}=2",
                        request=f"GET {test_url} vs {test_url2}",
                        remediation="Implement object-level authorization checks."
                    )
                    break
            except Exception:
                pass

    def _check_crypto_failures(self, target: str) -> None:
        parsed = urlparse(validate_url(target))
        host = parsed.netloc
        if parsed.scheme != "https":
            self._add_finding(
                f"A02-{len(self.findings)+1:03d}",
                "No HTTPS detected",
                "A02:2021-Cryptographic Failures",
                "HIGH",
                "Target does not enforce HTTPS. Data may be transmitted in plaintext.",
                remediation="Enable HTTPS with TLS 1.2 or higher."
            )
        if check_tool("testssl.sh"):
            self._log_cmd(f"testssl.sh --fast {host}")
            result = run_command(["testssl.sh", "--fast", host], timeout=120)
            if result and result.stdout:
                weak = [l for l in result.stdout.splitlines() if "weak" in l.lower() or "vulnerable" in l.lower()]
                if weak:
                    self._add_finding(
                        f"A02-{len(self.findings)+1:03d}",
                        "Weak SSL/TLS configuration detected",
                        "A02:2021-Cryptographic Failures",
                        "HIGH",
                        "\n".join(weak[:5]),
                        remediation="Disable weak ciphers and protocols. Use TLS 1.2+."
                    )
        elif check_tool("sslyze"):
            self._log_cmd(f"sslyze {host}")
            run_command(["sslyze", host], timeout=120)

    def _check_injection(self, url: str) -> None:
        xss_payloads = ["<script>alert(1)</script>", "\"><script>alert(1)</script>", "javascript:alert(1)"]
        sqli_payloads = ["' OR '1'='1", "\" OR \"1\"=\"1", "' UNION SELECT NULL--"]
        lfi_payloads = ["../../../../etc/passwd", "....//....//....//etc/passwd", "/etc/passwd"]

        for payload in xss_payloads:
            test_url = f"{url}?q={payload}"
            try:
                resp = requests.get(test_url, headers={"User-Agent": self.user_agent}, timeout=5)
                if payload in resp.text:
                    self._add_finding(
                        f"A03-{len(self.findings)+1:03d}",
                        "Reflected XSS detected",
                        "A03:2021-Injection",
                        "HIGH",
                        f"Payload reflected in response: {payload}",
                        request=f"GET {test_url}",
                        remediation="Sanitize all user input and implement output encoding."
                    )
                    break
            except Exception:
                pass

        for payload in sqli_payloads:
            test_url = f"{url}?id={payload}"
            try:
                resp = requests.get(test_url, headers={"User-Agent": self.user_agent}, timeout=5)
                if any(err in resp.text.lower() for err in ["sql syntax", "mysql_fetch", "ora-", "syntax error"]):
                    self._add_finding(
                        f"A03-{len(self.findings)+1:03d}",
                        "SQL Injection detected",
                        "A03:2021-Injection",
                        "CRITICAL",
                        f"SQL error in response for payload: {payload}",
                        request=f"GET {test_url}",
                        remediation="Use parameterized queries and ORM."
                    )
                    break
            except Exception:
                pass

        if not self.skip_sqlmap and check_tool("sqlmap"):
            self._log_cmd(f"sqlmap -u {url} --batch --level=3 --risk=2 --random-agent")
            result = run_command([
                "sqlmap", "-u", url, "--batch", "--level=3", "--risk=2",
                "--random-agent", f"--user-agent={self.user_agent}", "--timeout=30"
            ], timeout=300)
            if result and result.stdout and "sqlmap identified" in result.stdout.lower():
                self._add_finding(
                    f"A03-{len(self.findings)+1:03d}",
                    "SQL Injection detected via sqlmap",
                    "A03:2021-Injection",
                    "CRITICAL",
                    "sqlmap reported injection vulnerabilities.",
                    remediation="Use parameterized queries and ORM."
                )

        for payload in lfi_payloads:
            test_url = f"{url}?file={payload}"
            try:
                resp = requests.get(test_url, headers={"User-Agent": self.user_agent}, timeout=5)
                if "root:" in resp.text or "daemon:" in resp.text:
                    self._add_finding(
                        f"A03-{len(self.findings)+1:03d}",
                        "Local File Inclusion detected",
                        "A03:2021-Injection",
                        "HIGH",
                        f"File contents exposed via LFI: {payload}",
                        request=f"GET {test_url}",
                        remediation="Validate and sanitize file paths. Use allowlists."
                    )
                    break
            except Exception:
                pass

    def _check_insecure_design(self, url: str) -> None:
        debug_paths = ["/debug", "/console", "/actuator", "/swagger", "/api/docs", "/graphql"]
        for path in debug_paths:
            full_url = urljoin(url, path)
            try:
                resp = requests.get(full_url, headers={"User-Agent": self.user_agent}, timeout=5, allow_redirects=False)
                if resp.status_code == 200:
                    self._add_finding(
                        f"A04-{len(self.findings)+1:03d}",
                        f"Debug/API documentation endpoint exposed: {path}",
                        "A04:2021-Insecure Design",
                        "MEDIUM",
                        f"Endpoint {path} is publicly accessible and may expose sensitive information.",
                        request=f"GET {full_url}",
                        remediation="Restrict debug endpoints to internal networks or authenticated users."
                    )
                    break
            except Exception:
                pass

        try:
            robots_url = urljoin(url, "/robots.txt")
            resp = requests.get(robots_url, headers={"User-Agent": self.user_agent}, timeout=5)
            if resp.status_code == 200 and resp.text:
                disallowed = [l.strip() for l in resp.text.splitlines() if l.lower().startswith("disallow")]
                if disallowed:
                    self._add_finding(
                        f"A04-{len(self.findings)+1:03d}",
                        "Sensitive paths disclosed in robots.txt",
                        "A04:2021-Insecure Design",
                        "LOW",
                        f"Found {len(disallowed)} disallowed paths in robots.txt",
                        request=f"GET {robots_url}",
                        remediation="Avoid exposing sensitive paths in robots.txt."
                    )
        except Exception:
            pass

    def _check_security_misconfiguration(self, url: str) -> None:
        if check_tool("nikto"):
            self._log_cmd(f"nikto -h {url} -C all -Format txt -output /tmp/nikto.txt")
            result = run_command(["nikto", "-h", url, "-C", "all", "-Format", "txt", "-output", "/tmp/nikto.txt"], timeout=300)
            if result and os.path.exists("/tmp/nikto.txt"):
                try:
                    with open("/tmp/nikto.txt", "r") as f:
                        lines = f.readlines()
                        issues = [l.strip() for l in lines if l.startswith("+")]
                        if issues:
                            self._add_finding(
                                f"A05-{len(self.findings)+1:03d}",
                                "Security misconfigurations detected by Nikto",
                                "A05:2021-Security Misconfiguration",
                                "HIGH",
                                "\n".join(issues[:10]),
                                remediation="Patch identified misconfigurations and apply security best practices."
                            )
                except Exception:
                    pass

        try:
            resp = requests.get(url, headers={"User-Agent": self.user_agent}, timeout=10)
            server = resp.headers.get("Server", "")
            if server:
                self._add_finding(
                    f"A05-{len(self.findings)+1:03d}",
                    "Server token exposed",
                    "A05:2021-Security Misconfiguration",
                    "LOW",
                    f"Server header reveals: {server}",
                    request=f"GET {url}",
                    remediation="Configure server to suppress version tokens."
                )
            x_powered = resp.headers.get("X-Powered-By", "")
            if x_powered:
                self._add_finding(
                    f"A05-{len(self.findings)+1:03d}",
                    "X-Powered-By header exposed",
                    "A05:2021-Security Misconfiguration",
                    "LOW",
                    f"X-Powered-By: {x_powered}",
                    remediation="Remove X-Powered-By header."
                )
        except Exception:
            pass

    def _check_vulnerable_components(self, url: str) -> None:
        if check_tool("whatweb"):
            self._log_cmd(f"whatweb --no-errors {url}")
            result = run_command(["whatweb", "--no-errors", url])
            if result and result.stdout:
                versions = re.findall(r'([A-Za-z0-9\-]+)\s+\[?([0-9]+\.[0-9]+[^\s\]]*)\]?', result.stdout)
                if versions:
                    self._add_finding(
                        f"A06-{len(self.findings)+1:03d}",
                        "Component versions detected",
                        "A06:2021-Vulnerable and Outdated Components",
                        "MEDIUM",
                        f"Detected versions: {', '.join([f'{v[0]} {v[1]}' for v in versions[:10]])}",
                        remediation="Update components to latest secure versions and monitor CVEs."
                    )

        if not self.skip_nuclei and check_tool("nuclei"):
            if self.stealth:
                cmd = ["nuclei", "-u", url,
                       "-t", "cves/", "-t", "vulnerabilities/",
                       "-silent", "-timeout", "15",
                       "-rate-limit", "30", "-c", "10",
                       "-retries", "2",
                       "-jsonl",
                       "-H", f"User-Agent: {self.user_agent}"]
            else:
                cmd = ["nuclei", "-u", url,
                       "-t", "cves/", "-t", "vulnerabilities/",
                       "-silent", "-timeout", "10",
                       "-rate-limit", "30", "-c", "20",
                       "-jsonl"]
            self._log_cmd(" ".join(cmd))
            result = run_command(cmd, timeout=120)
            if result and result.stdout:
                self._add_finding(
                    f"A06-{len(self.findings)+1:03d}",
                    "Nuclei detected potential component vulnerabilities",
                    "A06:2021-Vulnerable and Outdated Components",
                    "MEDIUM",
                    result.stdout[:500],
                    remediation="Review and patch identified vulnerabilities."
                )

    def _check_auth_failures(self, url: str) -> None:
        login_paths = ["/login", "/signin", "/auth", "/wp-login.php", "/admin/login"]
        for path in login_paths:
            full_url = urljoin(url, path)
            try:
                resp = requests.get(full_url, headers={"User-Agent": self.user_agent}, timeout=5, allow_redirects=True)
                if resp.status_code == 200 and ("password" in resp.text.lower() or "login" in resp.text.lower()):
                    cookies = resp.cookies
                    session_cookie = any("session" in c.name.lower() or "auth" in c.name.lower() for c in cookies)
                    if not session_cookie:
                        self._add_finding(
                            f"A07-{len(self.findings)+1:03d}",
                            f"Login form found without secure session cookie at {path}",
                            "A07:2021-Identification and Authentication Failures",
                            "MEDIUM",
                            f"Login page at {path} does not appear to set secure session cookies.",
                            request=f"GET {full_url}",
                            remediation="Ensure session cookies are HttpOnly, Secure, and SameSite."
                        )
                    else:
                        self._add_finding(
                            f"A07-{len(self.findings)+1:03d}",
                            f"Login form detected at {path}",
                            "A07:2021-Identification and Authentication Failures",
                            "INFO",
                            f"Login page found. Verify brute-force protection and credential policies.",
                            request=f"GET {full_url}",
                            remediation="Implement rate limiting, account lockout, and strong password policies."
                        )
                    break
            except Exception:
                pass

    def _check_data_integrity(self, url: str) -> None:
        jwt_paths = ["/api/token", "/auth", "/login", "/.well-known/jwks.json"]
        for path in jwt_paths:
            full_url = urljoin(url, path)
            try:
                resp = requests.post(full_url, json={"username": "test", "password": "test"}, headers={"User-Agent": self.user_agent}, timeout=5)
                auth_header = resp.headers.get("Authorization", "")
                if "bearer " in auth_header.lower():
                    token = auth_header.split(" ", 1)[1] if " " in auth_header else auth_header
                    if token.count(".") == 2:
                        self._add_finding(
                            f"A08-{len(self.findings)+1:03d}",
                            "JWT token issued - verify signing and claims",
                            "A08:2021-Software and Data Integrity Failures",
                            "INFO",
                            "JWT token detected in Authorization header. Ensure strong signing algorithm and secret.",
                            request=f"POST {full_url}",
                            remediation="Use RS256 or ES256. Verify claims and expiration."
                        )
                    break
            except Exception:
                pass

    def _check_logging_failures(self, url: str) -> None:
        error_test = f"{url}?error=test"
        try:
            resp = requests.get(error_test, headers={"User-Agent": self.user_agent}, timeout=5)
            if any(ind in resp.text.lower() for ind in ["stack trace", "traceback", "exception", "error in", "warning:"]):
                self._add_finding(
                    f"A09-{len(self.findings)+1:03d}",
                    "Detailed error messages exposed",
                    "A09:2021-Security Logging and Monitoring Failures",
                    "MEDIUM",
                    "Application exposes detailed error messages that may leak sensitive information.",
                    request=f"GET {error_test}",
                    remediation="Implement generic error pages and log errors securely server-side."
                )
        except Exception:
            pass

    def _check_ssrf(self, url: str) -> None:
        ssrf_payloads = [
            "http://127.0.0.1:80",
            "http://localhost:8080",
            "file:///etc/passwd",
            "gopher://127.0.0.1:25"
        ]
        for payload in ssrf_payloads:
            test_url = f"{url}?url={payload}"
            try:
                resp = requests.get(test_url, headers={"User-Agent": self.user_agent}, timeout=5, allow_redirects=False)
                if resp.status_code in [200, 301, 302] and any(k in resp.text.lower() for k in ["root:", "apache", "it works"]):
                    self._add_finding(
                        f"A10-{len(self.findings)+1:03d}",
                        "Potential SSRF vulnerability",
                        "A10:2021-Server-Side Request Forgery",
                        "HIGH",
                        f"SSRF payload caused internal response: {payload}",
                        request=f"GET {test_url}",
                        remediation="Validate and sanitize all user-supplied URLs. Use allowlists."
                    )
                    break
            except Exception:
                pass

    def run(self, url: str, output_dir: str) -> List[Dict]:
        target = validate_url(url)
        color_log("Starting OWASP Top 10 (2021) scan", "INFO")

        self._check_broken_access_control(target)
        self._check_crypto_failures(target)
        self._check_injection(target)
        self._check_insecure_design(target)
        self._check_security_misconfiguration(target)
        self._check_vulnerable_components(target)
        self._check_auth_failures(target)
        self._check_data_integrity(target)
        self._check_logging_failures(target)
        self._check_ssrf(target)

        color_log(f"OWASP scan complete. Found {len(self.findings)} issues.", "INFO")
        return self.findings
