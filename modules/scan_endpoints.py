#!/usr/bin/env python3
"""Waspy - Endpoints & Design Flaws Scan Module"""
import argparse
import os
import sys
import time
import json
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import Colors, print_banner, color_log, setup_logger, check_tool, validate_url, run_command
from reporter import ReportGenerator


def parse_args():
    parser = argparse.ArgumentParser(description="Waspy - Endpoints/Design Flaws Scan")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default=None, help="Output directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--threads", type=int, default=50, help="Concurrent threads")
    parser.add_argument("--wordlist", default=None, help="Custom wordlist")
    parser.add_argument("--user-agent", default="Waspy/1.0", help="Custom User-Agent")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode (rate limiting)")
    return parser.parse_args()


def run_ffuf(target, ua, output_dir, wordlist):
    """Run ffuf for directory fuzzing."""
    if not check_tool("ffuf"):
        color_log("ffuf not found, trying gobuster...", "WARNING")
        return run_gobuster(target, ua, output_dir, wordlist)
    color_log("Running ffuf directory fuzzing...", "INFO")
    ffuf_out = os.path.join(output_dir, "ffuf.json")
    wl = wordlist or os.path.join(os.path.dirname(__file__), "..", "wordlists", "dirs.txt")
    cmd = ["ffuf", "-u", f"{target}/FUZZ", "-w", wl, "-of", "json", "-o", ffuf_out,
           "-H", f"User-Agent: {ua}", "-t", "50", "-fc", "404", "-mc", "200,301,302,403,500"]
    result = run_command(cmd, timeout=300)
    if result and os.path.exists(ffuf_out):
        with open(ffuf_out) as f:
            data = json.load(f)
            return data.get("results", [])
    return []


def run_gobuster(target, ua, output_dir, wordlist):
    """Fallback to gobuster."""
    if not check_tool("gobuster"):
        return []
    color_log("Running gobuster directory fuzzing...", "INFO")
    gb_out = os.path.join(output_dir, "gobuster.txt")
    wl = wordlist or os.path.join(os.path.dirname(__file__), "..", "wordlists", "dirs.txt")
    cmd = ["gobuster", "dir", "-u", target, "-w", wl, "-o", gb_out,
           "-t", "50", "-a", ua, "-s", "200,301,302,403,500"]
    result = run_command(cmd, timeout=300)
    found = []
    if result and os.path.exists(gb_out):
        with open(gb_out) as f:
            for line in f:
                if line.startswith("/"):
                    parts = line.split()
                    if len(parts) >= 3:
                        found.append({"url": urljoin(target, parts[0]), "status": parts[2].strip("()")})
    return found


def fetch_robots_sitemap(target, ua):
    """Fetch and parse robots.txt and sitemap.xml."""
    results = {"robots": [], "sitemap": []}
    for path in ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml"]:
        full_url = urljoin(target, path)
        result = run_command(["curl", "-s", "-H", f"User-Agent: {ua}", full_url], timeout=10)
        if result and result.stdout and result.stdout.strip():
            if path.endswith(".xml"):
                urls = re.findall(r"<loc>(.*?)</loc>", result.stdout)
                results["sitemap"].extend(urls[:100])
            else:
                for line in result.stdout.splitlines():
                    if line.startswith(("Disallow:", "Allow:")):
                        results["robots"].append(line.strip())
    return results


def analyze_wp_api(target, ua):
    """Analyze WordPress REST API for user enumeration and IDOR."""
    endpoints = ["/wp-json/wp/v2/users", "/wp-json/wp/v2/posts", "/wp-json/wp/v2/pages",
                 "/wp-json/wp/v2/comments", "/wp-json/wp/v2/media"]
    findings = []
    for ep in endpoints:
        full_url = urljoin(target, ep)
        result = run_command(["curl", "-s", "-H", f"User-Agent: {ua}", full_url], timeout=10)
        if result and result.stdout:
            try:
                data = json.loads(result.stdout)
                if isinstance(data, list) and data:
                    if ep.endswith("/users"):
                        users = [{"id": u.get("id"), "name": u.get("name"), "slug": u.get("slug")}
                                 for u in data if u.get("id")]
                        if users:
                            findings.append({
                                "type": "user_enumeration",
                                "endpoint": full_url,
                                "users": users,
                                "severity": "MEDIUM",
                                "description": f"WordPress REST API expõe {len(users)} usuários sem autenticação"
                            })
                    elif ep.endswith(("/posts", "/pages", "/comments", "/media")):
                        findings.append({
                            "type": "api_exposure",
                            "endpoint": full_url,
                            "count": len(data),
                            "severity": "LOW",
                            "description": f"API expõe {len(data)} {ep.split('/')[-1]} publicamente"
                        })
            except json.JSONDecodeError:
                pass
    return findings


def analyze_generic_api(target, ua):
    """Analyze generic REST/GraphQL APIs."""
    findings = []
    api_endpoints = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/rest", "/rest/v1", "/graphql", "/graphiql",
        "/swagger.json", "/openapi.json", "/api-docs",
        "/.well-known/jwks.json", "/oauth/token", "/auth/token"
    ]
    for ep in api_endpoints:
        full_url = urljoin(target, ep)
        result = run_command(["curl", "-s", "-H", f"User-Agent: {ua}", "-H", "Accept: application/json", full_url], timeout=10)
        if result and result.stdout and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    # Check for OpenAPI/Swagger spec
                    if any(k in data for k in ["openapi", "swagger", "paths", "components"]):
                        findings.append({
                            "type": "api_docs_exposed",
                            "endpoint": full_url,
                            "severity": "HIGH",
                            "description": f"Documentação de API exposta (OpenAPI/Swagger): {ep}"
                        })
                    # Check for JWT JWKS
                    elif "keys" in data and ep.endswith("/jwks.json"):
                        findings.append({
                            "type": "jwks_exposed",
                            "endpoint": full_url,
                            "severity": "INFO",
                            "description": "JWKS endpoint exposto - chaves públicas de JWT acessíveis"
                        })
            except json.JSONDecodeError:
                pass
            
            # GraphQL introspection
            if ep in ["/graphql", "/graphiql"]:
                introspection_query = '{"query": "{__schema {types {name fields {name}}}}"}'
                result = run_command(["curl", "-s", "-X", "POST", "-H", f"User-Agent: {ua}",
                                     "-H", "Content-Type: application/json", "-d", introspection_query, full_url], timeout=10)
                if result and result.stdout and "__schema" in result.stdout:
                    findings.append({
                        "type": "graphql_introspection",
                        "endpoint": full_url,
                        "severity": "MEDIUM",
                        "description": "GraphQL introspection habilitado - esquema completo exposto"
                    })
    return findings


def check_sensitive_files(target, ua):
    """Check for sensitive files and backup files."""
    sensitive_paths = [
        "/.env", "/.env.production", "/.env.local", "/.env.backup",
        "/.git/config", "/.git/HEAD", "/.svn/entries",
        "/backup.zip", "/backup.tar.gz", "/backup.sql", "/dump.sql",
        "/config.php.bak", "/wp-config.php.bak", "/wp-config.php~",
        "/web.config.bak", "/.htaccess.bak", "/docker-compose.yml",
        "/docker-compose.override.yml", "/.dockerignore",
        "/phpinfo.php", "/info.php", "/test.php", "/server-status",
        "/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
        "/wp-config.php", "/configuration.php", "/config.json",
        "/.npmrc", "/.yarnrc", "/.pnpm-store", "/package-lock.json",
        "/composer.lock", "/Gemfile.lock", "/requirements.txt",
        "/.aws/credentials", "/.ssh/id_rsa", "/.ssh/authorized_keys"
    ]
    findings = []
    for path in sensitive_paths:
        full_url = urljoin(target, path)
        result = run_command(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                              "-H", f"User-Agent: {ua}", full_url], timeout=5)
        if result and result.stdout.strip() in ["200", "301", "302"]:
            severity = "HIGH" if any(x in path for x in [".env", ".git", "backup", "config", "credential", "id_rsa", "authorized_keys"]) else "MEDIUM"
            findings.append({
                "type": "sensitive_file",
                "endpoint": full_url,
                "status": result.stdout.strip(),
                "severity": severity,
                "description": f"Arquivo sensível exposto: {path}"
            })
    return findings


def check_design_flaws(target, ua):
    """Check for design flaws: debug endpoints, API docs, etc."""
    debug_paths = ["/debug", "/console", "/actuator", "/actuator/env", "/actuator/health",
                   "/actuator/metrics", "/actuator/beans", "/actuator/mappings",
                   "/swagger.json", "/openapi.json", "/api-docs", "/api/swagger.json",
                   "/swagger-ui.html", "/swagger-ui/", "/redoc",
                   "/graphql", "/graphiql", "/playground", "/altair",
                   "/.well-known/security.txt", "/server-status", "/server-info",
                   "/h2-console", "/console/", "/adminer.php", "/phpmyadmin",
                   "/trace", "/metrics", "/prometheus", "/health", "/ready"]
    findings = []
    for path in debug_paths:
        full_url = urljoin(target, path)
        result = run_command(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                              "-H", f"User-Agent: {ua}", full_url], timeout=5)
        if result and result.stdout.strip() in ["200", "301", "302"]:
            severity = "HIGH" if any(x in path for x in ["actuator", "swagger", "graphql", "h2-console", "adminer", "phpmyadmin", "console"]) else "MEDIUM"
            findings.append({
                "type": "debug_endpoint",
                "endpoint": full_url,
                "status": result.stdout.strip(),
                "severity": severity,
                "description": f"Endpoint de debug/documentação exposto: {path}"
            })
    return findings


def test_idor_on_endpoints(target, ua, discovered_endpoints):
    """Test IDOR on endpoints with numeric IDs."""
    findings = []
    # Extract endpoints that look like they have IDs
    id_pattern = re.compile(r'.*/(\d+)(/|$)')
    tested = set()
    for ep in discovered_endpoints:
        url = ep.get("url", "") if isinstance(ep, dict) else ep
        match = id_pattern.match(url)
        if match and url not in tested:
            tested.add(url)
            original_id = match.group(1)
            # Try adjacent IDs
            for test_id in [str(int(original_id) - 1), str(int(original_id) + 1), "1", "2"]:
                if test_id == original_id:
                    continue
                test_url = url.replace(f"/{original_id}/", f"/{test_id}/").replace(f"/{original_id}", f"/{test_id}")
                result = run_command(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                                     "-H", f"User-Agent: {ua}", test_url], timeout=5)
                if result and result.stdout.strip() == "200":
                    findings.append({
                        "type": "idor",
                        "endpoint": test_url,
                        "original_endpoint": url,
                        "severity": "HIGH",
                        "description": f"Possível IDOR: acessou recurso ID {test_id} a partir de {original_id}"
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
    output_dir = args.output or os.path.join(project_dir, "..", "relatorios", f"{domain}_endpoints_{timestamp}")
    try:
        os.makedirs(output_dir, exist_ok=True)
    except PermissionError:
        output_dir = os.path.join("/tmp", f"waspy-endpoints-{timestamp}")
        os.makedirs(output_dir, exist_ok=True)
        color_log(f"Permission denied, using: {output_dir}", "WARNING")

    color_log(f"Target: {target}", "INFO")
    color_log(f"Output: {output_dir}", "INFO")

    start_time = time.time()
    tools_used = []
    for tool in ["ffuf", "gobuster", "curl", "jq", "whois"]:
        if check_tool(tool):
            tools_used.append(tool)

    all_findings = []
    discovered_endpoints = []

    # Phase 1: Directory Fuzzing
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}Phase 1: Directory Fuzzing (ffuf/gobuster){Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}\n")

    fuzz_results = run_ffuf(target, args.user_agent, output_dir, args.wordlist)
    for r in fuzz_results[:100]:
        ep_url = r.get('url', r.get('input', ''))
        discovered_endpoints.append({"url": ep_url, "status": r.get("status")})
        all_findings.append({
            "id": f"END-{len(all_findings)+1:03d}",
            "title": f"Diretório/Arquivo encontrado: {ep_url}",
            "category": "A01:2021-Broken Access Control - Exposed Endpoint",
            "severity": "MEDIUM" if str(r.get("status")) == "200" else "LOW",
            "description": f"Endpoint acessível retornando HTTP {r.get('status', 'N/A')}",
            "affected_endpoints": ep_url,
            "evidence": f"Status: {r.get('status')}, Length: {r.get('length', 'N/A')}",
            "remediation": "Restringir acesso a diretórios sensíveis. Remover arquivos de backup/teste."
        })

    # Phase 2: robots.txt & sitemap
    print(f"\n{Colors.CYAN}[Robots/Sitemap] Analisando...{Colors.RESET}")
    rs_data = fetch_robots_sitemap(target, args.user_agent)
    if rs_data["robots"]:
        all_findings.append({
            "id": f"END-{len(all_findings)+1:03d}",
            "title": "robots.txt expõe caminhos sensíveis",
            "category": "A04:2021-Insecure Design - Information Disclosure",
            "severity": "LOW",
            "description": f"robots.txt contém {len(rs_data['robots'])} entradas Disallow/Allow",
            "affected_endpoints": urljoin(target, "/robots.txt"),
            "evidence": "\n".join(rs_data["robots"][:20]),
            "remediation": "Não expor caminhos administrativos/sensíveis no robots.txt"
        })
    if rs_data["sitemap"]:
        for url in rs_data["sitemap"][:50]:
            discovered_endpoints.append({"url": url, "status": "200"})
        all_findings.append({
            "id": f"END-{len(all_findings)+1:03d}",
            "title": "sitemap.xml expõe estrutura completa",
            "category": "A04:2021-Insecure Design - Information Disclosure",
            "severity": "LOW",
            "description": f"sitemap.xml lista {len(rs_data['sitemap'])} URLs",
            "affected_endpoints": urljoin(target, "/sitemap.xml"),
            "evidence": "\n".join(rs_data["sitemap"][:20]),
            "remediation": "Restringir sitemap a crawlers autorizados ou remover URLs sensíveis"
        })

    # Phase 3: WP API Analysis
    print(f"\n{Colors.CYAN}[WP API] Analisando REST API WordPress...{Colors.RESET}")
    api_findings = analyze_wp_api(target, args.user_agent)
    for af in api_findings:
        all_findings.append({
            "id": f"END-{len(all_findings)+1:03d}",
            "title": af["description"],
            "category": "A01:2021-Broken Access Control - API / IDOR" if af["type"] == "user_enumeration" else "A03:2021-Injection - API Exposure",
            "severity": af["severity"],
            "description": af["description"],
            "affected_endpoints": af["endpoint"],
            "evidence": json.dumps(af.get("users", af.get("count", "")), indent=2),
            "remediation": "Restringir API REST a usuários autenticados. Desabilitar enumeração de usuários."
        })

    # Phase 3.5: Generic API Analysis
    print(f"\n{Colors.CYAN}[API] Analisando APIs genéricas (REST/GraphQL/OpenAPI)...{Colors.RESET}")
    generic_api_findings = analyze_generic_api(target, args.user_agent)
    for af in generic_api_findings:
        all_findings.append({
            "id": f"END-{len(all_findings)+1:03d}",
            "title": af["description"],
            "category": "A03:2021-Injection - API Exposure",
            "severity": af["severity"],
            "description": af["description"],
            "affected_endpoints": af["endpoint"],
            "evidence": f"Endpoint: {af['endpoint']}",
            "remediation": "Restringir acesso à documentação da API. Desabilitar introspecção GraphQL em produção."
        })

    # Phase 4: Sensitive Files
    print(f"\n{Colors.CYAN}[Files] Verificando arquivos sensíveis e backups...{Colors.RESET}")
    sensitive_findings = check_sensitive_files(target, args.user_agent)
    for sf in sensitive_findings:
        all_findings.append({
            "id": f"END-{len(all_findings)+1:03d}",
            "title": f"Arquivo sensível exposto: {sf['endpoint']}",
            "category": "A04:2021-Insecure Design - Information Disclosure",
            "severity": sf["severity"],
            "description": sf["description"],
            "affected_endpoints": sf["endpoint"],
            "evidence": f"HTTP {sf['status']}",
            "remediation": "Remover arquivos sensíveis do servidor web. Configurar .htaccess/nginx para bloquear acesso."
        })

    # Phase 5: Design Flaws
    print(f"\n{Colors.CYAN}[Design] Verificando falhas de design...{Colors.RESET}")
    design_findings = check_design_flaws(target, args.user_agent)
    for df in design_findings:
        all_findings.append({
            "id": f"END-{len(all_findings)+1:03d}",
            "title": f"Endpoint de debug exposto: {df['endpoint']}",
            "category": "A04:2021-Insecure Design",
            "severity": df["severity"],
            "description": df["description"],
            "affected_endpoints": df["endpoint"],
            "evidence": f"HTTP {df['status']}",
            "remediation": "Remover ou proteger endpoints de debug/actuator/swagger/graphql em produção"
        })

    # Phase 6: IDOR Testing
    print(f"\n{Colors.CYAN}[IDOR] Testando IDOR em endpoints numéricos...{Colors.RESET}")
    idor_findings = test_idor_on_endpoints(target, args.user_agent, discovered_endpoints)
    for idf in idor_findings:
        all_findings.append({
            "id": f"END-{len(all_findings)+1:03d}",
            "title": f"Possível IDOR detectado",
            "category": "A01:2021-Broken Access Control",
            "severity": idf["severity"],
            "description": idf["description"],
            "affected_endpoints": idf["endpoint"],
            "evidence": f"Original: {idf['original_endpoint']} -> Testado: {idf['endpoint']}",
            "remediation": "Implementar verificação de autorização no nível do objeto (object-level authorization)."
        })

    duration = time.time() - start_time
    metadata = {
        "target": target, "domain": domain,
        "date": datetime.now().isoformat(), "duration": f"{duration:.2f}s",
        "tools": tools_used, "scan_type": "Endpoints & Design Flaws"
    }
    results = {"recon": {"target": target, "discovered_endpoints": discovered_endpoints}, "findings": all_findings}

    # Report
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}Phase 2: Report Generation{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}\n")

    reporter = ReportGenerator()
    safe_domain = domain.replace(".", "")
    reporter.generate_markdown(results, metadata, output_dir, f"{safe_domain}ENDPOINTS")
    reporter.generate_html(results, metadata, output_dir, f"{safe_domain}ENDPOINTS")
    reporter.generate_json(results, metadata, output_dir)

    color_log(f"Endpoints scan completed in {duration:.2f}s. {len(all_findings)} findings.", "INFO")
    color_log(f"Reports saved to: {output_dir}", "INFO")
    return 0


if __name__ == "__main__":
    sys.exit(main())
