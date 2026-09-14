import os
import re
import json
import html
from datetime import datetime
from typing import Dict, List, Optional


class ReportGenerator:
    """Generates OWASP-formatted Markdown, HTML, and JSON reports with Waspy branding."""

    OWASP_MAP = {
        "A01": "BROKEN ACCESS CONTROL",
        "A02": "CRYPTOGRAPHIC FAILURES",
        "A03": "INJECTION",
        "A04": "INSECURE DESIGN",
        "A05": "SECURITY MISCONFIGURATION",
        "A06": "VULNERABLE AND OUTDATED COMPONENTS",
        "A07": "IDENTIFICATION AND AUTHENTICATION FAILURES",
        "A08": "SOFTWARE AND DATA INTEGRITY FAILURES",
        "A09": "SECURITY LOGGING AND MONITORING FAILURES",
        "A10": "SERVER-SIDE REQUEST FORGERY (SSRF)",
    }

    CVSS_SEVERITY = {
        "CRITICAL": (9.0, 10.0, "#dc2626"),
        "HIGH": (7.0, 8.9, "#ea580c"),
        "MEDIUM": (4.0, 6.9, "#d97706"),
        "LOW": (0.1, 3.9, "#65a30d"),
        "INFO": (0.0, 0.0, "#3b82f6"),
    }

    def __init__(self):
        self.commands_log: List[str] = []

    def add_command_log(self, commands: List[str]) -> None:
        self.commands_log.extend(commands)

    def _get_client_name(self, domain):
        if not domain:
            return "Cliente"
        parts = domain.split(".")
        tlds = {"br", "com", "org", "net", "edu", "gov", "io", "co", "me", "info", "biz", "app", "dev", "tech", "ai", "xyz"}
        meaningful = [p for p in parts if p not in tlds and len(p) > 2]
        if meaningful:
            return meaningful[0].replace("-", " ").replace("_", " ").title()
        return parts[0].replace("-", " ").replace("_", " ").title()

    def _format_date_ptbr(self, date_str):
        months = {
            1: "janeiro", 2: "fevereiro", 3: "mar\u00e7o", 4: "abril",
            5: "maio", 6: "junho", 7: "julho", 8: "agosto",
            9: "setembro", 10: "outubro", 11: "novembro", 12: "dezembro",
        }
        try:
            if not date_str:
                raise ValueError("empty")
            if "T" in date_str:
                date_str = date_str.split("T")[0]
            dt = datetime.strptime(date_str, "%Y-%m-%d")
            return f"{dt.day} de {months[dt.month]} de {dt.year}"
        except Exception:
            return date_str

    def _get_owasp_code(self, category):
        cat = (category or "").upper()
        for code in ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]:
            if code in cat:
                return code
        return "A00"

    def _group_findings(self, findings):
        grouped = {}
        for f in findings:
            code = self._get_owasp_code(f.get("category", ""))
            grouped.setdefault(code, []).append(f)
        return grouped

    def _severity_count(self, findings):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _extract_cve_ids(self, finding):
        cve_field = finding.get("cve")
        if cve_field:
            ids = re.findall(r"CVE-\d{4}-\d{4,7}", str(cve_field), re.IGNORECASE)
            if ids:
                return sorted(set(i.upper() for i in ids))
        text_fields = " ".join(str(finding.get(k, "")) for k in ("title", "description", "evidence", "response", "remediation"))
        ids = re.findall(r"CVE-\d{4}-\d{4,7}", text_fields, re.IGNORECASE)
        return sorted(set(i.upper() for i in ids)) if ids else []

    def _cvss_score(self, finding):
        cvss = finding.get("cvss")
        try:
            return float(cvss) if cvss else None
        except (TypeError, ValueError):
            return None

    def _cvss_color(self, score):
        if score is None:
            return "#64748b"
        for sev, (lo, hi, color) in self.CVSS_SEVERITY.items():
            if lo <= score <= hi:
                return color
        return "#64748b"

    def _cvss_label(self, score):
        if score is None:
            return "N/A"
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0.0:
            return "LOW"
        return "INFO"

    def _risk_score(self, findings):
        weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
        total = sum(weights.get(f.get("severity", "INFO").upper(), 0) for f in findings)
        max_possible = max(len(findings) * 10, 1)
        score = int((total / max_possible) * 100)
        return max(0, min(100, score))

    def _risk_label(self, score):
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        if score >= 20:
            return "LOW"
        return "INFO"

    def _waf_detected(self, recon):
        waf = recon.get("waf") or recon.get("waf_detected")
        if isinstance(waf, bool):
            return waf
        if isinstance(waf, str) and waf.lower() not in ("", "none", "false", "no"):
            return True
        return False

    def _waf_name(self, recon):
        waf = recon.get("waf") or recon.get("waf_detected")
        if isinstance(waf, str) and waf.lower() not in ("", "none", "false", "no"):
            return waf
        return "Desconhecido"

    def _format_evidence(self, finding):
        ev = finding.get("evidence") or finding.get("response") or "N/A"
        return str(ev)

    def _deduplicate_findings(self, findings):
        """Remove duplicate findings based on CVE IDs and category."""
        seen = set()
        unique = []
        for f in findings:
            cves = tuple(sorted(self._extract_cve_ids(f)))
            category = f.get("category", "")
            affected = f.get("affected_endpoints", "")
            if isinstance(affected, list):
                affected = affected[0] if affected else ""
            # For findings without CVEs, use endpoint+category to avoid over-deduplication
            if cves:
                key = (cves, category)
            else:
                key = (("NO_CVE", affected[:100]), category)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def generate_markdown(self, results: Dict, metadata: Dict, output_dir: str, report_name: str = "report") -> str:
        """Generate ABNT-formatted Markdown report with Waspy branding."""
        findings = results.get("findings", [])
        # Deduplicate findings by CVE + category
        findings = self._deduplicate_findings(findings)
        md_path = os.path.join(output_dir, f"{report_name}.md")
        recon = results.get("recon", {})
        domain = metadata.get("domain", "")
        client = self._get_client_name(domain)
        date_ptbr = self._format_date_ptbr(metadata.get("date", ""))
        sev_counts = self._severity_count(findings)
        grouped = self._group_findings(findings)
        tools = metadata.get("tools", [])
        risk_score = self._risk_score(findings)
        risk_label = self._risk_label(risk_score)
        md = []

        # CAPA (ABNT)
        md.append("# RELATÓRIO TÉCNICO DE AVALIAÇÃO DE SEGURANÇA EM APLICAÇÃO WEB\n")
        md.append(f"**Título**: Avaliação de Segurança em Aplicação Web — Metodologia OWASP Top 10 (2021)\n")
        md.append(f"**Cliente**: {client}")
        md.append(f"**Ambiente Testado**: {metadata.get('target', 'N/A')}")
        md.append(f"**Data**: {date_ptbr}")
        md.append(f"**Local**: São Paulo, SP\n")
        md.append("---")
        md.append("**Responsável Técnico**: Denilson Medeiros França")
        md.append("**Equipe**: Waspy Security Team")
        md.append("**Ferramenta**: Waspy - Web Application Security Pentest Scanner")
        md.append(f"**Versão**: 1.0")
        md.append(f"**Ferramentas Utilizadas**: {', '.join(tools) if tools else 'N/A'}\n")
        md.append("---")
        md.append("## SUMÁRIO EXECUTIVO\n")
        md.append(f"Este relatório apresenta os resultados da avaliação de segurança realizada na aplicação web **{metadata.get('target', 'N/A')}**, seguindo a metodologia **OWASP Top 10 (2021)**. O teste foi conduzido no modelo **Black-Box**, sem credenciais de acesso, simulando um atacante externo.\n")
        md.append(f"**Total de Vulnerabilidades Identificadas**: {len(findings)}")
        md.append(f"**Score de Risco**: {risk_score}/100 ({risk_label})")
        md.append(f"**Duração do Scan**: {metadata.get('duration', 'N/A')}\n")
        md.append("### Distribuição por Severidade")
        md.append("| Severidade | Quantidade |")
        md.append("|------------|------------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            md.append(f"| {sev} | {sev_counts.get(sev, 0)} |")
        md.append("")

        md.append("## 1. PLANEJAMENTO E ESCOPO")
        md.append(f"- **Atividade**: Mapeamento e teste de vulnerabilidades web")
        md.append(f"- **Cliente**: {client}")
        md.append(f"- **Alvo**: {domain}")
        md.append(f"- **Escopo**: Aplicação Web Principal e caminhos públicos")
        md.append(f"- **Fora de escopo**: DoS/DDoS, engenharia social, segurança física")
        md.append(f"- **Tipo de teste**: Black-Box (sem credenciais)")
        md.append(f"- **Data de execução**: {date_ptbr}")
        md.append(f"- **Responsável**: Denilson Medeiros França\n")

        md.append("## 2. METODOLOGIA")
        md.append("A avaliação seguiu a metodologia **OWASP Top 10 (2021)**, cobrindo as 10 categorias de riscos mais críticos:")
        for code in ["A01","A02","A03","A04","A05","A06","A07","A08","A09","A10"]:
            title = self.OWASP_MAP.get(code, code)
            md.append(f"- **{code}**: {title}")
        md.append("")
        md.append("### Ferramentas e Técnicas")
        md.append("- **Reconhecimento**: subfinder, nmap, whatweb, whois, dig, DNS enumeração")
        md.append("- **Enumeração de Diretórios**: ffuf/gobuster com wordlists customizadas")
        md.append("- **Análise WordPress**: WPScan (plugins, usuários, versões), Nuclei templates passivos")
        md.append("- **Varredura de CVEs**: Nuclei (templates CVE, tags=cve, severidades critical/high/medium)")
        md.append("- **Testes de Injeção**: SQLMap (SQLi), payloads XSS/LFI/RCE/SSRF/IDOR")
        md.append("- **Análise de Configuração**: Nikto, cabeçalhos de segurança, SSL/TLS (testssl.sh)")
        md.append("- **Heurística Passiva**: Cruzamento de versões detectadas com banco local de CVEs conhecidos")
        md.append("- **Modo Furtivo (Stealth)**: Rate limiting (30-50 req/s), User-Agent customizado, retries em 403/429\n")

        md.append("## 3. RECONHECIMENTO")
        md.append("### Subdomínios Encontrados")
        subs = recon.get("subdomains", [])
        if subs:
            for s in subs[:50]:
                md.append(f"- {s}")
            if len(subs) > 50:
                md.append(f"- ... e mais {len(subs) - 50} subdomínios")
        else:
            md.append("- Nenhum subdomínio identificado.")
        md.append("")

        md.append("### Portas Abertas e Serviços")
        ports = recon.get("open_ports", [])
        if ports:
            for p in ports:
                md.append(f"- {p}")
        else:
            dns = recon.get("dns", {})
            if isinstance(dns, dict):
                for rtype, records in dns.items():
                    if records:
                        md.append(f"- **{rtype}**: {', '.join(records[:5])}")
            else:
                md.append("- Dados de portas não disponíveis.")
        md.append("")

        md.append("### Tecnologias Detectadas")
        techs = recon.get("technologies", [])
        if techs:
            md.append(", ".join(t for t in techs[:30] if t))
        else:
            md.append("- Nenhuma tecnologia identificada.")
        md.append("")

        md.append("### WAF (Web Application Firewall)")
        if self._waf_detected(recon):
            md.append(f"- **WAF Detectado**: Sim ({self._waf_name(recon)})")
            md.append("- **Impacto**: WAF pode bloquear payloads de exploração ativa, gerando falsos negativos em testes de injeção.")
        else:
            md.append("- **WAF Detectado**: Não")
        md.append("")

        md.append("## 4. VULNERABILIDADES ENCONTRADAS (OWASP Top 10 + CVE)\n")
        for code in ["A01","A02","A03","A04","A05","A06","A07","A08","A09","A10"]:
            title = self.OWASP_MAP.get(code, code)
            code_findings = grouped.get(code, [])
            md.append(f"### {code} — {title}\n")
            if code_findings:
                for i, f in enumerate(code_findings, 1):
                    affected = f.get("affected_endpoints") or f.get("request", [])
                    if isinstance(affected, str):
                        affected = [affected]
                    evidence = self._format_evidence(f)
                    cve_ids = self._extract_cve_ids(f)
                    cvss = self._cvss_score(f)
                    cvss_str = f"{cvss:.1f}" if cvss is not None else "N/A"
                    cve_str = ", ".join(cve_ids) if cve_ids else "Não identificado"
                    severity = f.get("severity", "N/A")
                    source = f.get("source", "scan")
                    
                    md.append(f"#### {i}. {f.get('id', f'VULN-{code}-{i:03d}')}: {f.get('title', 'Vulnerabilidade')}")
                    md.append(f"- **Categoria OWASP**: {code} — {title}")
                    md.append(f"- **Severidade**: {severity}")
                    md.append(f"- **CVSS**: {cvss_str} ({self._cvss_label(cvss)})")
                    md.append(f"- **CVE(s)**: {cve_str}")
                    md.append(f"- **Fonte**: {source}")
                    md.append(f"- **Descrição**: {f.get('description','N/A')}")
                    md.append(f"- **Endpoints Afetados**: {', '.join(affected) if affected else 'N/A'}")
                    md.append(f"- **Evidências**:\n```\n{evidence[:1500]}\n```")
                    md.append(f"- **Remediação**: {f.get('remediation','N/A')}")
                    md.append("")
            else:
                md.append("- Nenhuma vulnerabilidade identificada nesta categoria.\n")

        md.append("## 5. ANÁLISE DE RISCO E PRIORIZAÇÃO")
        md.append("### Matriz de Risco")
        md.append("| Vulnerabilidade | Severidade | CVSS | Impacto | Probabilidade | Prioridade |")
        md.append("|-----------------|------------|------|---------|---------------|------------|")
        # Sort by severity weight
        severity_weight = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        sorted_findings = sorted(findings, key=lambda x: severity_weight.get(x.get("severity", "INFO"), 0), reverse=True)
        for f in sorted_findings[:15]:
            sev = f.get("severity", "INFO")
            cvss = self._cvss_score(f)
            cvss_str = f"{cvss:.1f}" if cvss is not None else "N/A"
            impact = "Alto" if sev in ["CRITICAL", "HIGH"] else "Médio" if sev == "MEDIUM" else "Baixo"
            prob = "Alta" if sev in ["CRITICAL", "HIGH"] else "Média" if sev == "MEDIUM" else "Baixa"
            priority = "Imediata" if sev == "CRITICAL" else "Alta" if sev == "HIGH" else "Média" if sev == "MEDIUM" else "Baixa"
            md.append(f"| {f.get('title', 'N/A')[:50]} | {sev} | {cvss_str} | {impact} | {prob} | {priority} |")
        md.append("")

        md.append("## 6. RECOMENDAÇÕES TÉCNICAS")
        md.append("### Imediatas (Crítico/Alto)")
        critical_high = [f for f in findings if f.get("severity") in ["CRITICAL", "HIGH"]]
        if critical_high:
            for f in critical_high[:5]:
                md.append(f"- **{f.get('title', 'N/A')}**: {f.get('remediation', 'N/A')}")
        else:
            md.append("- Nenhuma vulnerabilidade crítica/alta identificada.")
        md.append("")
        md.append("### Médio Prazo (Médio)")
        medium = [f for f in findings if f.get("severity") == "MEDIUM"]
        if medium:
            for f in medium[:5]:
                md.append(f"- **{f.get('title', 'N/A')}**: {f.get('remediation', 'N/A')}")
        else:
            md.append("- Nenhuma vulnerabilidade média identificada.")
        md.append("")
        md.append("### Boas Práticas (Baixo/Informativo)")
        md.append("- Implementar cabeçalhos de segurança: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy")
        md.append("- Desabilitar enumeração de usuários na API REST do WordPress (`/wp-json/wp/v2/users`)")
        md.append("- Remover arquivos sensíveis expostos: `.env`, `.git`, backups, `wp-config.php.bak`")
        md.append("- Restringir acesso a painéis de debug: `/actuator`, `/swagger`, `/graphql`, `/h2-console`")
        md.append("- Manter WordPress, plugins e temas sempre atualizados")
        md.append("- Implementar WAF com regras personalizadas para permitir testes autorizados")
        md.append("- Realizar testes de segurança periódicos (recomendado: trimestral)\n")

        md.append("## 7. COMANDOS EXECUTADOS")
        for cmd in self.commands_log:
            md.append(f"```bash\n{cmd}\n```")
        md.append("")

        md.append("## 8. REFERÊNCIAS")
        md.append("- OWASP Top 10:2021 — https://owasp.org/Top10/")
        md.append("- NIST National Vulnerability Database — https://nvd.nist.gov/")
        md.append("- CVE MITRE — https://cve.mitre.org/")
        md.append("- WPScan Vulnerability Database — https://wpscan.com/vulnerabilities/")
        md.append("- Nuclei Templates — https://github.com/projectdiscovery/nuclei-templates")
        md.append("- Waspy Scanner — https://github.com/Denilson-franca\n")

        md.append("---")
        md.append("*Relatório gerado por **Waspy** — Web Application Security Pentest Scanner*")
        md.append("*By Denilson França | GitHub: https://github.com/Denilson-franca*\n")

        md.append("## AVISO LEGAL")
        md.append("> **ESTE SOFTWARE DEVE SER UTILIZADO APENAS EM SISTEMAS DE SUA PROPRIEDADE OU COM AUTORIZAÇÃO EXPRESSA POR ESCRITO.**")
        md.append(">")
        md.append("> O Waspy foi projetado para **avaliações de segurança autorizadas**, **programas de bug bounty** e **fins educacionais**. A varredura não autorizada de sistemas que você não possui ou não tem permissão para testar é **ilegal** e pode resultar em penalidades civis e/ou criminais.")
        md.append(">")
        md.append("> Os autores e contribuidores do Waspy **não se responsabilizam** por qualquer uso indevido ou danos causados por esta ferramenta. Ao utilizar o Waspy, você concorda em cumprir todas as leis e regulamentações aplicáveis.")

        with open(md_path, "w", encoding="utf-8") as f:
            f.write("\n".join(md))
        return md_path


    def generate_html(self, results: Dict, metadata: Dict, output_dir: str, report_name: str = "report") -> str:
        """Generate styled HTML report with Waspy branding."""
        findings = results.get("findings", [])
        # Deduplicate findings by CVE + category
        findings = self._deduplicate_findings(findings)
        html_path = os.path.join(output_dir, report_name + ".html")
        recon = results.get("recon", {})
        domain = metadata.get("domain", "")
        client = self._get_client_name(domain)
        sev_colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#65a30d", "INFO": "#3b82f6"}
        sev_counts = self._severity_count(findings)
        grouped = self._group_findings(findings)
        tools = ", ".join(metadata.get("tools", []))
        risk_score = self._risk_score(findings)
        risk_label = self._risk_label(risk_score)
        waf_alert = ""
        if self._waf_detected(recon):
            waf_alert = "<div class='waf-alert'><strong>WAF Detectado:</strong> " + html.escape(self._waf_name(recon)) + "</div>"

        findings_html = ""
        for f in findings:
            color = sev_colors.get(f.get("severity", "INFO"), "#333")
            cve_ids = self._extract_cve_ids(f)
            cve_str = ", ".join(cve_ids) if cve_ids else "N/A"
            cvss = self._cvss_score(f)
            cvss_str = "%.1f" % cvss if cvss is not None else "N/A"
            cvss_color = self._cvss_color(cvss)
            affected = f.get("affected_endpoints") or f.get("request", [])
            if isinstance(affected, str):
                affected = [affected]
            evidence = self._format_evidence(f)
            fid = html.escape(str(f.get("id", "")))
            title = html.escape(str(f.get("title", "")))
            desc = html.escape(str(f.get("description", "")))
            rem = html.escape(str(f.get("remediation", "")))
            sev = html.escape(str(f.get("severity", "")))
            endpoints = html.escape(", ".join(affected))
            ev_esc = html.escape(evidence[:1000])
            findings_html += "<div class='finding'>"
            findings_html += "<h3>" + fid + " \u2014 " + title + "</h3>"
            findings_html += "<p><strong>Categoria:</strong> <span class='badge' style='background:" + color + "'>" + sev + "</span></p>"
            findings_html += "<p><strong>OWASP:</strong> " + html.escape(self._get_owasp_code(f.get('category', ''))) + "</p>"
            findings_html += "<p><strong>CVE:</strong> " + html.escape(cve_str) + "</p>"
            findings_html += "<p><strong>CVSS:</strong> <span style='color:" + cvss_color + ";font-weight:bold'>" + cvss_str + " (" + self._cvss_label(cvss) + ")</span></p>"
            findings_html += "<p><strong>Descrição:</strong> " + desc + "</p>"
            findings_html += "<p><strong>Endpoints:</strong> " + endpoints + "</p>"
            findings_html += "<pre>" + ev_esc + "</pre>"
            findings_html += "<p><strong>Remediação:</strong> " + rem + "</p>"
            findings_html += "</div>"

        owasp_sections = ""
        for code in ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]:
            title = self.OWASP_MAP.get(code, code)
            cf = grouped.get(code, [])
            items = ""
            if cf:
                for f in cf:
                    c = sev_colors.get(f.get("severity", "INFO"), "#333")
                    fid = html.escape(str(f.get("id", "")))
                    ftitle = html.escape(str(f.get("title", "")))
                    fsev = html.escape(str(f.get("severity", "")))
                    items += "<li><span style='color:" + c + "'><strong>" + fid + "</strong></span> \u2014 " + ftitle + " (" + fsev + ")</li>"
            else:
                items = "<li>Nenhuma vulnerabilidade identificada</li>"
            owasp_sections += "<div class='section'><h3>" + code + " - " + html.escape(title) + "</h3><ul>" + items + "</ul></div>"

        dns_records = recon.get("dns", {})
        dns_str = ", ".join(dns_records.get("A", [])) if isinstance(dns_records, dict) else "N/A"
        subs = recon.get("subdomains", [])
        subs_str = ", ".join(subs[:20]) if subs else "None found"
        techs = recon.get("technologies", [])
        techs_str = ", ".join(techs[:20]) if techs else "None detected"
        cmds_html = "".join(["<li><code>" + html.escape(cmd) + "</code></li>" for cmd in self.commands_log])
        template = """<!DOCTYPE html>\n<html lang="pt-BR">\n<head>\n<meta charset="UTF-8">\n<title>Waspy Report</title>\n<style>\nbody { font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 20px; }\n.container { max-width: 1200px; margin: 0 auto; }\nh1 { color: #ef4444; border-bottom: 2px solid #ef4444; padding-bottom: 10px; }\nh2 { color: #94a3b8; margin-top: 30px; }\nh3 { color: #38bdf8; }\n.meta, .section, .finding, .disclaimer { background: #1e293b; padding: 15px; border-radius: 8px; margin: 10px 0; border: 1px solid #334155; }\n.badge { color: white; padding: 3px 10px; border-radius: 4px; font-size: 0.85em; }\npre { background: #0f172a; padding: 10px; border-radius: 4px; overflow-x: auto; }\ntable { width: 100%; border-collapse: collapse; }\nth, td { padding: 8px; text-align: left; border-bottom: 1px solid #334155; }\nth { background: #1e293b; color: #38bdf8; }\n.summary-box { background: linear-gradient(135deg, #dc2626, #ea580c); padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0; }\n.summary-box h3 { color: white; margin: 0 10px; display: inline-block; }\n.waf-alert { background: #78350f; border: 1px solid #f59e0b; padding: 15px; border-radius: 8px; margin: 15px 0; color: #fbbf24; }\n</style>\n</head>\n<body>\n<div class="container">\n<h1>Waspy - Avaliacao de Seguranca em Aplicacao Web (OWASP)</h1>\n<div class="meta">\n<p><strong>Cliente:</strong> """ + html.escape(client) + """</p>\n<p><strong>Ambiente:</strong> """ + html.escape(metadata.get("target", "")) + """</p>\n<p><strong>Data:</strong> """ + html.escape(metadata.get("date", "")) + """</p>\n<p><strong>Duracao:</strong> """ + html.escape(metadata.get("duration", "")) + """</p>\n<p><strong>Analista:</strong> Denilson Medeiros Franca</p>\n<p><strong>Ferramentas:</strong> """ + html.escape(tools) + """</p>\n</div>\n""" + waf_alert + """\n<div class="summary-box">\n<h3>Score de Risco: """ + str(risk_score) + """/100 (""" + html.escape(risk_label) + """)</h3>\n<h3>Total de Achados: """ + str(len(findings)) + """</h3>\n</div>\n<table>\n<tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr>\n<tr><td>""" + str(sev_counts.get("CRITICAL", 0)) + """</td><td>""" + str(sev_counts.get("HIGH", 0)) + """</td><td>""" + str(sev_counts.get("MEDIUM", 0)) + """</td><td>""" + str(sev_counts.get("LOW", 0)) + """</td><td>""" + str(sev_counts.get("INFO", 0)) + """</td></tr>\n</table>\n<h2>Reconhecimento</h2>\n<div class="section"><h3>Subdominios</h3><p>""" + html.escape(subs_str) + """</p></div>\n<div class="section"><h3>Tecnologias</h3><p>""" + html.escape(techs_str) + """</p></div>\n<div class="section"><h3>DNS Records</h3><p>""" + html.escape(dns_str) + """</p></div>\n<h2>OWASP Top 10 Findings</h2>\n""" + owasp_sections + """\n<h2>Detalhes das Vulnerabilidades</h2>\n""" + (findings_html if findings_html else "<p>Nenhum achado.</p>") + """\n<h2>Ferramentas Executadas</h2>\n<ul>""" + cmds_html + """</ul>\n<div class="disclaimer">\n<p><strong>Aviso Legal:</strong> Este pentest foi realizado exclusivamente para fins de seguranca autorizada.</p>\n<p>By Denilson Franca | GitHub: https://github.com/Denilson-franca</p>\n</div>\n</div>\n</body>\n</html>"""
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(template)
        return html_path

    def generate_json(self, results: Dict, metadata: Dict, output_dir: str) -> str:
        """Generate JSON report."""
        findings = results.get("findings", [])
        # Deduplicate findings by CVE + category
        findings = self._deduplicate_findings(findings)
        json_path = os.path.join(output_dir, "results.json")
        report = {
            "metadata": metadata,
            "results": {**results, "findings": findings},
            "generated_at": datetime.now().isoformat(),
            "author": "Denilson Franca",
            "tool": "Waspy",
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        return json_path
