# Manual do Usuário — Waspy   
(Web Application Security Pentest Scanner)

**Versão**: 1.0  
**Autor**: Denilson Medeiros França  
**GitHub**: [https://github.com/Denilson-franca](https://github.com/Denilson-franca)  
**Email**: [gearsec\_denilson@proton.me](mailto:gearsec_denilson@proton.me)  
**Licença**: MIT


## 1. Visão Geral

O **Waspy** é um scanner automatizado de segurança para aplicações web que mapeia vulnerabilidades seguindo a metodologia **OWASP Top 10 (2021/2023)**. Ele orquestra ferramentas padrão da indústria (nmap, nuclei, wpscan, ffuf, sqlmap, nikto, whatweb, etc.) e adiciona uma **engine heurística passiva** capaz de detectar CVEs conhecidos em plugins WordPress **mesmo quando o WAF (Cloudflare, etc.) bloqueia a exploração ativa**.

### Principais Características

- **3 Modos de Varredura**: Rápido (CVEs), Completo (OWASP A01-A10), Endpoints

- **Modo Furtivo (Stealth)**: Rate limiting, User-Agent customizado, retries em 403/429

- **Heurística de CVEs**: 3 camadas (Nuclei passivo + WPScan/curl + HTML raw) + banco local com 25+ plugins

- **Relatórios ABNT**: Markdown, HTML e JSON com estrutura profissional

- **Cache Inteligente**: Evita re-escanear o mesmo alvo em 24h

- **Deduplicação**: Remove findings duplicados por CVE + endpoint


## 2. Pré-requisitos

### Ferramentas de Sistema (Obrigatórias)

```
\# Ubuntu/Debian/Kali  
sudo apt update && sudo apt install -y \\  
  nmap whatweb whois dnsutils curl git \\  
  ffuf gobuster nikto jq  
  
\# Go tools (opcionais mas recomendadas)  
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest  
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest  
go install github.com/owasp-amass/amass/v4/...@master
```

### Python

```
python3 -m venv .venv  
source .venv/bin/activate  
pip install -r requirements.txt
```

### WPScan (Ruby)

```
gem install wpscan  
\# ou  
sudo apt install wpscan
```

### SQLMap

```
pip install sqlmap  
\# ou  
sudo apt install sqlmap
```

### testssl.sh (SSL/TLS)

```
git clone --depth 1 https://github.com/drwetter/testssl.sh.git  
cd testssl.sh && sudo ln -s $(pwd)/testssl.sh /usr/local/bin/
```


## 3. Instalação

```
git clone https://github.com/Denilson-franca/waspy.git  
cd waspy  
python3 -m venv .venv  
source .venv/bin/activate  
pip install -r requirements.txt  
  
\# Verificar instalação  
python3 modules/scan\_quick.py --help  
bash waspy.sh --help
```


## 4. Estrutura do Projeto

```
waspy/  
├── wasp.py                 \# Entry point principal (Full OWASP)  
├── ghost\_gear.py           \# Entry point alternativo  
├── waspy.sh                \# Interface visual interativa (bash)  
├── MANUAL.md               \# Este manual  
├── requirements.txt        \# Dependências Python  
├── config/  
│   └── owasp\_payloads.json \# Payloads OWASP  
├── wordlists/  
│   └── dirs.txt            \# Wordlist para fuzzing  
├── modules/  
│   ├── utils.py            \# Utilitários, banner, logging, run\_command  
│   ├── recon.py            \# Reconhecimento (subdomínios, portas, DNS, techs)  
│   ├── scan\_full.py        \# Scan completo OWASP A01-A10  
│   ├── scan\_quick.py       \# Scan rápido CVEs + heurística  
│   ├── scan\_endpoints.py   \# Endpoints, APIs, IDOR, arquivos sensíveis  
│   ├── owasp\_scan.py       \# Testes ativos OWASP (injection, headers, etc.)  
│   └── reporter.py         \# Geração de relatórios (MD, HTML, JSON) ABNT  
├── relatorios/             \# Output dos scans (gitignored)  
└── \_\_pycache\_\_/
```


## 5. Modos de Uso

### 5.1 Interface Visual (Recomendado para Iniciantes)

```
bash waspy.sh
```

**Fluxo do Menu**:

```
1. Digite a URL alvo (ex: https://exemplo.com)  
2. Opção 5 → Configure Modo Furtivo (s/N) + User-Agent  
3. Escolha o tipo de scan:  
   \[1\] Pentest Completo OWASP Top 10  
   \[2\] Varredura Rápida CVEs e Reconhecimento  
   \[3\] Buscar Endpoints Comprometidos e Falhas de Design  
   \[4\] Alterar URL alvo  
   \[5\] Configurar Modo Furtivo  
   \[0\] Sair  
4. Aguarde conclusão → Relatórios em ./relatorios/
```

### 5.2 Linha de Comando — Scan Rápido (CVEs + Heurística)

```
\# Apenas heurística passiva (mais rápido, ~80s) - WAF não bloqueia  
python3 modules/scan\_quick.py -u https://alvo.com --stealth --user-agent "Waspy/1.0" --no-nuclei  
  
\# Com enumeração passiva Nuclei (versões exatas, ~2 min)  
python3 modules/scan\_quick.py -u https://alvo.com --stealth --user-agent "Waspy/1.0" --no-wpscan  
  
\# Completo (Nuclei CVE tags + heurística)  
python3 modules/scan\_quick.py -u https://alvo.com --stealth --user-agent "Waspy/1.0"
```

**Flags Principais**: | Flag | Descrição | Padrão | |------|-----------|--------| | `-u, --url` | URL alvo (obrigatório) | — | | `-o, --output` | Diretório de saída | `./relatorios/` | | `--stealth` | Modo furtivo (rate limit, retries, UA custom) | off | | `--user-agent` | User-Agent personalizado | `Waspy/1.0` | | `--rate-limit` | Requisições/segundo (stealth) | 10 | | `--threads` | Threads concorrentes | 5 | | `--no-nuclei` | Pula Nuclei CVE scan | off | | `--no-wpscan` | Pula WPScan | off | | `--no-whatweb` | Pula WhatWeb | off | | `-v, --verbose` | Log detalhado | off |

### 5.3 Linha de Comando — Scan Completo (OWASP A01-A10)

```
\# Completo com stealth (recomendado para produção)  
python3 modules/scan\_full.py -u https://alvo.com --stealth --user-agent "Waspy/1.0" --skip-sqlmap  
  
\# Pula Nuclei ativo (mais rápido, evita WAF)  
python3 modules/scan\_full.py -u https://alvo.com --stealth --user-agent "Waspy/1.0" --skip-nuclei --skip-sqlmap  
  
\# Com output customizado  
python3 modules/scan\_full.py -u https://alvo.com -o /tmp/meu-scan --stealth --user-agent "MinhaEmpresa/1.0"
```

**Flags Adicionais**: | Flag | Descrição | |------|-----------| | `--skip-nuclei` | Pula Nuclei (ativo + passivo) | | `--skip-sqlmap` | Pula SQLMap (testes SQLi ativos) | | `--skip-wpscan` | Pula WPScan | | `--skip-ffuf` | Pula fuzzing de diretórios | | `--threads` | Threads concorrentes (padrão: 50) |

### 5.4 Linha de Comando — Scan de Endpoints

```
python3 modules/scan\_endpoints.py -u https://alvo.com --stealth --user-agent "Waspy/1.0"
```

**O que testa**:

- Fuzzing de diretórios (ffuf/gobuster)

- robots.txt + sitemap.xml

- WordPress REST API (`/wp-json/wp/v2/users`, posts, pages)

- APIs genéricas (OpenAPI/Swagger, GraphQL, JWKS)

- Arquivos sensíveis (`.env`, `.git`, backups, configs)

- Endpoints de debug (actuator, swagger, h2-console, phpmyadmin)

- Testes de IDOR em endpoints numéricos


## 6. Modo Furtivo (Stealth Mode) — Essencial para WAF

Quando ativado (`--stealth` ou Opção 5 no menu), aplica:

| Configuração | Valor | Propósito |
| - | - | - |
| Nuclei rate-limit | 30 req/s (passivo) / 10 req/s (ativo) | Evita 429/403 por volume |
| Nuclei concurrency | 10 | Limita conexões simultâneas |
| Nuclei timeout | 15s | Mais tolerante a latência |
| Nuclei retries | 2 | Reenvia em 403/429 |
| User-Agent | Customizado | Evita assinatura padrão |
| Python timeout | Infinito (`None`) | Não mata Nuclei lento |


**Use SEMPRE em alvos com Cloudflare, AWS WAF, Akamai, etc.**


## 6. Entendendo os Relatórios

### Localização

```
./relatorios/\<dominio\>\_\<tipo\>\_\<timestamp\>/  
├── \<dominio\>\<TIPO\>.md      \# Markdown (ABNT)  
├── \<dominio\>\<TIPO\>.html    \# HTML estilizado  
├── results.json            \# JSON estruturado  
└── \*.json                  \# Outputs brutos (nuclei, wpscan, ffuf)
```

**Tipos**: `OWASP` (completo), `QUICK` (rápido), `ENDPOINTS` (endpoints)

### Estrutura ABNT (Markdown/HTML)

1. **Capa** — Título, cliente, data, responsável, ferramenta

2. **Sumário Executivo** — Total vulns, score de risco (0-100), distribuição por severidade

3. **Planejamento e Escopo** — Atividade, alvo, tipo teste, fora de escopo

4. **Metodologia** — OWASP Top 10, ferramentas, modo stealth

5. **Reconhecimento** — Subdomínios, portas, tecnologias, WAF

6. **Vulnerabilidades (A01-A10)** — Cada finding com:

   - ID único (`HEU-XXX`, `NUC-XXX`, `CVE-XXX`, `END-XXX`)

   - Categoria OWASP + severidade (CRITICAL/HIGH/MEDIUM/LOW/INFO)

   - CVSS score + label

   - CVE(s) associadas

   - Fonte de detecção (`nuclei\_passive`, `wpscan`, `html\_raw`, `curl\_fallback`, `scan`)

   - Descrição, endpoints afetados, evidências, remediação

7. **Análise de Risco** — Matriz impacto/probabilidade/prioridade

8. **Recomendações** — Imediatas, médio prazo, boas práticas

9. **Comandos Executados** — Log completo para reprodutibilidade

10. **Referências** — OWASP, NIST, CVE, WPScan, Nuclei

11. **Aviso Legal** — Disclaimer completo

### Severidades

| Nível | Cor | Ação |
| - | - | - |
| **CRITICAL** | 🔴 Vermelho | Corrigir IMEDIATAMENTE (RCE, SQLi autenticada) |
| **HIGH** | 🟠 Laranja | Corrigir URGENTE (SQLi, XSS stored, auth bypass) |
| **MEDIUM** | 🟡 Amarelo | Corrigir em curto prazo (CSRF, IDOR, info disclosure) |
| **LOW** | 🟢 Verde | Melhoria (server token, headers ausentes) |
| **INFO** | 🔵 Azul | Informacional (tecnologias, enumeração usuários) |


### Prefixos de ID (Origem da Descoberta)

| Prefixo | Significado |
| - | - |
| `HEU-` | Heurística passiva (banco local de CVEs) |
| `NUC-` | Nuclei template match (tecnologia/CVE) |
| `CVE-` | Nuclei CVE-focused scan (tags=cve) |
| `WPSCAN-` | WPScan enumeration (users, plugins) |
| `END-` | Scan de endpoints (fuzzing, API, files) |
| `A01-A10-` | Testes ativos OWASP (injection, headers, etc.) |



## 7. Heurística de CVEs — Como Funciona

O Waspy detecta CVEs **sem disparar payloads de exploração** (WAF-proof):

### Banco de Dados Local (`WORDPRESS\_PLUGIN\_CVE\_DB`)

- **25+ plugins** WordPress com CVEs conhecidos

- Cada entrada: `version\_max`, `cve`, `severity`, `title`, `description`

- Exemplo: Forminator ≤ 1.36.0 → CVE-2026-18328 (XSS), CVE-2026-19221 (RCE)

### 3 Camadas de Detecção

```
┌─────────────────────────────────────────────────────────────┐  
│  CAMADA 1: Nuclei Passivo (-t http/technologies/wordpress/) │  
│  → Lê /wp-content/plugins/\<plugin\>/readme.txt               │  
│  → Extrai versão exata (ex: Forminator 1.35.0)             │  
└─────────────────────────────────────────────────────────────┘  
                              ↓  
┌─────────────────────────────────────────────────────────────┐  
│  CAMADA 2: WPScan / curl fallback                           │  
│  → WPScan --enumerate p,u (plugins + users)                 │  
│  → curl em paths conhecidos (/wp-content/plugins/...)       │  
└─────────────────────────────────────────────────────────────┘  
                              ↓  
┌─────────────────────────────────────────────────────────────┐  
│  CAMADA 3: HTML Raw Heuristic                               │  
│  → GET na home + regex para /wp-content/plugins/\<nome\>/     │  
│  → Funciona MESMO com WAF bloqueando tudo                   │  
└─────────────────────────────────────────────────────────────┘  
                              ↓  
              CRUZAMENTO: versão ≤ version\_max → ALERTA CVE
```

### Adicionar Novos Plugins ao Banco

Edite `modules/scan\_full.py` e `modules/scan\_quick.py`:

```
"novo-plugin": \[  
    \{"version\_max": "2.5.0", "cve": "CVE-2024-XXXX", "severity": "HIGH",  
     "title": "Título da Vulnerabilidade", "description": "Descrição..."\},  
\],
```

Também adicione o path em `raw\_html\_plugin\_heuristic()` (scan\_full.py).


## 8. Dicas de Uso Avançado

### Scan em Alvo com WAF Agressivo

```
\# Apenas heurística (zero payloads ativos)  
python3 modules/scan\_quick.py -u https://alvo.com \\  
  --stealth --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..." \\  
  --no-nuclei --no-wpscan --no-whatweb
```

### Scan Apenas WordPress (Plugins + CVEs)

```
python3 modules/scan\_quick.py -u https://wp-site.com \\  
  --stealth --user-agent "Waspy/1.0" --no-nuclei --no-whatweb
```

### Usar Cache (Re-scan Rápido)

```
\# Primeiro scan cria cache em .plugin\_cache\_\<hash\>.json  
\# Segundo scan (mesmo output dir) usa cache instantâneo  
python3 modules/scan\_full.py -u https://alvo.com -o ./relatorios --stealth  
python3 modules/scan\_full.py -u https://alvo.com -o ./relatorios --stealth  \# Usa cache
```

### Wordlist Customizada

```
python3 modules/scan\_full.py -u https://alvo.com \\  
  --wordlist /path/minha-wordlist.txt
```

### Proxy (Burp Suite, etc.)

```
\# Via variável de ambiente (curl/nuclei/wpscan respeitam)  
export HTTP\_PROXY=http://127.0.0.1:8080  
export HTTPS\_PROXY=http://127.0.0.1:8080  
python3 modules/scan\_quick.py -u https://alvo.com --stealth
```

### Integração CI/CD (GitLab, GitHub Actions)

```
\# .gitlab-ci.yml  
security\_scan:  
  stage: security  
  script:  
    - python3 modules/scan\_quick.py -u $TARGET\_URL --stealth --no-nuclei -o report  
    - cat report/\*QUICK.md  
  artifacts:  
    reports:  
      sast: report/results.json
```


## 9. Solução de Problemas

| Erro | Causa | Solução |
| - | - | - |
| `nuclei: command not found` | Nuclei não instalado | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `wpscan: Error: cannot load such file -- addressable` | Gem faltando | `gem install addressable -v '\>=2.5,\<2.9'` |
| `WPScan: No vulnerable plugins detected` | WPScan sem API token ou WAF | Use `--no-wpscan` + heurística passiva |
| `Command timed out: nuclei` | Nuclei muito lento no stealth | Timeout é infinito no stealth; aguarde ou use `--no-nuclei` |
| `Permission denied on output dir` | Sem permissão em ./relatorios | Use `-o /tmp/meu-scan` ou `sudo` |
| `KeyError: 'slug'` no WPScan | Formato JSON inesperado | Já corrigido na v1.0; atualize o código |
| Relatórios vazios (0 findings) | WAF bloqueando tudo | Ative `--stealth`, use `--no-nuclei --no-wpscan` |


### Logs de Debug

```
\# Verbose mode  
python3 modules/scan\_quick.py -u https://alvo.com -v --stealth 2\>&1 | tee debug.log
```


## 10. Exemplos Práticos

### Exemplo 1: Pentest Completo em Site WordPress

```
bash waspy.sh  
\# URL: https://meusite.com  
\# Opção 5: Modo Furtivo = s, UA = Mozilla/5.0...  
\# Opção 1: Pentest Completo  
\# Aguarda ~5-10 min  
\# Relatório: relatorios/meusitecomOWASP.md/.html
```

### Exemplo 2: Bug Bounty — Recon + CVEs Rápidos

```
\# Reconhecimento passivo + heurística de CVEs  
python3 modules/scan\_quick.py -u https://target.com \\  
  --stealth --user-agent "BugBountyHunter/1.0" \\  
  --no-nuclei -o ./bb-target  
  
\# Ver CVEs encontrados  
grep -A 5 "CVE-" ./bb-target/\*QUICK.md
```

### Exemplo 3: Auditoria Interna — Sem WAF

```
\# Scan completo sem stealth (mais rápido)  
python3 modules/scan\_full.py -u https://intranet.empresa.local \\  
  --user-agent "InternalAudit/1.0" -o ./audit-$(date +%Y%m%d)
```

### Exemplo 4: Teste de Endpoints/API

```
python3 modules/scan\_endpoints.py -u https://api.empresa.com \\  
  --stealth --user-agent "API-Test/1.0" -o ./api-test  
\# Verifica: Swagger, GraphQL, IDOR, arquivos sensíveis
```


## 11. Segurança e Ética

> **⚠️ IMPORTANTE — LEIA ANTES DE USAR**

- **USE APENAS EM SISTEMAS DE SUA PROPRIEDADE OU COM AUTORIZAÇÃO EXPRESSA POR ESCRITO**

- Varredura não autorizada é **ILEGAL** (Lei 12.737/2012 no Brasil, CFAA nos EUA, GDPR na UE)

- O Waspy é para: **pentests autorizados**, **bug bounty programs**, **auditoria interna**, **educação**

- **Não nos responsabilizamos** por uso indevido

- Configure **regras de WAF** para permitir IPs de teste autorizados

- Sempre documente **escopo, autorização e responsável** antes de executar


## 12. Contribuição

```
\# 1. Fork o repositório  
\# 2. Crie branch: git checkout -b feature/nova-funcionalidade  
\# 3. Commit: git commit -am 'Adiciona X'  
\# 4. Push: git push origin feature/nova-funcionalidade  
\# 5. Abra Pull Request
```

### Diretrizes

- Siga PEP 8 (Python) / ShellCheck (Bash)

- Adicione testes para novas funcionalidades

- Atualize documentação (README, MANUAL.md)

- Mantenha compatibilidade retroativa

- Reporte bugs via GitHub Issues


## 13. Changelog (v1.0)

- ✅ Interface visual `waspy.sh` com menu interativo

- ✅ 3 módulos de scan: Full (OWASP), Quick (CVEs), Endpoints

- ✅ Modo Furtivo (Stealth) com rate limiting e retries

- ✅ Heurística passiva de CVEs (3 camadas, WAF-proof)

- ✅ Banco local com 25+ plugins WordPress

- ✅ Cache de plugins (24h)

- ✅ Relatórios ABNT (MD, HTML, JSON)

- ✅ Deduplicação de findings

- ✅ Banner unificado (roxo) Python + Bash

- ✅ Flags Nuclei corrigidas (`-jsonl`, `-H`, sem `-retry-interval`)

- ✅ Timeout infinito no modo stealth

- ✅ Correção KeyError WPScan users (dict vs list)


## 14. Suporte

- **GitHub Issues**: [https://github.com/Denilson-franca/waspy/issues](https://github.com/Denilson-franca/waspy/issues)

- **Email**: [gearsec\_denilson@proton.me](mailto:gearsec_denilson@proton.me)

- **LinkedIn**: [https://linkedin.com/in/denilson-franca](https://linkedin.com/in/denilson-franca)


*Manual gerado em 2024 — GearSec Security Team*

