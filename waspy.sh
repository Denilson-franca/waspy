#!/bin/bash

# =============================================================================
# WASPY - Web Application Security Penetration Assistant
# A modular web security testing framework
# By Denilson França - https://github.com/Denilson-franca
# LinkedIn: https://linkedin.com/in/denilson-franca
# =============================================================================

# -----------------------------------------------------------------------------
# Color Definitions
# -----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# -----------------------------------------------------------------------------
# Script Configuration
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/modules"
OUTPUT_DIR="$SCRIPT_DIR/relatorios"
TARGET_URL=""
STEALTH_MODE="off"
CUSTOM_UA="Waspy/1.0"

# Required tools for the framework (basic)
REQUIRED_TOOLS=("python3" "curl" "nmap" "whatweb" "whois" "dig")

# Optional tools (enhance scanning)
OPTIONAL_TOOLS=("ffuf" "gobuster" "wpscan" "nuclei" "nikto" "sqlmap" "subfinder" "amass" "jq" "testssl.sh" "sslyze")

# -----------------------------------------------------------------------------
# Signal Handling - Graceful Ctrl+C handling
# -----------------------------------------------------------------------------
cleanup() {
    echo ""
    echo -e "${RED}[!] ${BOLD}Interrupção (Ctrl+C) detectada. Encerrando Waspy...${NC}"
    echo -e "${YELLOW}[*] Limpando recursos temporários...${NC}"
    exit 1
}
trap cleanup SIGINT SIGTERM

# -----------------------------------------------------------------------------
# Banner Function
# -----------------------------------------------------------------------------
banner() {
    clear
    echo -e "${PURPLE}${BOLD}"
cat << 'EOF'
 __      __                                      
/\ \  __/\ \                                     
\ \ \/\ \ \ \     __      ____  _____   __  __   
 \ \ \ \ \ \ \  /'__`\   /,__\ /\ '__`\/\ \/\ \  
  \ \ \_/ \_\ \/\ \L\.\_/\__, `\ \ \L\ \ \ \_\ \ 
   \ `\___x___/\ \__/.\_\/\____/\ \ ,__/\/`____ \
    '\/__//__/  \/__/\/_/\/___/  \ \ \/  `/___/> \
                                  \ \_\     /\___/
                                   \/_/     \/__/
EOF
    echo -e "${NC}"
    echo -e "${GREEN}${BOLD}Waspy - Web Application Security Pentest Scanner${NC}"
    echo -e "${CYAN}By Denilson França${NC}"
    echo -e "${YELLOW}GitHub: https://github.com/Denilson-franca${NC}"
    echo -e "${BLUE}LinkedIn: https://linkedin.com/in/denilson-franca${NC}"
    echo -e "${RED}${BOLD}$(printf '%.0s=' {1..70})${NC}"
    
    if [[ -n "$TARGET_URL" ]]; then
        echo -e "${BLUE} Alvo: ${BOLD}${TARGET_URL}${NC}"
    fi
    echo ""
}

# -----------------------------------------------------------------------------
# Print Separator
# -----------------------------------------------------------------------------
separator() {
    echo -e "${BLUE}────────────────────────────────────────────────────────${NC}"
}

# -----------------------------------------------------------------------------
# Tool Verification
# -----------------------------------------------------------------------------
check_tools() {
    echo -e "${CYAN}[*] Verificando ferramentas obrigatórias...${NC}"
    local missing=0
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo -e "${GREEN}  [✓] ${tool} - encontrado${NC}"
        else
            echo -e "${RED}  [✗] ${tool} - NÃO ENCONTRADO (obrigatório)${NC}"
            missing=1
        fi
    done

    echo -e "${CYAN}[*] Verificando ferramentas opcionais (recomendadas)...${NC}"
    for tool in "${OPTIONAL_TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo -e "${GREEN}  [✓] ${tool} - encontrado${NC}"
        else
            echo -e "${YELLOW}  [!] ${tool} - não encontrado (funcionalidade limitada)${NC}"
        fi
    done

    # Check python3 modules
    echo -e "${CYAN}[*] Verificando módulos Python...${NC}"
    local required_scripts=("scan_full.py" "scan_quick.py" "scan_endpoints.py")
    for script in "${required_scripts[@]}"; do
        if [[ -f "$MODULES_DIR/$script" ]]; then
            echo -e "${GREEN}  [✓] modules/${script} - encontrado${NC}"
        else
            echo -e "${YELLOW}  [!] modules/${script} - não encontrado${NC}"
        fi
    done

    if [[ $missing -eq 1 ]]; then
        echo -e "${RED}[!] Algumas ferramentas obrigatórias estão faltando.${NC}"
        echo -e "${YELLOW}[*] Instale as ferramentas ausentes antes de continuar.${NC}"
        echo -e "${YELLOW}[*] Ubuntu/Debian: apt install nmap whatweb whois dnsutils curl${NC}"
        echo -e "${YELLOW}[*] Ferramentas Go: nuclei, wpscan, subfinder, ffuf, gobuster${NC}"
        return 1
    fi

    echo -e "${GREEN}[+] Verificação concluída.${NC}"
    echo ""
}

# -----------------------------------------------------------------------------
# Prompt for Target URL
# -----------------------------------------------------------------------------
prompt_target() {
    while true; do
        echo -e "${CYAN}${BOLD}Digite a URL alvo:${NC}"
        read -rp $'\033[0;36m\033[1m>>> \033[0m' TARGET_URL
        if [[ -z "$TARGET_URL" ]]; then
            echo -e "${YELLOW}[!] A URL não pode estar vazia. Tente novamente.${NC}"
        elif [[ ! "$TARGET_URL" =~ ^https?:// ]]; then
            echo -e "${YELLOW}[!] URL inválida. Use http:// ou https://. Tente novamente.${NC}"
        else
            break
        fi
    done
    echo -e "${GREEN}[+] URL alvo definida: ${TARGET_URL}${NC}"
    echo ""
}

# -----------------------------------------------------------------------------
# Prompt for Stealth Mode and User-Agent
# -----------------------------------------------------------------------------
prompt_stealth_config() {
    echo -e "${CYAN}${BOLD}Configuração de Modo Furtivo (WAF Evasion)${NC}"
    echo ""
    echo -e "${YELLOW}O modo furtivo aplica rate limiting, User-Agent customizado e retries no Nuclei${NC}"
    echo -e "${YELLOW}para evitar bloqueio por WAFs como Cloudflare. Recomendado para alvos protegidos.${NC}"
    echo ""
    
    while true; do
        echo -e "${CYAN}Ativar Modo Furtivo? (s/N):${NC}"
        read -rp $'\033[0;36m\033[1m>>> \033[0m' choice
        case "$choice" in
            [sS]|[yY]|[yes])
                STEALTH_MODE="on"
                break
                ;;
            [nN]|[no]|"")
                STEALTH_MODE="off"
                break
                ;;
            *)
                echo -e "${YELLOW}[!] Digite 's' para sim ou 'n' para não.${NC}"
                ;;
        esac
    done
    
    echo ""
    echo -e "${CYAN}User-Agent personalizado (Enter para padrão: Waspy/1.0):${NC}"
    read -rp $'\033[0;36m\033[1m>>> \033[0m' ua_input
    if [[ -n "$ua_input" ]]; then
        CUSTOM_UA="$ua_input"
    fi
    echo ""
    
    if [[ "$STEALTH_MODE" == "on" ]]; then
        echo -e "${GREEN}[+] Modo Furtivo ATIVADO${NC}"
        echo -e "${GREEN}[+] User-Agent: ${CUSTOM_UA}${NC}"
    else
        echo -e "${YELLOW}[*] Modo Furtivo DESATIVADO${NC}"
    fi
    echo ""
}

# -----------------------------------------------------------------------------
# Run Scan Module
# Arguments:
#   $1 - Module script name (e.g., scan_full.py)
#   $2 - Module display name
#   $3 - Extra arguments to pass to the Python script
# -----------------------------------------------------------------------------
run_scan() {
    local script="$1"
    local module_name="$2"
    local module_path="$MODULES_DIR/$script"
    local extra_args="${3:-}"

    # Build extra arguments based on stealth config
    local stealth_args=()
    if [[ "$STEALTH_MODE" == "on" ]]; then
        stealth_args=(--stealth --user-agent "$CUSTOM_UA")
    elif [[ "$CUSTOM_UA" != "Waspy/1.0" ]]; then
        stealth_args=(--user-agent "$CUSTOM_UA")
    fi

    echo -e "${CYAN}[*] Iniciando: ${module_name}${NC}"
    echo -e "${BLUE}[*] Alvo: ${TARGET_URL}${NC}"
    echo -e "${BLUE}[*] Diretório de saída: ${OUTPUT_DIR}${NC}"
    if [[ "$STEALTH_MODE" == "on" ]]; then
        echo -e "${PURPLE}[*] Modo Furtivo: ATIVADO (rate limiting + retries + UA customizado)${NC}"
    fi
    separator

    if [[ ! -f "$module_path" ]]; then
        echo -e "${RED}[!] Módulo não encontrado: ${module_path}${NC}"
        echo -e "${YELLOW}[*] Pressione ENTER para continuar...${NC}"
        read -r
        return 1
    fi

    # Ensure output directory exists
    mkdir -p "$OUTPUT_DIR"

    # Use array to preserve quoting
    local cmd=(python3 "$module_path" -u "$TARGET_URL" -o "$OUTPUT_DIR" "${stealth_args[@]}" $extra_args)
    echo -e "${YELLOW}[*] Executando: ${cmd[*]}${NC}"
    echo ""
    "${cmd[@]}"
    local exit_code=$?

    echo ""
    if [[ $exit_code -eq 0 ]]; then
        echo -e "${GREEN}[+] ${module_name} concluído com sucesso!${NC}"
        echo -e "${GREEN}[+] Resultados salvos em: ${OUTPUT_DIR}${NC}"
    else
        echo -e "${RED}[!] ${module_name} falhou com código de saída: ${exit_code}${NC}"
    fi

    echo -e "${YELLOW}[*] Pressione ENTER para continuar...${NC}"
    read -r
}

# -----------------------------------------------------------------------------
# Option 1: Pentest Completo OWASP Top 10
# whatweb -> nmap -> ffuf -> wpscan -> nuclei + WAF detection + injection tests
# -----------------------------------------------------------------------------
run_option1() {
    if [[ -z "$TARGET_URL" ]]; then
        echo -e "${YELLOW}[!] Defina uma URL alvo primeiro.${NC}"
        prompt_target
    fi

    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║  OPÇÃO 1: PENTEST COMPLETO OWASP TOP 10                       ║${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
echo -e "${YELLOW}Fluxo: whatweb -> nmap -> ffuf/gobuster -> wpscan -> nuclei${NC}"
    echo -e "${YELLOW}+ Testes ativos de injeção + Detecção de WAF${NC}"
    echo ""

    prompt_stealth_config

    # Run the full scan module with all features
    run_scan "scan_full.py" "Pentest Completo OWASP Top 10"
}

# -----------------------------------------------------------------------------
# Option 2: Varredura Rápida CVEs e Reconhecimento
# whatweb -> wpscan --enumerate p,u -> nuclei -tags cve (stealth mode)
# -----------------------------------------------------------------------------
run_option2() {
    if [[ -z "$TARGET_URL" ]]; then
        echo -e "${YELLOW}[!] Defina uma URL alvo primeiro.${NC}"
        prompt_target
    fi

    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║  OPÇÃO 2: VARREDURA RÁPIDA - CVEs E RECONHECIMENTO           ║${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Modo Stealth/Rápido: whatweb + wpscan (plugins/usuários) + nuclei (CVEs)${NC}"
    echo -e "${YELLOW}Cruza versões de plugins com banco NIST/WPScan${NC}"
    echo ""

    prompt_stealth_config

    # Ask if user wants to skip Nuclei CVE scan (faster, heuristic only)
    echo -e "${CYAN}Pular Nuclei CVE scan e usar apenas heurística passiva? (s/N):${NC}"
    read -rp $'\033[0;36m\033[1m>>> \033[0m' skip_nuclei
    local extra_args=""
    if [[ "$skip_nuclei" =~ ^[sS]$ ]]; then
        extra_args="--no-nuclei"
        echo -e "${GREEN}[+] Nuclei CVE scan será pulado (mais rápido)${NC}"
    fi
    echo ""

    run_scan "scan_quick.py" "Varredura Rápida - CVEs e Reconhecimento" "$extra_args"
}

# -----------------------------------------------------------------------------
# Option 3: Endpoints Comprometidos e Falhas de Design
# ffuf/gobuster -> robots.txt -> sitemap.xml -> REST API (curl + jq)
# -----------------------------------------------------------------------------
run_option3() {
    if [[ -z "$TARGET_URL" ]]; then
        echo -e "${YELLOW}[!] Defina uma URL alvo primeiro.${NC}"
        prompt_target
    fi

    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║  OPÇÃO 3: ENDPOINTS COMPROMETIDOS E FALHAS DE DESIGN         ║${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Fuzzing: ffuf/gobuster + robots.txt + sitemap.xml + WP REST API${NC}"
    echo -e "${YELLOW}Análise: /wp-json/wp/v2/users (enumeração usuários/IDOR)${NC}"
    echo ""

    run_scan "scan_endpoints.py" "Busca de Endpoints Comprometidos e Falhas de Design"
}

# -----------------------------------------------------------------------------
# Interactive Menu
# -----------------------------------------------------------------------------
main_menu() {
    while true; do
        banner

echo -e "${GREEN}╔════════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC} ${BOLD}                           WASPY - MENU DE OPERAÇÕES                           ${NC}${GREEN}║${NC}"
    echo -e "${GREEN}╠════════════════════════════════════════════════════════════════════════════════╣${NC}"
    if [[ "$STEALTH_MODE" == "on" ]]; then
        echo -e "${GREEN}║${NC}  ${PURPLE}🔒 Modo Furtivo: ATIVADO  |  UA: ${CUSTOM_UA:0:30}${GREEN}║${NC}"
    else
        echo -e "${GREEN}║${NC}  ${YELLOW}⚙ Modo Furtivo: DESATIVADO  |  UA: ${CUSTOM_UA:0:30}${GREEN}║${NC}"
    fi
    echo -e "${GREEN}║${NC}                                                                                ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  ${CYAN}1${NC}  ${GREEN}|${NC} ${YELLOW}Pentest completo OWASP Top 10${NC}                                            ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}       ${BLUE}(whatweb -> nmap -> ffuf -> wpscan -> nuclei + WAF detection)${NC}            ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}                                                                                ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  ${CYAN}2${NC}  ${GREEN}|${NC} ${YELLOW}Varredura rápida CVEs e reconhecimento${NC}                                   ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}       ${BLUE}(whatweb + wpscan enumerate p,u + nuclei tags=cve stealth)${NC}               ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}                                                                                ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  ${CYAN}3${NC}  ${GREEN}|${NC} ${YELLOW}Buscar endpoints comprometidos e falhas de design${NC}                        ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}       ${BLUE}(ffuf/gobuster + robots.txt + sitemap.xml + WP REST API)${NC}                 ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}                                                                                ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  ${CYAN}4${NC}  ${GREEN}|${NC} ${YELLOW}Alterar URL alvo${NC}                                                         ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                                                ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}5${NC}  ${GREEN}|${NC} ${YELLOW}Configurar Modo Furtivo (WAF Evasion)${NC}                                  ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                                                ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${RED}0${NC}  ${GREEN}|${NC} ${RED}Sair${NC}                                                                     ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                                                ${GREEN}║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════════════════╝${NC}"

        echo ""
        read -rp $'\033[0;36m\033[1mSelecione uma opção: \033[0m' choice
        echo ""

        case "$choice" in
            1)
                run_option1
                ;;
            2)
                run_option2
                ;;
            3)
                run_option3
                ;;
            4)
                prompt_target
                ;;
            5)
                prompt_stealth_config
                ;;
            0)
                echo -e "${RED}[*] Saindo do Waspy. Até logo!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Opção inválida: '${choice}'. Selecione 0-5.${NC}"
                echo ""
                ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# Entry Point
# -----------------------------------------------------------------------------
main() {
    banner
    check_tools

    if [[ -z "$TARGET_URL" ]]; then
        prompt_target
    fi

    main_menu
}

main "$@"
