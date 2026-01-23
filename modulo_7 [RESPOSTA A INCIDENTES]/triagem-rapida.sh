#!/bin/bash
# modulo7/scripts/triagem-rapida.sh

echo "=== SCRIPT DE TRIAGEM RÁPIDA - LINUX ==="

# Configurações
INCIDENT_ID="INC-$(date +%Y%m%d-%H%M%S)"
OUTPUT_DIR="/forensics/$INCIDENT_ID"
mkdir -p "$OUTPUT_DIR"

# Função para log
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$OUTPUT_DIR/triage.log"
}

# Coletar informações do sistema
collect_system_info() {
    log "Coletando informações do sistema..."

    # Informações básicas
    {
        echo "=== HOST INFORMATION ==="
        echo "Hostname: $(hostname)"
        echo "Domain: $(domainname 2>/dev/null || echo 'N/A')"
        echo "Kernel: $(uname -r)"
        echo "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2)"
        echo "Uptime: $(uptime)"
        echo "Date: $(date)"
        echo "Timezone: $(timedatectl | grep 'Time zone' 2>/dev/null || echo 'N/A')"
    } > "$OUTPUT_DIR/01_system_info.txt"
}

# Coletar informações de usuários
collect_user_info() {
    log "Coletando informações de usuários..."

    {
        echo "=== USER INFORMATION ==="
        echo ""
        echo "Usuários logados:"
        who -a

        echo ""
        echo "Últimos logins:"
        last -20

        echo ""
        echo "Usuários no sistema:"
        awk -F: '{print $1 ":" $3 ":" $6}' /etc/passwd

        echo ""
        echo "Histórico de comandos por usuário:"
        for user in $(ls/home); do
            if [ -f "/home/$user/.bash_history" ]; then
                echo "=== $user ==="
                tail -50 "/home/$user/.bash_history"
                echo ""
            fi
        done
    } > "$OUTPUT_DIR/02_user_info.txt"
}

# Coletar informações de processos
collect_process_info() {
    log "Coletando informações de processos..."

    {
        echo "=== PROCESS INFORMATION ==="
        echo ""
        echo "Processos em execução (tree):"
        pstree -paul

        echo ""
        echo "Top processos por CPU:"
        ps aux --sort=-%cpu | head -20

        echo ""
        echo "Top processos por MEM:"
        ps aux --sort=-%mem | head -20

        echo ""
        echo "Processos com conexões de rede:"
        lsof -i 2>/dev/null | head -50

        echo ""
        echo "Cron jobs:"
        for user in $(cut -f1 -d: /etc/passwd); do
            echo "=== $user ==="
            crontab -l -u $user 2>/dev/null || echo "Nenhum cron"
            echo ""
        done
    } > "$OUTPUT_DIR/03_process_info.txt"
}

# Coletar informações de rede
collect_network_info() {
    log "Coletando informações de rede..."

    {
        echo "=== NETWORK INFORMATION ==="
        echo ""
        echo "Interfaces de rede:"
        ip addr show

        echo ""
        echo "Roteamento:"
        ip route show

        echo ""
        echo "Conexões ativas:"
        ss -tulpn

        echo ""
        echo "Conexões estabelecidas:"
        netstat -tunp | grep ESTABLISHED

        echo ""
        echo "ARP table:"
        ip neigh show

        echo ""
        echo "DNS servers:"
        cat /etc/resolv.conf

        echo ""
        echo "Hosts file:"
        cat /etc/hosts
    } > "$OUTPUT_DIR/04_network_info.txt"
}

# Coletar informações de arquivos
collect_file_info() {
    log "Coletando informações de arquivos..."

    {
        echo "=== FILE SYSTEM INFORMATION ==="
        echo ""
        echo "Partições montadas:"
        df -h
        mount

        echo ""
        echo "Arquivos modificados recentemente (últimas 24h):"
        find /etc -type f -mtime -1 -ls 2>/dev/null | head -50

        echo ""
        echo "Arquivos executáveis modificados (últimos 7 dias):"
        find /bin /sbin /usr/bin /usr/sbin -type f -mtime -7 -ls 2>/dev/null

        echo ""
        echo "Arquivos com SUID/SGID:"
        find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null | head -50

        echo ""
        echo "Arquivos ocultos em diretórios home:"
        for dir in /home/* /root; do
            if [ -d "$dir" ]; then
                echo "=== $dir ==="
                find "$dir" -name ".*" -type f -ls 2>/dev/null | head -20
            fi
        done
    } > "$OUTPUT_DIR/05_file_info.txt"
}

# Coletar logs do sistema
collect_logs() {
    log "Coletando logs do sistema..."

    # Logs de autenticação
    for logfile in /var/log/auth.log /var/log/secure /var/log/messages; do
        if [ -f "$logfile" ]; then
            cp "$logfile" "$OUTPUT_DIR/logs/"
            # Extrair eventos suspeitos
            grep -E "(Failed|Invalid|authentication failure)" "$logfile" > \
                "$OUTPUT_DIR/logs/suspicious_auth_$(basename $logfile).txt"
        fi
    done

    # Logs do sistema
    {
        echo "=== SYSTEM LOGS (últimas 1000 linhas) ==="
        journalctl -n 1000 --no-pager
    } > "$OUTPUT_DIR/06_system_logs.txt"

    # Logs específicos
    for service in ssh sudo cron; do
        if journalctl -u $service.service &>/dev/null; then
            journalctl -u $service.service -n 100 --no-pager > \
                "$OUTPUT_DIR/logs/${service}_logs.txt"
        fi
    done
}

# Análise de malware
analyze_malware() {
    log "Realizando análise básica de malware..."

    {
        echo "=== MALWARE ANALYSIS ==="
        echo ""
        echo "Verificando processos suspeitos:"
        ps aux | grep -E "(cryptominer|minerd|xmrig|backdoor|shell)"

        echo ""
        echo "Conexões para IPs suspeitos:"
        ss -tulpn | grep -E "(185\.|45\.9\.|tor-exit)"

        echo ""
        echo "Arquivos em /tmp suspeitos:"
        find /tmp -type f -exec file {} \; | grep -E "(ELF|executable|script)"

        echo ""
        echo "Verificando rootkits:"
        if command -v rkhunter >/dev/null; then
            rkhunter --check --sk 2>&1 | tail -50
        fi
    } > "$OUTPUT_DIR/07_malware_analysis.txt"
}

# Gerar relatório
generate_report() {
    log "Gerando relatório de triagem..."

    cat > "$OUTPUT_DIR/00_TRIAGEM_REPORT.md" << EOF
# RELATÓRIO DE TRIAGEM RÁPIDA
## Incidente: $INCIDENT_ID
## Data/Hora: $(date)
## Sistema: $(hostname)

## RESUMO EXECUTIVO
Análise inicial realizada em resposta ao incidente. Foram coletadas evidências
e identificados indicadores de comprometimento.

## INDICADORES DE COMPROMETIMENTO (IOCs)

### 1. Processos Suspeitos
\`\`\`
$(grep -A5 "suspeitos" "$OUTPUT_DIR/07_malware_analysis.txt" 2>/dev/null || echo "Nenhum processo suspeito identificado")
\`\`\`

### 2. Conexões de Rede Anormais
\`\`\`
$(grep -A5 "IPs suspeitos" "$OUTPUT_DIR/07_malware_analysis.txt" 2>/dev/null || echo "Nenhuma conexão suspeita identificada")
\`\`\`

### 3. Tentativas de Acesso Falhas
\`\`\`
$(head -20 "$OUTPUT_DIR/logs/suspicious_auth_"*.txt 2>/dev/null | head -20 || echo "Nenhuma tentativa suspeita")
\`\`\`

## AÇÕES RECOMENDADAS
1. [] Isolar sistema da rede
2. [] Preservar evidências para análise forense
3. [] Notificar equipe de segurança
4. [] Iniciar procedimentos de contenção

## PRÓXIMOS PASSOS
- Análise forense completa
- Varredura com antivírus
- Verificação de backups
- Comunicação com partes interessadas

---
*Relatório gerado automaticamente pelo script de triagem*
EOF
}

# Main execution
main() {
    echo "🚨 INICIANDO TRIAGEM RÁPIDA - Incidente: $INCIDENT_ID"
    echo "📁 Output: $OUTPUT_DIR"
    echo ""

    collect_system_info
    collect_user_info
    collect_process_info
    collect_network_info
    collect_file_info
    collect_logs
    analyze_malware
    generate_report

    echo ""
    echo "✅ Triagem concluída!"
    echo "📄 Relatório: $OUTPUT_DIR/00_TRIAGEM_REPORT.md"
    echo "📋 Log de atividades: $OUTPUT_DIR/triage.log"

    # Calcular hashes para integridade
    echo ""
    echo "🔐 Calculando hashes para integridade..."
    find "$OUTPUT_DIR" -type f -exec sha256sum {} \; > "$OUTPUT_DIR/evidence_hashes.txt"

    echo "🎯 Próximos passos:"
    echo "1. Review do relatório"
    echo "2. Isolamento do sistema se necessário"
    echo "3. Escalonamento para análise forense"
}

# Run main function
main