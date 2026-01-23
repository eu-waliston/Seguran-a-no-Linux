#!/bin/bash
# modulo7/ir-kit/setup-ir-kit.sh

echo "=== SETUP DO KIT DE RESPOSTA A INCIDENTES ==="

# Criar estrutura de diretórios
mkdir -p ~/ir-kit/{bin,tools,evidence,playbooks,report-templates}
mkdir -p ~/ir-kit/evidence/{memory,disk,network,logs,artifacts}
mkdir -p ~/ir-kit/tools/{windows,linux,macos,network}

# Instalar ferramentas essenciais
echo "Instalando ferramentas forenses..."
sudo apt update
sudo apt install -y \
    # Coleta de evidências
    ddrescue gddrescue dcfldd dc3dd \
    # Análise forense
    sleuthkit autopsy foremost scalpel bulk-extractor \
    # Análise de memória
    volatility3 rekall avml lime-forensics \
    # Análise de rede
    wireshark tcpdump netsniff-ng ntopng \
    # Análise de malware
    yara radare2 cutter binwalk strings \
    # Utilitários
    htop iotop iftop nethogs pstree lsof \
    # Documentação
    asciinema termtosvg

# Configurar ambiente
cat > ~/ir-kit/.env << 'EOF'
IR_TEAM_EMAIL="csirt@empresa.com"
IR_LEAD_PHONE="+55-11-99999-9999"
LEGAL_CONTACT="juridico@empresa.com"
EVIDENCE_PREFIX="EVID-$(date +%Y%m%d)"
HASH_ALGORITHM="sha256"
EOF

# Script de inicialização do IR
cat > ~/ir-kit/bin/init-ir.sh << 'EOF'
#!/bin/bash
# Inicialização de Resposta a Incidentes

source ~/ir-kit/.env

echo "=========================================="
echo "🚨 INICIALIZAÇÃO DE RESPOSTA A INCIDENTES"
echo "=========================================="
echo "Data/Hora: $(date)"
echo "Caso ID: $EVIDENCE_PREFIX"
echo "=========================================="

# Criar diretório do caso
CASE_DIR="~/ir-kit/cases/$EVIDENCE_PREFIX"
mkdir -p $CASE_DIR/{timeline,evidence,logs,screenshots}

# Iniciar log de atividades
exec > >(tee -a "$CASE_DIR/activity.log") 2>&1

# Coletar informações iniciais
echo "Coletando informações do sistema..."
{
    echo "=== SISTEMA INFORMATION ==="
    uname -a
    hostname
    date
    uptime
    who
    last -20

    echo "=== REDE INFORMATION ==="
    ip addr
    ip route
    ss -tulpn
    netstat -rn

    echo "=== PROCESSOS ==="
    ps aux --sort=-%cpu | head -20
    top -b -n 1 | head -30
} > "$CASE_DIR/initial_triage.txt"

echo "Caso inicializado em: $CASE_DIR"
echo "Execute 'triagem-rapida.sh' para começar análise"
EOF

chmod +x ~/ir-kit/bin/*.sh