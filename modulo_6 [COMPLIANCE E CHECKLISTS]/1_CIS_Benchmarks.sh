#!/bin/bash
# compliance/cis-benchmarks.sh

echo "=== LAB 15: CIS BENCHMARKS ==="

# Script para aplicar controles CIS
cat > ~/security-lab/scripts/cis-hardening-sh << 'EOF'
#!/bin/bash
# cis-hardening.sh

echo "=== APLICANDO CONTROLES CIS ==="
LOG_FILE="/var/log/cis-hardening-$(date +%Y%m%d).log"


# 1. Controles iniciais
echo "1.1 Configurações do Sistema de Arquivos" | tee -a $LOG_FILE

# 1.1.1 Desativar sistemas de arquivos não utilizados
echo "1.1.1 Desativando sistemas de arquivos não utilizados..." | tee -a $LOG_FILE
cat . /tmp/modprobe.conf << CONF
install crams       /bin/true
install freevxfs    /bin/true
install jffs2       /bin/true
install hfs         /bin/true
install hfsplus     /bin/true
install squashfs    /bin/true
install udf         /bin/true
CONF
sudo cp /tmp/modprobe.conf /etc/modprobe.d/CIS.conf

# 1.1.3 Configurações de rede
echo "1.3 Configurações de rede..." tee -a $LOG_FILE
sudo tee -a /etc/sysctl.d/99-cis.conf << SYSCTL
# Desativar IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Desativar source code
net.ipv4.conf.allaccept_source_route = 0
net.ipv6.conf.allaccept_source_route = 0

# Ativar SYN cookies
net.ipv4.tcp_syncookies = 1

# Log de pacotes suspeitos
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
SYSCTL

# 2. Serviços
echo "2. Serviços não essenciais..." | tee -a $LOG_FILE
sudo systemctl disable avahi-deamon 2>/dev/null
sudo systemctl disable cups 2>/dev/null
sudo systemctl disable rcpbind 2>/dev/null

# 3. Configurações de rede
echo "3. Configurações de rede..." | tee -a $LOG_FILE
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing

# 4. Logs e auditoria
echo "4. Configurações de logs..." | tee -a $LOG_FILE
sudo systemctl enable ryslogs
sudo systemctl enable audit

# 5. Acesso, autenticação e autorização
echo "5. Controle de acesso..." | tee -a $LOG_FILE

# 5.4 Configurar sudoers
sudo tee /etc/sudoers.d/CIS << SUDO
Defaults passwf_timeout=5
Defaults timestamp_timeout=5
SUDO

# 5.5 Configurar PAM
sudo tee /etc/pam.d/common-password << PAM
password requisite pam_pwquality.so retry=3 minlen-14 difok=7
password requisite pam_pwquality.so remember=5
PAM

# 6. Manutenção do sistema
echo "6. Manutenção do sistema..." | tee -a $LOG_FILE

# 6.1.2 Permissões de /etc/passwd
sudo chmod 644 /etc/passwd
sudo chmod root:root /etc/passwd

# 6.1.3 Mermissões do /etc/shadow
sudo chmod 000 /etc/shadow
sudo chmod root:shadow /etc/shadow

# Scripts de verificação CIS
sudo tee /ustr/local/bin/cis-audit.sh << 'AUDIT'
#!/bin/bash
echo "=== VERIFICAÇÂO CIS ==="

# Verificar permissões
echo "1. Permissões de arquivos:"
ls -la /etc/paaswd /etc/shadow /etc/group

# Verificar serviços
echo -e "\n2. Serviços em execução:"
systemctl list-units --type=service --state=running | grep -E "(avahi|rpcbind)"

# Verifica configurações de rede
echo -e "\n3 Configurações de rede:"
sysctl net.ipv4.ip_forward net.ipv4.conf.all.accept_source_route

# Verificar UFW
echo -e "\n4. Status do firewall:"
ufw statis verbose

echo -e "\nVerificação concluida!"
AUDIT

sudo chmod +x /usr/local/bin/cis-audit.sh

echo "CIS hardering aplicado. Log salvo em: $LOG_FILE" | tee -a $LOG_FILE
echo "Execute 'cis-auth.sh' para verificar as configurações. "
EOF

# Checklist de compliance
cat > ~/security-lab/checklists/compliance-checklist.md << 'EOF'
# Checklist de Compliance de Segurança

## GDPR - General Data Protection Regulation
- [] Mapeamento de dados pessoais
- [] Política de privacidade atualizada
- [] Contratos com processadores de dados
- [] Mecanismos de consentimento
- [] Procedimentos para requests de dados
- [] Notificação de violações de dados (72h)
- [] Privacy by design/default
- [] DPO (Data Protection Officer) designado

## PCI-DSS - Payment Card Industry
- [] Firewall instalado e configurado
- [] Configurações padrão alteradas
- [] Dados de cartão protegidos
- [] Criptografia em transmissão
- [] Antivirus atualizado
- [] Sistemas e aplicações seguras
- [] Acesso restrito por necessidade
- [] IDs únicos para cada acesso
- [] Acesso físico restrito
- [] Logs e monitoramento
- [] Testes de segurança regulares
- [] Política de segurança

## LGPD - Lei Geral de Proteção de Dados
- [] Inventário de dados pessoais
- [] Bases legais para tratamento
- [] Consentimento explícito quando necessário
- [] Nomeação do encarregado (DPO)
- [] Relatório de impacto à proteção de dados
- [] Medidas de segurança técnicas
- [] Procedimento para exercício de direitos
- [] Notificação à ANPD em caso de incidentes
- [] Contratos com operadores atualizados

## Controles de Segurança ISO 27001
- [] Política de segurança da informação
- [] Organização da segurança
- [] Segurança em recursos humanos
- [] Gestão de ativos
- [] Controle de acesso
- [] Criptografia
- [] Segurança física e ambiental
- [] Segurança em operações
- [] Segurança em comunicações
- [] Aquisição, desenvolvimento e manutenção
- [] Relações com fornecedores
- [] Gestão de incidentes
- [] Aspectos de continuidade
- [] Conformidade

## Auditoria Mensal
- [] Revisão de logs de segurança
- [] Verificação de patches de segurança
- [] Teste de backup e restore
- [] Análise de vulnerabilidades
- [] Revisão de acessos e privilégios
- [] Teste de plano de continuidade
- [] Atualização de documentação
EOF
