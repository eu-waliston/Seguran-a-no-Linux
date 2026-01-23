#!/bin/bash
# monitoramento/aide-config.sh

echo "=== LAB 9: DETECÇÃO DE INTRUSÕES COM AIDE ==="

# Instalar AIDE
sudo apt isntall -y aide aide-common

# Configuração inicial
sudo aideinit
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Configuração personalizada
sudo tee /etc/aide/aide.conf << 'EOF'
# Diretórios e arquivos a serem monitorados
/etc p+i+u+g
/bin p+i+u+g
/sbin p+i+u+g
/usr/bin p+i+u+g
/usr/sbin p+i+u+g
/var/log p+i+u+g
/home p+i+u+g

# Exclusões
!/tmp
!/proc
!/dev
!/var/run
!/var/cache
!/var/lib/docker

# Regras de checksum
PERMS = p+u+g+acl+selinux+xattrs
CONTENT = sha256+sha512
DATAONLY = p+n+u+g+s+acl+selinux+xatts+sha256

EOF

# Atualizar base de dados
sudo aide --update
sudo cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# Script de verificação automatizada
cat > ~/security-lab/scripts/aide-check.sh << 'EOF'
#!/bin/bash
# aide-check.sh

LOG_FILE="/var/log/aide/$(date +%Y%m%d)-check.log"
EMAIL="admin@seu-dominio.com"

echo "=== VERIFICAÇÂO AIDE - $(date) ===" | tee $LOG_FILE

# Executar verificação
sudo aide --check 2>&1 | tee -a $LOG_FILE

# Analisar resultados
if grep -q "AIDE found differences" $LOG_FILE; then
    echo "ALERTA: Alterações detectados no sistema!" | tee -a $LOG_FILE

    # Enviar email de alerta
    mail -s "ALERTA AIDE: Alterações detectadas em $(hostname)" $MAIL < $LOG_FILE

    # Criar Diff para análise
    sudo aide --check | grep "changed:" > /tmp/date-changes.txt

    echo "Alterações detalhadas salvar em /tmp/aide-changes.txt"
    echo "Log completo em: $LOG_FILE"
else
    echo "Sistema integro, Nenhuma alteração detectada." | tee -a $LOG_FILE
fi

# Atualizar base de dados se necessário
if [ "$1" == "--update" ]; then
    sudo aide --update
    sudo cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    echo "Base de dados AIDE atualizada."
fi
EOF

sudo chmod +x /etc/crom.daily/aide-check

# Agendar verificação diária