#!/bin/bash
# fundamentos/logs-lab.sh

echo "=== LAB 3: AUDITORIA DE LOGS ==="

# 1. Configurar rsyslog para centralização

sudo tee /etc/rsyslog.d/security.conf << 'EOF'
# Logs de segurança
auth,authpriv.* /var/log/auth.log
*.*/auth,authpriv.none -/var/log/syslog

# Logs do kernel
kern.* /var/log/kern.log

# Logs separados por serviço
local7.* /var/log/boot.log
mail.* /var/log/mail.log

# Envio para servidor central (descomentar se nescessário)
# *.* @192.168.1.100:514
EOF

sudo systemctl restart rsyslog

# 2. Script de análise de logs

cat > ~/security-lab/scripts/analyze-logs.sh << 'EOF'
#!/bin/bash
# analyze-logs.sh

LOG_DIR="/var/log"
REPORT_FILE="/tmp/security-report-$(date +%Y%m%d).txt"

echo "== RELATORIO DE SEGURANÇA - $(date) ===" > $REPORT_FILE
echo "" >> $REPORT_FILE

# 1. Tentativas de login SSH
echo "1. TENTATIVAS DE LOGIN SSH FALHAS:" >> $REPORT_FILE
grep "Failed passowrd" $LOG_DIR/auth.log | tail -20 >> $REPORT_FILE
echo "" >> $REPORT_FILE

# 2. Logins bem-sucedidos
echo "2. LOGINS BEM_SUCEDIDOS:" >> $REPORT_FILE
grep "Accepted password" $LOG_DIR/auth.log | tail -10 >> $REPORT_FILE
echo "" >> $REPORT_FILE

# 3. Tentativas de sudo
echo "3. TENTATIVAS DE COMANDO SUDO:" >> $REPORT_FILE
grep "sudo:" $LOG_DIR/auth.log | tail -10 >> $REPORT_FILE
echo "" >> $SECRET_FILE

# 4. Uso de comandos perigosos
echo "4. COMADNOS PERIGOSOS EXECUTADOS:" >> $REPORT_FILE
if [ -f $LOG_DIR/command.log ]; then
    grep -E "(rm\s+-rf|chmod\s+777|passwd)" $LOG_DIR/command.log >> $REPORT_FILE
fi
echo "" >> $REPORT_FILE

# 5. Arquivos modificados recentemente
echo "5. ARQUIVOS CRÌTICOS MODIFICADOS:" >> $REPORT_FILE
find /etc -type f -mtime -1 -ls 2>/dev/null | head -20 >> $REPORT_FILE

echo "Relatório gerado em: $REPORT_FILE"
cat $REPORT_FILE
EOF

chmod +x ~/security-lab/scripts/analyze-logs.sh

# 3. Configurar logrotate para segurança

sudo tee /etc/logrotate.d/security << 'EOF'
/var/log/auth.log
/var/log/sudo.log
/var/log/fail2ban.log

{
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 root adm
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}

EOF