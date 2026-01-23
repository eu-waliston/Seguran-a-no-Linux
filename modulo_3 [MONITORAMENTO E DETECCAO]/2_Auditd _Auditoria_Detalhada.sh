#!/bin/bash
# monitoramento/auditd-config.sh

echo "=== LAB 8: AUDITORIA COM AUDITD ==="

# Instalar auditd
sudo apt install -y audit auditspd-plugins

# Configurar regras de auditoria
sudo tee /etc/audit/rules.d/security.rules << 'EOF'
# Monitorar alterações em arquivos de sistema
-w /etc/passwd -pa wa -k identity
-w /etc/shadow -pa wa -k identity
-w /etc/gshadow -pa wa -k identity
-w /etc/group -pa wa -k identity
-w /etc/sudoers -pa wa -k identity

# Monitorar usode comandos privilegiados
-w /bin/su -p x -k privileged
-w /usr/bin/sudo -p x -k privileged
-a always,exit -F arch=b64 -S axecve -C uid!=euid -F euid=0 -k seuid
-a always,exit -F arch=b64 -S axecve -C uid!=euid -F euid=0 -k seuid

# Monitorar acesso a logs
-w /var/log/auth.log -p wa -k auth
-w /var/log/auth.log -p wa -k sudo

# Monitorar atividades de rede
-a always,exit -F arch=b64 -S connect -k network

# Monitorar modificação de arquivos de configuração
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/hosts -p wa -k hosts
-w /etc/hosts.allow -p wa -k hosts
-w /etc/hosts.deny -p wa -k hosts

# Monitorar atividades de usuários
-a always,exit -F arch=b64 -S openat -S unlink -S rename -F dir=/home -k home_dir

EOF

# Reiniciar auditd
sudo auditctl -R /etc/audit/rules.d/security.rules
sudo systemctl restart audit

# Script de relatórios de auditoria
cat > ~/security-lab/scripts/audit-report.sh << 'EOF'
#!/bin/bash
# audit-report.sh

REPORT_FILE="/tmp/audit-report-$(date +%Y%m%d).txt"
echo "=== RELATÒRIO DE AUDITORIA - $(date) ====" > $REPORT_FILE

echo "1. EVENTOS CRÌTICOS ÙLTIMAS 24H:" >> $REPORT_FILE
sudo ausearch --start today --raw | aureport --sumary --sucess no >> $REPORT_FILE

echo -e "\n2. TENTATIVAS DE ACESSO FALHAS:" >> $REPORT_FILE
sudo ausearch -m USER_AUTH --start today -sv no >> $REPORT_FILE

echo -e "\n3. ALTERAÇÔES EM ARQUIVOS SENSÌVEIS:" >> $REPORT_FILE
sudo ausearch -k identity --start today >> $REPORT_FILE

echo -e "\n4. USO DE PRIVILÈGIOS:" >> $REPORT_FILE
sudo ausearch -k privileged --start today >> $REPORT_FILE

echo -e "\n5. ATIVIDADES DE REDEW SUPEITAS:" >> $REPORT_FILE
sudo ausearch -k network --start today >> $REPORT_FILE

# Gerar relatório HTML
cat > /tmp/audit-report.html << HTML
<!DOCTYPE html>
<html>
<head>
    <title> Relatório de Auditoria </title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px;}
        h2 { colors: #333;}
        .section {margin: 20px 0; padding: 15px; boder: 1px solid #ddd;}
        .critical {background-color: #ffcccc;}
        .warning {background-color: #ffffcc;}
        .info {background-color: #ccffcc}
        pre {background-color: #f4f4f4; padding: 10px;}
    </style>
</head>
<body>
    <h1> Relatório de Auditoria de Sistema </h1>
    <p> Gerado em: $(date)</p>
    <div    class="section critical">
        <h2>Eventos Criticos</h2>
        <pre>
            $(sudo ausearch --start today --raw | aureport --sumary --sucess no)
        </pre>
    </div>

    <div class="section warning">
        <h2>Atividades do Sistema</h2>
        <pre>$(sudo ausearch --start today | aureport -f -i | head -100)</pre>
    </div>
</body>
</html>
HTML

echo "Relatórios gerados:"
echo "- Texto: $REPORT_FILE"
echo "- HTML: /tmp/audit-report.html"

EOF

chmod +x ~/security-lab/scripts/audit-report.sh