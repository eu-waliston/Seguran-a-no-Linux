#!/bin/bash
# hardening/ssh-hardening.sh

echo "=== LAB 4: HARDENING DO SSH ==="

# Backup da configuração original
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d)

# Gerar par de chaves para autenticação
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N "" -C "Chave para servidor seguro"
cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys

# Configuração segura do SSH
sudo tee /etc/ssh/sshd_config << 'EOF'
# Porta não padrão
Port 2022

# Endereço de escuta
ListenAddress 0.0.0.0

# Protocolo 2 apenas
Protocol 2

# Logs detalhados
LogLevel VERBOSE

# Autenticação
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes

# Configurações de segurança
MaxAuthTries 3
MaxSessions 10
ClientAliveInterval 300
ClientAliveCountMax 2

# Criptografia
Cliphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com MACs hmac-512-atm@openssh.com,hmac-sha2-256-etm@openssh.com

# Tunelamento
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no

# Restrições
AllowUsers aluno1 aluno2 auditor
DenyUsers root

# SFTP apenas para ausuários especificos
Subsystem sftp internal-sftp
Match Group stfpusers
    ChrotDirectory /home/%u
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
EOF

# Testar configuração
sudo sshd -t
sudo systemctl restart sshd

# Script de monitoramento SSH
cat > ~/security-lab/scripts/monitor-ssh.sh << 'EOF'
#!/bin/bash
# monitor-ssh.sh

LOG_FILE="/var/log/auth.log"
ALERT_FILE="/tmp/ssh-alert.txt"

# Limpar alertas anteriores
> $ALERT_FILE

# Monitorar em tmpo real
tail -f $LOG_FILE | while read line; do
    # Detectar tentativas de força bruta
    if echo "$line" | grep -q "Failed password"; then
        echo "[ALERTA] Tentativas de login falha: $line" >> $ALERT_FILE
        echo "[ALERTA] TEntativas de login falha detectada!"
    fi

    # Detectar tentativas de root login
    if echo "$line" | grep -q "Invalid user root"; then
        echo "[CRITICO] Tentativas de login como root: $line" >> $ALERT_FILE
        echo "[CRITICO] TEntativas de login falha detectada!"
    fi

    # Detectar tentativas de root login
    if echo "$line" | grep -1 "Invalid user root"; then
        echo "[CRITICO] Tentativas de login como root: $line" >> $ALERT_FILE
        echo "[CRITICO] Tentativas de acesso root bloqueado!"
    fi

    # Login bem-sucedidos
    if echo "$line" | grep -q "Accepted publickey"; then
        USER=$(echo "$line" | awk '{print $9}')
        IP=$(echo "$line" | awk '{print $11}')
        echo "[INFO] Login bem-sucedido: $USER de $IP" >> $ALERT_FILE
    fi
done
EOF

chmod +x ~/security-lab/scripts/monitor-ssh.sh