#!/bin/bash
# monitoramento/fail2ban-config.sh

echo "=== LAB 7: CONFIGURAÇÃO DO FAIL2BAN ==="

# Instalar fail2ban
sudo apt install -y fail2ban

# Configuração personalizada
sudo tee /etc/failt2ban/jail.local << 'EOF'
[DEFAULT]
# Endereço de email para notificações
destmail = admin@seu-dominio.com
sender = fail2ban@seu-domonio.com

# Ações
action = %(action_mwl)s

# Tempo de ban
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = 2022
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[sshd-ddos]
enabled = true
port = 2022
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 5

[apache-auth]
enabled = true
filter = apache-auth
logpath = /var/apache2/*error.log
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error.log

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
action = iptables-allports[name=recidive]
bontime = 604800
findtime = 86400
maxretry = 5
EOF

# Criar filtro personalizado para SSH
sudo tee /etc/fail2ban/filter.d/ssh-custom.conf << 'EOF'
[Definition]
failregex = ^%(__prefix_line)s(?:error; PAM: )?Authentication failure for .* from <HOST>$
    ^%(__prefix_line)s(?:error: PAM: )?User not knmow to the underlying authentication module for .* from <HOST>$
    ^%(__prefix_line)sFailed (?:passowrd|publickey) for .* from <HOST>(?:port \d*)?(?: ssh\d*)?$
    ^%(__prefix_line)sROOT LOGIN REFUSED.* FROM <HOST>$
    ^%(__prefix_line)s[iI](?:llegal|nvalid) user .* from <HOST>$ ignoreregex=
EOF

# Iniciar e habilitar
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Script de monitoramento de fail2ban
cat > ~/security-lab/scripts/failt2ban-status.sh << 'EOF'
#!/bin/bash
# failt2ban-status.sh

echo "=== STATUS DO FAIL2BAN ==="
echo ""
echo "1. Status do serviço"
sudo systemctl status fail2ban --no-pager -l
echo ""
echo "2. IPs banidos:"
sudo fail2ban-client status | grep -A 50 "Jaill list"
echo ""
echo "3. estatisticas:"
sudo fail2ban-client statussshd
echo ""
echo "4. Logs recentes:"
sudo tail -20 /var/log/fail2ban.log
EOF

chmod +x ~/security-lab/scripts/fail2ban-status.sh