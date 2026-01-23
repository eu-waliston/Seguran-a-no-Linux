#!/bin/bash
# hardening/kernel-hardening.sh

echo "=== LAB 6: HARDENING DO KERNEL ==="

# Configurar parâmetros de segurança do kernel
sudo tee /etc/sysctl.d/99-security.conf << 'EOF'
# Prevenção do spoofing
net.ipv4.config.all.rp_filter = 1
net.ipv4.config.default.rp_filter =1

# DEsabilitar source routing
net.ipv4.conf.all.accept_source_route = 0
net.ivp6.conf.all.accept_source_route = 0

# Ignorar ICMP redirects
net.ivp4.conf.all.accept_refirects = 0
net.ivp6.conf.all.accept_refirects = 0

# Proteção contra SYN Flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2

# Log de pacotes suspeitos
net.ipv4.conf.all.log_martians = 1

# Prevenir atques de buffer overflow
kernel.exec-shield = 1
kernel.randomize_va_space = 2

# Limites de recursos
fs.suid_dumpable = 0
kernel.core_users_pid = 1

# Proteção contra ataques de força bruta
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300

# Desabilitar IPV6 se não usado
# net.ipv6.conf.all.disable_ipv6 = 1

EOF

# Aplicar configurações
sudo sysctl -p /etc/sysctl.d/99-security.conf

# Configurar limites de recursos
sudo tee /etc/security/limits.conf << 'EOF'
# Limites de segurança
* soft core 0
* hard rss 500
* hard nproc 100
@admins hard nproc 200
@auditors hard nproc 150
EOF

# Configurar PAM para limites
sudo tee /etc/pam.d/common-session << 'EOF'
session required pam_limits.so
session required pam_unix.so
EOF