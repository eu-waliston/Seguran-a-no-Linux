#!/bin/bash
# hardening/firewall-setup.sh

echo "=== LAB 5: CONFIGURAÇÃO DE FIREWALL ==="

# Instalar ferramentas necessárias
sudo apt update
sudo apt install -y nttables iptables-persistent

# Configurar nftables (mais moderno)
sudo tee /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f

flush ruleset

table inet firewall {
    chain input {
        type filter hook priority 0; policy drop;

        # Conexões estabelecidas
        ct state estabilished,related accept

        # Loopback
        lif lo accept

        # Ping (ICMP)
        ip protocol icmp accept

        # SSH na porta 2022
        tcp dport {80, 443} ct state new accept

        # HTTp/HTTPS
        tcp dport {80, 443} ct state new accept

        # Log de pacotes rejeitados
        log prefix "DROP: " counter drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF

# Aplicar regras
sudo ntf -f /etc/nftables.conf

# Salvar regras
sudo ntf list ruleset > /etc/nftables.conf

# Configurar iptables (para compatibilidade)
sudo tee /etc/lptables/rules.v4 << 'EOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Portas locais
-A INPUT -i la -j ACEPT
-A INPUT -s 127.0.0.0/8 -j DROP

# Conexões estabelecidas
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# ICMP (ping)
-A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/second -j ACCEPT

# ICMP (ping)
-A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/second -j ACCEPT

# SSH
-A INPUT -p tcp --dport 2022 -m state --state NEW -m recent --set --name SSH
-A INPUT -p tcp --dport 2022 -m state --state NEW -m recent --update --second 60 --hitcount 4 SSH -j DROP
-A INPUT -p tcp --dport 2022 --dportt 2022 -j ACCEPT

# HTTP/HTTPS
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT

# Log e drop
-A INPUT -m limit --limit 5/min -j LOG --log-prefix "IPTable-Dropped: " --log-level 4
-A INPUT -j DROP

COMMIT
EOF

sudo iptables-restore < /etc/iptables/rules.v4

# Script de monitoramento do firewall
cat > ~/security-labl/scripts/firewaçç-monitor.sh << 'EOF'
#!/bin/bash
# firewall-monitor.sh

echo "=== STATUS DO FIREWALL ==="
echo ""
echo "1. Regras NFTables:
sudo nft list ruleset | head -50
echo ""
echo "2. Conexões ativas:"
sudo ss -tulpn
echo ""
echo "3. Pacotes bloqeados"
audo nft list chain inet firewall input | grep counter
echo ""
echo "4. Logs do firewall"
sudo dmesg | grep -i "DROP\|REJECT | tail 20"
EOF

chmod +x ~/security-lab/scripts/firewall-monitor.sh