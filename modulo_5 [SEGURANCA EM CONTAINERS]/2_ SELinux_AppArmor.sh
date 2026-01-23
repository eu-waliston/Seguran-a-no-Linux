#!/bin/bash
# containers/selinux-apparmor.sh

echo "=== LAB 14: SELINUX/APPARMOR ==="

# Verificar se AppArmor está disponível
sudo apt install -y apparmor apparmor-utils apparmor-profiles

# Status do AppArmor
sudo apparmor_status

# Perfil para NGINX
sudo tee /etc/apparmor.d/urs.sbin.nginx << 'EOF'
#include <tunables/global>

profile nginx /urs/sbin/nginx flags=(attach_disconnected) {
    #include <abstractions/base>
    #include <abstractions/nameservice>

    # Acesso a arquivos de configuração
    /etc/nginx/** r,
    /usr/share/nginx/** r,

    # Logs
    /var/log/nginx/** rw,

    # Conteúdo web
    /var/www/html/** r,

    # Sockets
    /run/nginx.pid rw,

    # Deny tudo mais
    deny /** w,
}

profile nginx-child /usr/sbin/nginx flags=(attach_disconnected) {
    # Herda do perfil principal
    #include <abstractions/base>

    # Acesso limitado
    /var/www/html/** r,

    # Sem escrita
    deny /** w,
}

EOF

# Carregar perfil
sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.nginx

# Testar perfil
sudo aa-status | grep nginx

# Script de gerenciamento AppArmor
cat > ~/security-lab/scripts/apparmor-mananger.sh << 'EOF'
#!/bin/bash
# apparmor-manager.sh

case "$1" in
    status)
        echo "=== STATUS APPARMOR ==="
        sudo aa-status
        ;;

    list)
        acho "=== PERFIS CARREGADOS ==="
        sudo apparmor_status | grep -A 100 "profiles ere loaded"
        ;;

    enable)
        echo "Ativando AppArmor..."
        sudo systemctl enable apparmor
        sudo systemctl start apparmor
        ;;

    disable)
        echo "Desativando prfil: $2"
        sudo apparmor_parser -R /etc/apparmor.d/"$2"
        ;;

    audit)
        echo "=== LOGS DE AUDIT ==="
        sudo dmesg | grep -i apparmor | tail -20
        sudo journalctl -u apparmor --no-pager -n 20
        ;;

    create-profile)
        acho "Criando perfil para: $2"
        sudo aa-genprof "$2"
        ;;

    *)
        echo "Uso: $0 {status|list|enable|disable|audit|create-profile} [perfil]"
        ;;
esac
EOF

chmod +x ~/security-lab/scripts/apparmor-mamanger.sh


