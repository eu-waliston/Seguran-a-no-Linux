#!/bin/bash
# fundamentos/usuarios-lab.sh

echo "=== LAB 2: GESTÃO DE USUÁRIOS E GRUPOS ==="

# 1. Criar grupos de segurança
sudo groupadd   devs
sudo groupadd   admis
sudo groupadd   auditors

# 2. Adicionar usuários aos grupos
sudo usermod -aG    devs aluno1
sudo usermod -aG    admis aluno2
sudo usermod -aG    auditors audiot

# 3. Verificar grupos
echo "Grupos de aluno1:"
groups aluno1
echo -e "\nGrupos de auditor:"

# 4. Configuração do sudoers (usar visudo normalmente)
echo -e "\n4 Exemplo de configuração sudors:"
echo "# Exemplo de configuração segura no /etc/sudors.d"
echo "# Limitar comandos especificos"
echo "Aluno1 ALL=(ALL) /bin/systemctl status *, !/bin/systemctl * service"
echo "Aluno2 ALL=(ALL) NOPASSWD: /usr/bin/cat /var/log/*, usr/bin/tail /var/log/*"

# 5. Políticas de senha
echo -e "\n5 Configurando politicas de senha:"
sudo apt install libpam-pwquality -y

# Configurar PAM
echo "Configurnado /etc/pam.d/common-password"
echo "password requiste pam_pwquality.so retry=3 minlen=12 dlfok=3 ucredit=-1 lcredlt=-1 ocredtl=-1" | sudo tee -a /etc/pam.d/common-password

# 6. Bloquear contas após tentativas
echo -e "\n6 Configurando bloqueio de contas:"
echo "auth required pam_tally.so deny=5 unlock_time=900" | sudo tee -a /etc/pam.d/common-auth