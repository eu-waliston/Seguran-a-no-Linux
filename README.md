# 🛡️ Projeto de Segurança no Linux - Do Básico ao Avançado
## 📋 Visão Geral
Este projeto abrange desde conceitos fundamentais até técnicas avançadas de segurança em sistemas Linux, com exemplos práticos e configurações reais para hardening.

## 📁 Estrutura do Projeto
```

linux-security-project/
│
├── fundamentos/
│   ├── permissões-linux/
│   │   ├── exemplos-chmod.md
│   │   └── script-permissoes.sh
│   ├── usuarios-grupos/
│   │   ├── gestao-usuarios.md
│   │   └── sudoers-config/
│   └── auditoria-log/
│       ├── rsyslog-config/
│       └── log-analysis.sh
│
├── hardening/
│   ├── ssh-hardening/
│   │   ├── sshd_config.secure
│   │   └── autenticacao-chaves.md
│   ├── firewall/
│   │   ├── iptables-rules.sh
│   │   └── nftables-config.nft
│   ├── kernel-security/
│   │   ├── sysctl-hardening.conf
│   │   └── apparmor-profiles/
│   └── services-audit/
│       └── disable-unused.sh
│
├── monitoramento/
│   ├── fail2ban-config/
│   │   ├── jail.local
│   │   └── filter-ssh.conf
│   ├── auditd/
│   │   ├── audit.rules
│   │   └── relatorios-audit.md
│   └── intrusion-detection/
│       └── aide-config.sh
│
├── criptografia/
│   ├── disk-encryption/
│   │   └── LUKS-guide.md
│   ├── ssl-tls/
│   │   ├── openssl-examples/
│   │   └── nginx-ssl-config/
│   └── gpg-usage/
│       └── assinatura-verificacao.md
│
├── containers-security/
│   ├── docker-security/
│   │   ├── docker-hardening.sh
│   │   └── bench-security.sh
│   └── podman-selinux/
│       └── selinux-context.md
│
├── compliance/
│   ├── cis-benchmarks/
│   │   └── apply-cis.sh
│   └── gdpr-pci-checklist/
│       └── checklist-audit.md
│
├── scripts/
│   ├── security-scanner.sh
│   ├── backup-encrypted.sh
│   └── incident-response.sh
│
├── labs/
│   ├── lab1-permissoes/
│   ├── lab2-firewall/
│   └── lab3-ids/
│
└── README.md
```

## 🚀 Início Rápido

### Pré-requisitos
```
# Sistema Linux (Ubuntu/Debian/CentOS)
# Privilégios de superusuário para algumas configurações
# Familiaridade básica com linha de comando
```
### Instalação
```
git clone https://github.com/seu-usuario/linux-security-project.git
cd linux-security-project
chmod +x scripts/*.sh
```

## 📚 Conteúdo Detalhado

### 1. Fundamentos de Segurança Linux
   - Gerenciamento de Permissões: Uso correto de chmod, chown, e ACLs


   - Controle de Usuários e Grupos: Configuração de sudoers e políticas de acesso


   - Gestão de Logs: Configuração do rsyslog e análise de logs

#### 2. Hardening do Sistema

   - SSH Seguro: Configuração avançada do SSH com autenticação por chaves


   - Firewall: Regras iptables/nftables para diferentes cenários


   - Kernel Hardening: Parâmetros sysctl para segurança


   - Hardening de Serviços: Desativação de serviços desnecessários

#### 3. Monitoramento e Detecção

   - Fail2ban: Proteção contra ataques de força bruta


   - Auditd: Auditoria detalhada do sistema


   - IDS/IPS: Configuração do AIDE para detecção de intrusões

#### 4. Criptografia

   - Criptografia de Disco: LUKS para partições


   - SSL/TLS: Certificados e configuração segura


   - GPG: Assinatura e verificação de arquivos

#### 5. Segurança em Containers

   - Docker Security: Boas práticas e configurações


   - SELinux/AppArmor: Perfis de segurança para containers

#### 6. Conformidade

   - CIS Benchmarks: Scripts para aplicar benchmarks CIS


   - Checklists: GDPR, PCI-DSS e outras regulamentações

## 🛠️ Exemplos Práticos
### Exemplo 1: Configuração Segura do SSH
```
# scripts/ssh-hardening.sh
#!/bin/bash
# Backup do arquivo original
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Configurações de segurança
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/#Port 22/Port 2022/g' /etc/ssh/sshd_config
echo "AllowUsers seu_usuario" >> /etc/ssh/sshd_config
echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config

# Reiniciar serviço SSH
systemctl restart sshd
```

### Exemplo 2: Firewall com nftables
```
#!/usr/sbin/nft -f
# firewall/nftables-config.nft
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0;
        
        # Conexões estabelecidas
        ct state established,related accept
        
        # Loopback
        iif lo accept
        
        # ICMP
        ip protocol icmp accept
        
        # SSH na porta 2022
        tcp dport 2022 accept
        
        # HTTP/HTTPS
        tcp dport {80, 443} accept
        
        # Log e drop
        log prefix "DROP: "
        drop
    }
    
    chain forward {
        type filter hook forward priority 0;
        drop
    }
}
```
### Exemplo 3: Scanner de Segurança Automatizado
```
#!/bin/bash
# scripts/security-scanner.sh
echo "=== Scanner de Segurança Linux ==="
echo "Data: $(date)"
echo "Hostname: $(hostname)"
echo ""

# 1. Verificar usuários com UID 0
echo "1. Usuários com UID 0:"
awk -F: '($3 == 0) {print $1}' /etc/passwd
echo ""

# 2. Verificar senhas vazias
echo "2. Contas sem senha:"
awk -F: '($2 == "") {print $1}' /etc/shadow
echo ""

# 3. Verificar permissões críticas
echo "3. Permissões de arquivos sensíveis:"
ls -la /etc/passwd /etc/shadow /etc/sudoers
echo ""

# 4. Portas abertas
echo "4. Portas abertas:"
ss -tulpn
echo ""
```
## 🔧 Laboratórios Práticos

### Lab 1: Gestão de Permissões
```
cd labs/lab1-permissoes
# Criação de estrutura de diretórios segura
mkdir -p /dados/{publico,restrito,confidencial}
# Configuração de diferentes níveis de acesso
# Prática com chmod, chown, e setfacl
```

### Lab 2: Análise de Logs
```
cd labs/lab2-logs
# Configuração de centralização de logs
# Análise de tentativas de acesso SSH
# Detecção de padrões suspeitos
```

## 📊 Ferramentas Utilizadas


## 🔐 Segurança e Ferramentas

| Categoria        | Ferramentas                                  |
|------------------|----------------------------------------------|
| 🔥 Firewall      | iptables, nftables, ufw                      |
| 👀 Monitoramento | auditd, aide, tripwire                       |
| 🚨 Detecção      | fail2ban, rkhunter, lynis                    |
| 🔒 Criptografia  | openssl, gpg, LUKS                           |
| 📦 Containers    | docker-bench-security, trivy                 |

## 📖 Recursos Adicionais
  - Linux Security - Red Hat

  - CIS Benchmarks

  - Linux Hardening Guide

## 🤝 Contribuindo
Contribuições são bem-vindas! Por favor, leia o CONTRIBUTING.md para detalhes sobre o processo.

## 📄 Licença
Este projeto está licenciado sob a Licença MIT - veja o arquivo LICENSE para detalhes.

## ⚠️ Aviso Legal
Este material é para fins educacionais. Teste sempre em ambientes controlados antes de implementar em produção.

### ⭐ Se este projeto ajudou você, considere dar uma estrela no repositório!
