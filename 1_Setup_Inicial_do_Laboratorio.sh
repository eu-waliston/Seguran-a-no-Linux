#!/bin/bash
# setup-lab.sh

echo "=== CONFIGURAÇÃO DO LABORATÓRIO DE SEGURANÇA LINUX ==="
echo "Criando estrutura de diretórios..."

# Criar estrutura principal
mkdir -p ~/security-lab/{fundamentos,hardening,monitoramento,criptografia,labs}
cd ~/security-lab

# Criar usuários para testes
sudo useradd -m -s /bin/bash aluno1
sudo useradd -m -s /bin/bash aluno2
sudo useradd -m -s /bin/bash auditor
echo "aluno1:Senha123" | sudo chpasswd
echo "aluno2:Senha456" | sudo chpasswd

echo "Laboratório configurado em ~/security-lab"