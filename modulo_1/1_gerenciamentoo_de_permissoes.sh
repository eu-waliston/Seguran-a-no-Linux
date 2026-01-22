#!/bin/bash
# fundamentos/permissoes-lab.sh

echo "=== LAB 1: GERENCIAMENTO DE PERMISSÕES ==="

# Criar estrutura de diretórios

mkdir -p /tmp/lab-permissoes/{publico,restrito,confidencial}
cd /tmp/lab-permissions

#1 - Permissões básicas

acho "1 - criando arquivos com diferentes permissões"

# Arquivo público (todos podem ler)

echo "conteudo restrito" > restrito/arquivo-restrito.txt
sudo chown :sudo restrito/arquivo-restrito.txt
chmod 640 restrito/arquivo-restrito.txt
echo "Arquivo restrito: 640 (rw-r----)"

# Arquivo confidencial (apenas dono)

echo "Conteúdo confidencial" > confidencial/arquivo-confidencial.txt
chmod 600 confidencial/arquivo-confidencial.txt
echo "Arquivo confidencial: 600 (rw-------)"

# 2. Permissões especiais

echo -e "\n2. Permissões especiais:"

# SUID - Executar com privilégios do dono

sudo cp /bin/cat /tmp/lab-permissoes/cat-suid
sudo chmod 4755 /tmp/lab-permissoes/cat-suid
ls -la /tmp/lab-permissoes/cat-suid

# SGID - Herdar grupo do diretório

chmod 2770 restrito/
ls -ld restrito/

# Sticky Bit - Apenas dono pode deletar

chmod 1777 publico/
ls -ld publico/

# 3. ACLs (Access Control Lists)

echo -e "\n3. Controle de Acesso com ACLs:"
echo "Conteúdo secreto" > documento-secreto.txt

# Adicionar permissão específica para um usuário

setfacl -m u:aluno1:r-- documento-secreto.txt
setfacl -m u:auditor:rw- documento-secreto.txt

#Ver ACLs

getfacl documento-secreto.txt

# 4 mascara umask

echo -e "\n4 Configurando umask:"
echo "umask atual: $(umask)"
umask 077
touch documento-protegido.txt
ls -ls documento-protegido.txt