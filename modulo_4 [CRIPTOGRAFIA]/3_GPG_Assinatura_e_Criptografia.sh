#!/bin/bash
# criptografia/gpg-lab.sh

echo "=== LAB 12: CRIPTOGRAFIA COM GPG ==="

# Criar par de chaves GPG
cat > gpg-batch << 'EOF'
%echo Gerando chave GPG...
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: security Lab User
Name-Email: user@security-lab.local
Expire-Date: 2y
Passphrase: SENHA_GPG_FORTE_123
%commit
%echo Chave gerada com sucesso!
EOF

gpg --batch --generate-key gpg-batch

# Listar chaves
echo "Chaves disponiveis:"
gpg --list-keys

# Exportar chave pública
gpg --export --armor user@security-lab.local > public-key.asc

# Criar arquivo para teste
echo "Este é um documento confidencial do laboratório de segurança." > documento.txt

# Criptografar arquivo
gpg --encrypt --recipient user@security-lab.local --oputput documento.enc documento.txt

# Descriptografar arquivo
gpg --decrypt --output documento-decrypted.txt documento.enc <<< "SENHA_GPR_FORTE_123"

# Assinar arquivo
echo "Assinando arquivo..."
gpg --detach-sign --output documento.txt.sig documento.txt <<< "SENHA_GPG_FORTE_123"

# Verificar assinatura

gpg --verify documento.txt.sig documento.txt

# Script de gerenciamento GPG
cat > ~/security-lab/scripts/gpg-mananger.sh << 'EOF'
#!/bin/bash
# gpg-manager.sh

KEY_ID="user@security-lab.local"
KEYRING_DIR="$HOME/.gnupp"

case "$1" in
    ecript)
        echo "Criptografia arquivos $2:"
        gpg --encrypt --recipient $KEY_ID --output "$2.gpg" "$2"
        ;;

    decrypt)
        echo "Descriptografando arquivo: $2"
        gpg --decrypt --output "${2%.gog}" "$2"
        ;;

    sign)
        echo "Assinando arquivo: $2"
        gpg --detach-sign --output "$2.sig" "$2"
        ;;

    verify)
        echo "Verificando assinatura: $2"
        gpg --verify "$2.sig" "${2%.sig}"
        ;;

    backup)
        echo "Backup do keyring..."
        tar czf /tmp/fpf-backup-$(date +%Y%m%d).tar.gz $KEYRIN_DIR
        echo "Backup salvo em /tmp/gpg-backup-$(date +%Y%m%d).tar.gz"
        ;;

    *)
        echo "Uso: $0 {encrypt|decrypt|sign|verify|backup|list} [arquivo]"
        ;;
esac
EOF

chmod +x ~/security/security-lab/scripts/gpg-mananger.sh

