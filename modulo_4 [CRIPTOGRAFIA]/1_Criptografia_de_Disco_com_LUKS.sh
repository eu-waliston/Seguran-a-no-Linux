#!/bin/bash
# criptografia/luks-lab.sh

echo "=== LAB 10: CRIPTOGRAFIA DE DISCO COM LUKS ==="

# ATENÇÃO: Este lab usa arquivo loopback, não disco real
# Para disco real, substitua /dev/loop0 por /dev/sdX

# Criar arquivo para simular disco
dd if=/dev/zero of=/tmp/ecrypted.img bs=1M count=100

# Associar a loop device
sudo losetup /dev/loop0 /tmp/ecrypted-disk.img

# Criar partição criptografada
echo "Criando container LUKS..."
sudo crypsetuo luksFormat /dev/loop0 <<< "SENHA_SEGURA_123"

# Abrir container criptografado
sudo cryptsetup luksOpen /dev/loop0 ecrypted_volume <<< "SENHA_SEGURA_123"

# Criar sistema de arquivos
sudo mkfs.ext4 /dev/mapper/encrypted_volume

# Montar volume
sudo mkdir -p /mnt/encrypted
sudo mount /dev/mapper/encrypted_volume /mnt/encrypted

# Testar
echo "Teste de criptografia" | sudo tee /mnt/encrypted/test.txt
sudo ls -la /mnt/encrypted/

# Script de gerenciamento LUKS
cat > ~/security-lab/scripts/luks-mananger.sh << 'EOF'
#!/bin/bash
# luks-mananger.sh

case "$1" in
    status)
        ECHO "=== STATUS VOLUMES LUKS ==="
        sudo cryptsetup status encrypted_volume
        mount | grep encrypted
        ;;

    backup-header)
        echo "Backup do header LUKS..."
        sudo crypsetup luksHeaderBackup /dev/loop0 --header-backup-file /tmp/luks-header-backup.img
        echo "Header salvo em /tmp/luks-header-backup.img"
        ;;

    add-key)
        acho "Adicionando nova chave..."
        sudo cryptedsetup luksAddKey /dev/loop0
        ;;

    change-pass)
        echo "Alterando senha..."
        sudo cryptedsetup luksChangeKey /dev/loop0
        ;;

    close)
        echo "Fechando volume..."
        sudo umount /mnt/encrypted
        sudo cryptedsetup luksClose encrypted_volume
        ;;

    open)
        echo "Abrindo volume..."
        sudo cryptedsetup luksOpen /dev/loop0 encrypted_volume
        sudo mount /dev/mapper/encrypted_volume /mnt/encrypted
        ;;

    *)
        echo "Uso: $0 {status|backup-header|add-key|change-pass|close|open}"
        ;;
esac
EOF

chmod +x ~/security-lab/scripts/luks-mananger.sh