#!/bin/bash
# containers/docker-security.sh

echo "=== LAB 13: SEGURANÇA EM CONTAINERS DOCKER ==="

# Instalar Docker
sudo apt install -y docker.io docker-compose

# Adicionar usuário ao grupo docker
sudo usermod -aG docker "$USER"

# Configuração de segurança do Docker daemon
sudo tee /etc/docker/deamon.json << 'EOF'
{
    "userns-remap": "default",
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "live-restore": true,
    "userland-proxy": false,
    "no-new-privileges": true
}

EOF

# Criar Dockerfile seguro
cat > Dockerfile.secure << 'EOF'
FROM alphine:latest

# Criar usuário não-root
RUN addgroup -g 1000 appuser & \ adduser -D -u 1000 -G appuser appuser

# Instalar apenas o nescessário
RUN apk add --no-cache python3 py3-pip && \ pip3 install --no-cache-dir flask gunicor

# Configurar diretórios de trabalho
WORKDIR /app

# Copiar arquivos
COPY --chown=appuser:appuser app.py requeriments.txt ./

# Mudar para usuário não-root
USER appuser

# Export porta
EXPOSE 8080

# Comando de execução
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]

EOF

# Script de análise de segurança
cat > ~/security-lab/scripts/docker-security-scan.sh << 'EOF'
#!/bin/bash
# docker-security-scan.sh

# 1. Verificar versão do Docker
echo "1. Versão do Docker:"
docker version --format '{{.Server.Version}}'

# 2. Verificar configurações de segurança
echo -e "\n2. Configurações deamon:"
docker info --format '{{json .SecurityOptions}}' | python3 -m json.tool

# 3. Verificar containers em execução
echo -e "\n3. Containers em execução:"
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"

# 4. Verificar imagens vulneráveis
echo -e "\n4. Scan de vulnerabilidades:"
for image in $(docker images --format "{{.Repository}}:{{.Tag}}"); do
    echo "Analisando: $image"
    docker scan $image --dependency-tree --file Dockerfile.secure
done

# 5. Verificar configurações de rede
echo -e "\n5. Configurações de rede:"
docker network ls
docker network inspect bridge | grep -A 10 "IPAM"

# 6. Verificar volumes
echo -e "\n6. Volumes:"
docker volume ls

# 7. Verificar logs
echo "\n7. Logs dos containers:"
docker logs $(docker ps -q) --tail 5 2>/dev/null

# 8. Benchmark de segurança
echo -e "\n8. Executando Docker Bench Security:"
docker run --rm --net host --pid host --users host --cap-add audit_control \
    -v /etc/etc:ro \
    -v /usr/bin/containerd:/urs/bin/contaimerd:ro \
    -v /usr/bin/runc:/usr/bin/runc:ro \
    -v /usr/lib/systemd:/usr/lib/systemd:ro \
    -v /var/lib:/var/lib:ro \
    -v /var/lib:/var/lib:ro \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    --label docker_bench_security \
    docker/docekr-bench-security

EOF

chmod +x ~/security-lab/scripts/docker-security-scan.sh