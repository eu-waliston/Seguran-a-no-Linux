#!/bin/bash
# modulo7/labs/simulador-incidentes.sh

echo "=== LABORATÓRIO DE SIMULAÇÃO DE INCIDENTES ==="
echo "Ambiente controlado para treinamento de resposta a incidentes"

# Configurar ambiente isolado
setup_lab_environment() {
    echo "Configurando ambiente de laboratório..."

    # Criar rede isolada
    docker network create --subnet=10.10.0.0/24 ir-lab-network

    # Servidor vulnerável (simulado)
    docker run -d --name vuln-server \
        --network ir-lab-network \
        --ip 10.10.0.10 \
        -p 8080:80 \
        vulnerables/web-dvwa

    # Cliente atacante (simulado)
    docker run -d --name attacker \
        --network ir-lab-network \
        --ip 10.10.0.100 \
        kalilinux/kali-rolling \
        tail -f /dev/null

    # Servidor de logs (ELK)
    docker run -d --name elk \
        --network ir-lab-network \
        --ip 10.10.0.20 \
        -p 5601:5601 \
        sebp/elk

    echo "✅ Ambiente configurado"
}

# Cenários de simulação
run_scenario() {
    local scenario="$1"

    case $scenario in
        ransomware)
            simulate_ransomware_attack
            ;;
        data_breach)
            simulate_data_breach
            ;;
        ddos)
            simulate_ddos_attack
            ;;
        insider)
            simulate_insider_threat
            ;;
        *)
            echo "Cenário desconhecido: $scenario"
            ;;
    esac
}

simulate_ransomware_attack() {
    echo "🚨 Iniciando simulação de RANSOMWARE..."

    # 1. Criar arquivos de teste
    docker exec vuln-server bash -c "
        for i in {1..100}; do
            echo 'Conteúdo importante do arquivo $i' > /var/www/html/important_file_$i.txt
        done
    "

    # 2. Simular criptografia
    echo "Simulando criptografia de arquivos..."
    docker exec vuln-server bash -c "
        for file in /var/www/html/important_*.txt; do
            mv \"\$file\" \"\${file}.encrypted\"
        done
    "

    # 3. Criar nota de resgate
    docker exec vuln-server bash -c '
        cat > /var/www/html/README_RANSOMWARE.txt << EOF
        SEUS ARQUIVOS FORAM CRIPTOGRAFADOS!

        Para descriptografar, envie 1 BTC para:
        bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

        Contato: ransomwarehelp@onionmail.org
        EOF
    '

    # 4. Gerar logs suspeitos
    docker exec vuln-server bash -c '
        echo "$(date) - Ransomware: Arquivos criptografados" >> /var/log/ransomware.log
        echo "$(date) - Ransomware: Nota de resgate criada" >> /var/log/ransomware.log
    '

    echo "✅ Simulação de ransomware concluída"
    echo "📁 Arquivos criptografados em: http://localhost:8080/"
    echo "📄 Nota de resgate: http://localhost:8080/README_RANSOMWARE.txt"
}

simulate_data_breach() {
    echo "🔓 Iniciando simulação de VAZAMENTO DE DADOS..."

    # 1. Criar dados sensíveis
    docker exec vuln-server bash -c "
        mkdir -p /var/www/private
        echo 'Nome,Email,Senha,CPF' > /var/www/private/clientes.csv
        for i in {1..50}; do
            echo \"Cliente\$i,cliente\$i@empresa.com,SENHA\$i,111.222.333-\$i\" >> /var/www/private/clientes.csv
        done
    "

    # 2. Simular acesso não autorizado
    docker exec attacker bash -c "
        echo 'Simulando exploração de vulnerabilidade...'
        # Tentativa de acesso a diretório privado
        curl -s http://10.10.0.10/private/ | grep -i 'clientes'
    "

    # 3. Simular exfiltração
    docker exec attacker bash -c "
        echo 'Exfiltrando dados...'
        wget http://10.10.0.10/private/clientes.csv -O /tmp/stolen_data.csv
        echo 'Dados exfiltrados:'
        head -5 /tmp/stolen_data.csv
    "

    # 4. Gerar logs
    docker exec vuln-server bash -c "
        echo '$(date) - ALERTA: Acesso não autorizado ao diretório /private/' >> /var/log/apache2/access.log
        echo '$(date) - ALERTA: Download do arquivo clientes.csv por IP não autorizado' >> /var/log/apache2/access.log
    "

    echo "✅ Simulação de vazamento de dados concluída"
    echo "📊 Dados sensíveis criados: /var/www/private/clientes.csv"
    echo "🔍 Logs de acesso em: /var/log/apache2/access.log"
}

# Menu interativo
show_menu() {
    while true; do
        clear
        echo "=========================================="
        echo "   LABORATÓRIO DE SIMULAÇÃO DE INCIDENTES"
        echo "=========================================="
        echo ""
        echo "1. Configurar ambiente de laboratório"
        echo "2. Simular ataque de Ransomware"
        echo "3. Simular Vazamento de Dados"
        echo "4. Simular ataque DDoS"
        echo "5. Simular ameaça interna"
        echo "6. Executar treino completo"
        echo "7. Limpar ambiente"
        echo "8. Sair"
        echo ""
        read -p "Escolha uma opção: " choice

        case $choice in
            1) setup_lab_environment ;;
            2) run_scenario "ransomware" ;;
            3) run_scenario "data_breach" ;;
            4) run_scenario "ddos" ;;
            5) run_scenario "insider" ;;
            6) run_full_training ;;
            7) cleanup_environment ;;
            8) exit 0 ;;
            *) echo "Opção inválida!" ;;
        esac

        echo ""
        read -p "Pressione Enter para continuar..."
    done
}

run_full_training() {
    echo "🎯 INICIANDO TREINO COMPLETO DE RESPOSTA A INCIDENTES"
    echo ""

    # Fase 1: Detecção
    echo "FASE 1: DETECÇÃO"
    echo "----------------"
    simulate_ransomware_attack
    echo "⏳ Aguardando detecção pela equipe..."
    sleep 5

    # Fase 2: Análise
    echo ""
    echo "FASE 2: ANÁLISE"
    echo "---------------"
    echo "Analisando logs e evidências..."
    docker exec vuln-server tail -20 /var/log/apache2/access.log
    sleep 3

    # Fase 3: Contenção
    echo ""
    echo "FASE 3: CONTENÇÃO"
    echo "-----------------"
    echo "Isolando sistema comprometido..."
    docker network disconnect ir-lab-network vuln-server
    echo "Sistema isolado da rede"
    sleep 2

    # Fase 4: Erradicação
    echo ""
    echo "FASE 4: ERRADICAÇÃO"
    echo "-------------------"
    echo "Removendo malware..."
    docker exec vuln-server bash -c "
        rm -f /var/www/html/*.encrypted
        rm -f /var/www/html/README_*.txt
    "
    echo "Malware removido"
    sleep 2

    # Fase 5: Recuperação
    echo ""
    echo "FASE 5: RECUPERAÇÃO"
    echo "-------------------"
    echo "Restaurando sistema..."
    docker exec vuln-server bash -c "
        for i in {1..100}; do
            echo 'Conteúdo restaurado do arquivo $i' > /var/www/html/important_file_$i.txt
        done
    "
    echo "Sistema restaurado"
    sleep 2

    # Fase 6: Lições aprendidas
    echo ""
    echo "FASE 6: LIÇÕES APRENDIDAS"
    echo "-------------------------"
    echo "Realizando análise pós-incidente..."
    echo "1. Tempo de resposta: 15 minutos"
    echo "2. Eficácia da contenção: 100%"
    echo "3. Melhorias identificadas:"
    echo "   - Implementar detecção mais rápida"
    echo "   - Melhorar backups"
    echo "   - Treinar equipe"

    echo ""
    echo "✅ TREINO CONCLUÍDO COM SUCESSO!"
}

cleanup_environment() {
    echo "Limpando ambiente..."
    docker stop vuln-server attacker elk 2>/dev/null
    docker rm vuln-server attacker elk 2>/dev/null
    docker network rm ir-lab-network 2>/dev/null
    echo "✅ Ambiente limpo"
}

# Iniciar menu
show_menu