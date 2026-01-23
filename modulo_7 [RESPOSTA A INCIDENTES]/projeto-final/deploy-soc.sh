#!/bin/bash
# modulo7/projeto-final/deploy-soc.sh

echo "=== DEPLOYMENT DO SOC COMPLETO ==="

# Configurações
SOC_DIR="/opt/soc-enterprise"
LOG_FILE="/var/log/soc-deploy.log"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Funções de logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

check_prerequisites() {
    log "Verificando pré-requisitos..."

    # Verificar sistema operacional
    if [[ ! -f /etc/os-release ]]; then
        log "ERRO: Sistema operacional não suportado"
        exit 1
    fi

    # Verificar recursos
    local total_ram=$(free -g | awk '/^Mem:/{print $2}')
    local total_disk=$(df -h / | awk 'NR==2 {print $2}' | sed 's/G//')

    if [[ $total_ram -lt 16 ]]; then
        log "AVISO: Mínimo 16GB RAM recomendado (encontrado: ${total_ram}GB)"
    fi

    if [[ $total_disk -lt 100 ]]; then
        log "AVISO: Mínimo 100GB disco recomendado (encontrado: ${total_disk}GB)"
    fi

    # Verificar dependências
    local deps=("docker" "docker-compose" "git" "curl" "wget" "python3" "pip3")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log "Instalando $dep..."
            apt-get install -y "$dep" 2>/dev/null || \
            yum install -y "$dep" 2>/dev/null || \
            log "ERRO: Não foi possível instalar $dep"
        fi
    done
}

create_directory_structure() {
    log "Criando estrutura de diretórios..."

    mkdir -p "$SOC_DIR"/{config,data,logs,scripts,playbooks,dashboards,rules}
    mkdir -p "$SOC_DIR"/data/{elasticsearch,logstash,kibana,thehive,cortex,misp}
    mkdir -p "$SOC_DIR"/logs/{siem,soar,alerts,audit}
    mkdir -p "$SOC_DIR"/config/{wazuh,suricata,zeek,osquery}

    # Permissões
    chmod -R 750 "$SOC_DIR"
    chown -R root:security "$SOC_DIR"

    log "Estrutura criada em: $SOC_DIR"
}

deploy_elk_stack() {
    log "Deployando ELK Stack..."

    cat > "$SOC_DIR/docker-compose.elk.yml" << 'EOF'
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.10.0
    container_name: elasticsearch
    environment:
      - node.name=elasticsearch
      - cluster.name=soc-cluster
      - discovery.type=single-node
      - bootstrap.memory_lock=true
      - xpack.security.enabled=true
      - xpack.security.authc.api_key.enabled=true
      - "ES_JAVA_OPTS=-Xms4g -Xmx4g"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - ./data/elasticsearch:/usr/share/elasticsearch/data
      - ./config/elasticsearch/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml
    ports:
      - "9200:9200"
      - "9300:9300"
    networks:
      - soc-net
    restart: unless-stopped

  logstash:
    image: docker.elastic.co/logstash/logstash:8.10.0
    container_name: logstash
    volumes:
      - ./config/logstash/logstash.yml:/usr/share/logstash/config/logstash.yml
      - ./config/logstash/pipelines.yml:/usr/share/logstash/config/pipelines.yml
      - ./config/logstash/pipeline:/usr/share/logstash/pipeline
      - ./data/logstash:/usr/share/logstash/data
    ports:
      - "5044:5044"
      - "5000:5000/tcp"
      - "5000:5000/udp"
      - "9600:9600"
    environment:
      LS_JAVA_OPTS: "-Xmx2g -Xms2g"
    networks:
      - soc-net
    depends_on:
      - elasticsearch
    restart: unless-stopped

  kibana:
    image: docker.elastic.co/kibana/kibana:8.10.0
    container_name: kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=${ELASTIC_PASSWORD}
    volumes:
      - ./config/kibana/kibana.yml:/usr/share/kibana/config/kibana.yml
      - ./data/kibana:/usr/share/kibana/data
    ports:
      - "5601:5601"
    networks:
      - soc-net
    depends_on:
      - elasticsearch
    restart: unless-stopped

networks:
  soc-net:
    driver: bridge

volumes:
  elasticsearch-data:
    driver: local
  logstash-data:
    driver: local
  kibana-data:
    driver: local
EOF

    # Criar configurações
    mkdir -p "$SOC_DIR/config/elasticsearch"
    cat > "$SOC_DIR/config/elasticsearch/elasticsearch.yml" << 'EOF'
cluster.name: "soc-cluster"
network.host: 0.0.0.0
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: elastic-certificates.p12
xpack.security.transport.ssl.truststore.path: elastic-certificates.p12
EOF

    # Iniciar ELK
    cd "$SOC_DIR" && docker-compose -f docker-compose.elk.yml up -d

    log "ELK Stack deployado. Acesse Kibana em: http://localhost:5601"
}

deploy_wazuh() {
    log "Deployando Wazuh (EDR/SIEM)..."

    cat > "$SOC_DIR/docker-compose.wazuh.yml" << 'EOF'
version: '3.8'

services:
  wazuh.manager:
    image: wazuh/wazuh-manager:4.5.2
    hostname: wazuh.manager
    restart: always
    ports:
      - "1514:1514"
      - "1515:1515"
      - "1516:1516"
      - "55000:55000"
    environment:
      - INDEXER_URL=https://wazuh.indexer:9200
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=SecretPassword
      - FILEBEAT_SSL_VERIFICATION_MODE=full
      - SSL_CERTIFICATE_AUTHORITIES=/etc/ssl/certs/ca.crt
      - SSL_CERTIFICATE=/etc/ssl/certs/wazuh.manager.crt
      - SSL_KEY=/etc/ssl/certs/wazuh.manager.key
    volumes:
      - ./data/wazuh/queue:/var/ossec/queue
      - ./data/wazuh/var/multigroups:/var/ossec/var/multigroups
      - ./data/wazuh/integrations:/var/ossec/integrations
      - ./data/wazuh/active-response/bin:/var/ossec/active-response/bin
      - ./data/wazuh/agentless:/var/ossec/agentless
      - ./data/wazuh/etc:/var/ossec/etc
      - ./data/wazuh/logs:/var/ossec/logs
      - ./data/wazuh/ruleset:/var/ossec/ruleset
      - ./config/wazuh/ssl_certs:/etc/ssl/certs
    networks:
      - soc-net

  wazuh.indexer:
    image: wazuh/wazuh-indexer:4.5.2
    hostname: wazuh.indexer
    restart: always
    ports:
      - "9200:9200"
    environment:
      - OPENSEARCH_INITIAL_ADMIN_PASSWORD=SecretPassword
      - OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g
    volumes:
      - ./data/wazuh-indexer/data:/var/lib/wazuh-indexer
      - ./data/wazuh-indexer/logs:/var/log/wazuh-indexer
      - ./config/wazuh/indexer.yml:/usr/share/wazuh-indexer/opensearch.yml
    networks:
      - soc-net

  wazuh.dashboard:
    image: wazuh/wazuh-dashboard:4.5.2
    hostname: wazuh.dashboard
    restart: always
    ports:
      - "443:5601"
    environment:
      - OPENSEARCH_HOSTS=https://wazuh.indexer:9200
      - OPENSEARCH_USERNAME=admin
      - OPENSEARCH_PASSWORD=SecretPassword
    volumes:
      - ./config/wazuh/dashboard.yml:/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml
      - ./data/wazuh-dashboard/data:/usr/share/wazuh-dashboard/data
    networks:
      - soc-net
    depends_on:
      - wazuh.indexer
EOF

    # Criar certificados SSL
    mkdir -p "$SOC_DIR/config/wazuh/ssl_certs"
    openssl req -x509 -batch -nodes -days 365 -newkey rsa:2048 \
        -keyout "$SOC_DIR/config/wazuh/ssl_certs/wazuh.manager.key" \
        -out "$SOC_DIR/config/wazuh/ssl_certs/wazuh.manager.crt" \
        -subj "/C=BR/ST=SP/L=Sao Paulo/O=SOC/CN=wazuh.manager"

    # Iniciar Wazuh
    cd "$SOC_DIR" && docker-compose -f docker-compose.wazuh.yml up -d

    log "Wazuh deployado. Dashboard em: https://localhost"
}

deploy_thehive_cortex() {
    log "Deployando TheHive & Cortex (SOAR)..."

    cat > "$SOC_DIR/docker-compose.soar.yml" << 'EOF'
version: '3.8'

services:
  thehive:
    image: strangebee/thehive:5.2
    container_name: thehive
    depends_on:
      - cassandra
      - elasticsearch
      - cortex
    ports:
      - "9000:9000"
    environment:
      - JAVA_OPTS=-Xmx4g -Xms1g
      - CORTEX_URL=http://cortex:9001
      - CORTEX_KEY=${CORTEX_KEY}
    volumes:
      - ./data/thehive/data:/opt/thp/thehive/data
      - ./data/thehive/index:/opt/thp/thehive/index
      - ./config/thehive/application.conf:/etc/thehive/application.conf
    networks:
      - soc-net
    restart: unless-stopped

  cortex:
    image: thehiveproject/cortex:3.1.10
    container_name: cortex
    ports:
      - "9001:9001"
    environment:
      - JOB_DIRECTORY=/opt/cortex/jobs
    volumes:
      - ./data/cortex/data:/opt/cortex/data
      - ./config/cortex/application.conf:/etc/cortex/application.conf
    networks:
      - soc-net
    restart: unless-stopped

  cassandra:
    image: cassandra:4
    container_name: cassandra
    volumes:
      - ./data/cassandra:/var/lib/cassandra
    networks:
      - soc-net
    restart: unless-stopped

  elasticsearch-soar:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.0
    container_name: elasticsearch-soar
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
    volumes:
      - ./data/elasticsearch-soar:/usr/share/elasticsearch/data
    networks:
      - soc-net
    restart: unless-stopped
EOF

    # Criar configurações
    mkdir -p "$SOC_DIR/config/thehive"
    cat > "$SOC_DIR/config/thehive/application.conf" << 'EOF'
# TheHive Configuration
play.modules.enabled += "org.thp.thehive.connector.cortex.CortexModule"
play.modules.enabled += "org.thp.thehive.connector.misp.MispModule"

http.secret.key = "changemeinproduction"

db {
  provider = cassandra
  cassandra {
    keyspace = thehive
    cluster {
      hosts = ["cassandra"]
      port = 9042
    }
  }
}

search {
  endpoint = "http://elasticsearch-soar:9200"
  index = thehive
}

cortex {
  servers = [
    {
      name = "cortex"
      url = "http://cortex:9001"
      key = "${CORTEX_KEY}"
    }
  ]
}
EOF

    # Iniciar SOAR
    cd "$SOC_DIR" && docker-compose -f docker-compose.soar.yml up -d

    log "TheHive & Cortex deployados. TheHive em: http://localhost:9000"
}

deploy_network_monitoring() {
    log "Deployando monitoramento de rede..."

    # Suricata (IDS)
    cat > "$SOC_DIR/docker-compose.suricata.yml" << 'EOF'
version: '3.8'

services:
  suricata:
    image: jasonish/suricata:latest
    container_name: suricata
    network_mode: host
    cap_add:
      - NET_ADMIN
      - SYS_NICE
    volumes:
      - ./config/suricata/suricata.yaml:/etc/suricata/suricata.yaml
      - ./config/suricata/rules:/etc/suricata/rules
      - ./data/suricata/logs:/var/log/suricata
      - ./data/suricata/rules:/var/lib/suricata/rules
    restart: unless-stopped
    command:
      - -i
      - eth0
      - -c
      - /etc/suricata/suricata.yaml
EOF

    # Zeek (NIDS)
    cat > "$SOC_DIR/docker-compose.zeek.yml" << 'EOF'
version: '3.8'

services:
  zeek:
    image: blacktop/zeek:latest
    container_name: zeek
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN
    volumes:
      - ./config/zeek:/zeek/etc
      - ./data/zeek/logs:/zeek/logs
      - ./data/zeek/scripts:/zeek/scripts
    restart: unless-stopped
EOF

    # Arkime (PCAP)
    cat > "$SOC_DIR/docker-compose.arkime.yml" << 'EOF'
version: '3.8'

services:
  arkime:
    image: arkime/arkime:latest
    container_name: arkime
    environment:
      - ARKIME_INTERFACE=eth0
      - ARKIME_PASSWORD=SecretPassword
    ports:
      - "8005:8005"
    volumes:
      - ./data/arkime/pcap:/opt/arkime/raw
      - ./data/arkime/logs:/opt/arkime/logs
      - ./config/arkime/config.ini:/opt/arkime/etc/config.ini
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN
    restart: unless-stopped
EOF

    # Iniciar monitoramento de rede
    cd "$SOC_DIR" && docker-compose -f docker-compose.suricata.yml up -d
    cd "$SOC_DIR" && docker-compose -f docker-compose.zeek.yml up -d
    cd "$SOC_DIR" && docker-compose -f docker-compose.arkime.yml up -d

    log "Monitoramento de rede deployado"
}

deploy_automation_tools() {
    log "Deployando ferramentas de automação..."

    # Shuffle (SOAR Open Source)
    cat > "$SOC_DIR/docker-compose.shuffle.yml" << 'EOF'
version: '3.8'

services:
  shuffle-frontend:
    image: frikky/shuffle-frontend:latest
    container_name: shuffle-frontend
    ports:
      - "3001:3001"
    environment:
      - REACT_APP_BACKEND_HOST=localhost:3002
      - REACT_APP_BACKEND_WS_HOST=localhost:3002
    networks:
      - soc-net
    restart: unless-stopped

  shuffle-backend:
    image: frikky/shuffle-backend:latest
    container_name: shuffle-backend
    ports:
      - "3002:3002"
    environment:
      - SHUFFLE_APP_ENV=production
      - SHUFFLE_DB=shuffle
      - SHUFFLE_DB_HOST=shuffle-db
      - SHUFFLE_DB_USER=shuffle
      - SHUFFLE_DB_PASSWORD=shufflepassword
    volumes:
      - ./data/shuffle/apps:/etc/shuffle/apps
      - ./data/shuffle/database:/etc/shuffle/database
    networks:
      - soc-net
    depends_on:
      - shuffle-db
    restart: unless-stopped

  shuffle-db:
    image: mongo:latest
    container_name: shuffle-db
    environment:
      - MONGO_INITDB_ROOT_USERNAME=shuffle
      - MONGO_INITDB_ROOT_PASSWORD=shufflepassword
    volumes:
      - ./data/shuffle/mongodb:/data/db
    networks:
      - soc-net
    restart: unless-stopped
EOF

    # Inicar Shuffle
    cd "$SOC_DIR" && docker-compose -f docker-compose.shuffle.yml up -d

    # Scripts de automação Python
    mkdir -p "$SOC_DIR/scripts/automation"

    cat > "$SOC_DIR/scripts/automation/soc_automation.py" << 'EOF'
#!/usr/bin/env python3
"""
Sistema de Automação do SOC
"""

import json
import requests
from datetime import datetime
import logging
from typing import Dict, List
import yaml

class SOCAutomation:
    def __init__(self, config_file="config/automation.yaml"):
        self.config = self.load_config(config_file)
        self.setup_logging()

    def load_config(self, config_file):
        """Carregar configuração"""
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)

    def setup_logging(self):
        """Configurar logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/soc-automation.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def process_alert(self, alert_data: Dict):
        """Processar alerta e tomar ações automatizadas"""
        alert_id = alert_data.get('id')
        severity = alert_data.get('severity', 'low')

        self.logger.info(f"Processando alerta {alert_id} - Severidade: {severity}")

        # Verificar playbooks disponíveis
        playbook = self.find_playbook(alert_data)

        if playbook:
            self.execute_playbook(playbook, alert_data)
        else:
            self.escalate_to_analyst(alert_data)

    def find_playbook(self, alert_data: Dict):
        """Encontrar playbook apropriado"""
        alert_type = alert_data.get('type')

        playbooks = {
            'brute_force': 'playbooks/brute_force.yaml',
            'ransomware': 'playbooks/ransomware.yaml',
            'data_exfiltration': 'playbooks/data_exfiltration.yaml',
            'malware': 'playbooks/malware.yaml'
        }

        return playbooks.get(alert_type)

    def execute_playbook(self, playbook_path: str, alert_data: Dict):
        """Executar playbook de automação"""
        self.logger.info(f"Executando playbook: {playbook_path}")

        try:
            with open(playbook_path, 'r') as f:
                playbook = yaml.safe_load(f)

            # Executar ações do playbook
            for step in playbook.get('steps', []):
                action = step.get('action')
                params = step.get('parameters', {})

                if action == 'block_ip':
                    self.block_ip(params.get('ip'), alert_data)
                elif action == 'isolate_host':
                    self.isolate_host(params.get('host'), alert_data)
                elif action == 'disable_user':
                    self.disable_user(params.get('username'), alert_data)
                elif action == 'create_ticket':
                    self.create_ticket(alert_data)

        except Exception as e:
            self.logger.error(f"Erro ao executar playbook: {e}")
            self.escalate_to_analyst(alert_data)

    def block_ip(self, ip: str, alert_data: Dict):
        """Bloquear IP no firewall"""
        self.logger.info(f"Bloqueando IP: {ip}")

        # Integração com pfSense/OPNsense
        try:
            # Exemplo: API do pfSense
            response = requests.post(
                f"{self.config['firewall']['url']}/api/v1/firewall/rule",
                json={
                    'interface': 'wan',
                    'type': 'block',
                    'source': ip,
                    'destination': 'any',
                    'description': f"Blocked by SOC - Alert: {alert_data.get('id')}"
                },
                auth=(self.config['firewall']['user'], self.config['firewall']['pass'])
            )

            if response.status_code == 200:
                self.logger.info(f"IP {ip} bloqueado com sucesso")
            else:
                self.logger.error(f"Falha ao bloquear IP {ip}: {response.text}")

        except Exception as e:
            self.logger.error(f"Erro na integração com firewall: {e}")

    def isolate_host(self, host: str, alert_data: Dict):
        """Isolar host da rede"""
        self.logger.info(f"Isolando host: {host}")

        # Integração com switches/APIs de rede
        # Implementação específica do ambiente

    def disable_user(self, username: str, alert_data: Dict):
        """Desabilitar conta de usuário"""
        self.logger.info(f"Desabilitando usuário: {username}")

        # Integração com Active Directory/LDAP
        # Implementação específica do ambiente

    def create_ticket(self, alert_data: Dict):
        """Criar ticket no sistema de gestão"""
        self.logger.info(f"Criando ticket para alerta: {alert_data.get('id')}")

        # Integração com Jira/ServiceNow
        ticket_data = {
            'fields': {
                'project': {'key': 'SOC'},
                'summary': f"Security Alert: {alert_data.get('title')}",
                'description': alert_data.get('description', ''),
                'issuetype': {'name': 'Incident'},
                'priority': {'name': self.map_severity(alert_data.get('severity'))}
            }
        }

        try:
            response = requests.post(
                f"{self.config['ticketing']['url']}/rest/api/2/issue",
                json=ticket_data,
                auth=(self.config['ticketing']['user'], self.config['ticketing']['token'])
            )

            if response.status_code == 201:
                ticket_id = response.json().get('key')
                self.logger.info(f"Ticket criado: {ticket_id}")
                return ticket_id

        except Exception as e:
            self.logger.error(f"Erro ao criar ticket: {e}")

    def map_severity(self, severity: str) -> str:
        """Mapear severidade para prioridade do ticket"""
        mapping = {
            'critical': 'Highest',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low'
        }
        return mapping.get(severity, 'Medium')

    def escalate_to_analyst(self, alert_data: Dict):
        """Escalar alerta para analista humano"""
        self.logger.info(f"Escalando alerta {alert_data.get('id')} para analista")

        # Notificar via Slack/Teams
        self.send_notification(alert_data)

    def send_notification(self, alert_data: Dict):
        """Enviar notificação para canais"""
        message = {
            'text': f"🚨 ALERTA REQUER ATENÇÃO HUMANA 🚨",
            'blocks': [
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': f"*Alera ID:* {alert_data.get('id')}\n*Severidade:* {alert_data.get('severity')}\n*Tipo:* {alert_data.get('type')}\n*Descrição:* {alert_data.get('description')}"
                    }
                }
            ]
        }

        try:
            response = requests.post(
                self.config['slack']['webhook_url'],
                json=message
            )

            if response.status_code == 200:
                self.logger.info("Notificação enviada para Slack")

        except Exception as e:
            self.logger.error(f"Erro ao enviar notificação: {e}")

    def run(self):
        """Executar loop principal de automação"""
        self.logger.info("Iniciando sistema de automação do SOC")

        while True:
            try:
                # Buscar novos alertas
                alerts = self.fetch_new_alerts()

                for alert in alerts:
                    self.process_alert(alert)

                # Aguardar próximo ciclo
                import time
                time.sleep(self.config.get('polling_interval', 30))

            except KeyboardInterrupt:
                self.logger.info("Sistema de automação interrompido")
                break
            except Exception as e:
                self.logger.error(f"Erro no loop principal: {e}")
                time.sleep(60)

    def fetch_new_alerts(self) -> List[Dict]:
        """Buscar novos alertas do SIEM"""
        # Integração com Elasticsearch/Wazuh
        try:
            response = requests.get(
                f"{self.config['siem']['url']}/_search",
                json={
                    'query': {
                        'bool': {
                            'filter': [
                                {'term': {'processed': False}},
                                {'range': {'@timestamp': {'gte': 'now-5m'}}}
                            ]
                        }
                    }
                },
                auth=(self.config['siem']['user'], self.config['siem']['pass'])
            )

            if response.status_code == 200:
                hits = response.json().get('hits', {}).get('hits', [])
                return [hit['_source'] for hit in hits]

        except Exception as e:
            self.logger.error(f"Erro ao buscar alertas: {e}")

        return []

if __name__ == "__main__":
    automator = SOCAutomation()
    automator.run()
EOF

    chmod +x "$SOC_DIR/scripts/automation/soc_automation.py"

    log "Ferramentas de automação deployadas"
}

configure_dashboards() {
    log "Configurando dashboards do SOC..."

    # Dashboard Kibana
    cat > "$SOC_DIR/dashboards/kibana-dashboard.ndjson" << 'EOF'
{"type":"dashboard","id":"soc-overview","attributes":{"title":"SOC Overview","hits":0,"description":"Dashboard overview do SOC","panelsJSON":"[{\"version\":\"8.10.0\",\"type\":\"visualization\",\"gridData\":{\"x\":0,\"y\":0,\"w\":24,\"h\":15,\"i\":\"0\"},\"panelIndex\":\"0\",\"embeddableConfig\":{\"title\":\"Alertas por Severidade\"}},{\"version\":\"8.10.0\",\"type\":\"visualization\",\"gridData\":{\"x\":24,\"y\":0,\"w\":24,\"h\":15,\"i\":\"1\"},\"panelIndex\":\"1\",\"embeddableConfig\":{\"title\":\"Top Ameaças\"}}]","version":1,"timeRestore":false,"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"language\":\"kuery\",\"query\":\"\"},\"filter\":[]}"}},"references":[{"id":"alerts-by-severity","name":"0:panel_0","type":"visualization"},{"id":"top-threats","name":"1:panel_1","type":"visualization"}]}
{"type":"visualization","id":"alerts-by-severity","attributes":{"title":"Alertas por Severidade","visState":"{\"title\":\"Alertas por Severidade\",\"type\":\"pie\",\"params\":{\"type\":\"pie\",\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"isDonut\":true},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"severity\",\"size\":5,\"order\":\"desc\",\"orderBy\":\"1\"}}]}","uiStateJSON":"{}","description":"","version":1,"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}},"references":[{"id":"security-logs","name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern"}]}
{"type":"visualization","id":"top-threats","attributes":{"title":"Top Ameaças","visState":"{\"title\":\"Top Ameaças\",\"type\":\"tagcloud\",\"params\":{\"scale\":\"linear\",\"orientation\":\"single\",\"minFontSize\":18,\"maxFontSize\":72},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"threat.name\",\"size\":10,\"order\":\"desc\",\"orderBy\":\"1\"}}]}","uiStateJSON":"{}","description":"","version":1,"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}},"references":[{"id":"security-logs","name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern"}]}
EOF

    # Dashboard Grafana
    cat > "$SOC_DIR/dashboards/grafana-dashboard.json" << 'EOF'
{
  "dashboard": {
    "id": null,
    "title": "SOC Metrics",
    "tags": ["soc", "security"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "MTTD & MTTR",
        "type": "graph",
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
        "targets": [
          {
            "expr": "soc_mttd_seconds",
            "legendFormat": "MTTD",
            "refId": "A"
          },
          {
            "expr": "soc_mttr_seconds",
            "legendFormat": "MTTR",
            "refId": "B"
          }
        ]
      },
      {
        "id": 2,
        "title": "Alertas por Hora",
        "type": "stat",
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
        "targets": [
          {
            "expr": "rate(soc_alerts_total[1h])",
            "refId": "A"
          }
        ]
      }
    ]
  }
}
EOF

    # Importar dashboards
    log "Dashboards configurados. Importe-os manualmente nas respectivas ferramentas."
}

create_soc_playbooks() {
    log "Criando playbooks de resposta..."

    # Playbook: Ransomware Response
    cat > "$SOC_DIR/playbooks/ransomware_response.yaml" << 'EOF'
name: "Ransomware Response Playbook"
version: "2.0"
description: "Resposta automatizada a incidentes de ransomware"

triggers:
  - event_type: "ransomware_detected"
  - file_extension: [".encrypted", ".locked", ".crypt"]
  - registry_key: "HKCU\\Software\\CryptoWall"

phases:

  identification:
    - name: "Confirm ransomware infection"
      actions:
        - check_file_extensions:
            paths: ["C:\\Users\\*", "/home/*", "/var/www/*"]
            extensions: [".encrypted", ".locked", ".crypt", ".crypto"]

        - search_ransom_note:
            patterns: ["README.*", "HELP.*", "DECRYPT.*"]

        - check_network_connections:
            known_c2: ["185.243.115.230", "45.9.148.117"]

  containment:
    - name: "Isolate affected systems"
      actions:
        - network_isolation:
            method: "firewall_block"
            target: "affected_hosts"

        - disable_user_accounts:
            users: "compromised_users"

        - block_c2_communications:
            ips: "detected_c2_ips"
            domains: "detected_c2_domains"

  eradication:
    - name: "Remove ransomware artifacts"
      actions:
        - kill_malicious_processes:
            process_names: ["cryptominer.exe", "encryptor.exe"]

        - delete_malicious_files:
            paths: ["%TEMP%\\*.exe", "/tmp/*.encryptor"]

        - remove_persistence:
            registry_keys: "malicious_registry_keys"
            cron_jobs: "malicious_cron_jobs"

  recovery:
    - name: "Restore from backup"
      actions:
        - verify_backup_integrity:
            backup_type: "last_clean_backup"

        - restore_files:
            source: "backup_location"
            target: "affected_systems"

        - validate_restoration:
            checksum_validation: true

  lessons_learned:
    - name: "Post-incident activities"
      actions:
        - update_detection_rules:
            iocs: "collected_iocs"

        - patch_vulnerabilities:
            cves: "exploited_cves"

        - user_training:
            topic: "ransomware_awareness"

automation_actions:
  - name: "Block IP in firewall"
    type: "firewall"
    implementation:
      pfsense:
        api_url: "https://firewall.local/api/v1"
        rule: "block_single_ip"

  - name: "Isolate host from network"
    type: "network"
    implementation:
      cisco_ios:
        commands:
          - "interface gigabitethernet0/1"
          - "shutdown"

  - name: "Create incident ticket"
    type: "ticketing"
    implementation:
      jira:
        project: "SOC"
        issue_type: "Incident"

metrics:
  mttd_target: "15 minutes"
  mttr_target: "4 hours"
  success_criteria: "100% data recovery"
EOF

    # Playbook: Data Breach Response
    cat > "$SOC_DIR/playbooks/data_breach_response.yaml" << 'EOF'
name: "Data Breach Response Playbook"
version: "1.5"
description: "Resposta a vazamento de dados sensíveis"

compliance_requirements:
  - lgpd: "72h notification"
  - gdpr: "72h notification"
  - pci_dss: "immediate investigation"

steps:

  1. initial_assessment:
    - determine_data_type: ["PII", "PHI", "PCI", "credentials"]
    - assess_scope: ["records_affected", "systems_involved"]
    - identify_leak_vector: ["database", "api", "email", "cloud_storage"]

  2. immediate_actions:
    - secure_breach_point: true
    - preserve_evidence: true
    - prevent_further_leakage: true

  3. notification:
    - internal_stakeholders: ["legal", "compliance", "management"]
    - external_authorities: ["ANPD", "authorities"]
    - affected_individuals: "if_required_by_law"

  4. investigation:
    - forensic_analysis: true
    - log_analysis: "last_90_days"
    - determine_root_cause: true

  5. remediation:
    - fix_vulnerabilities: true
    - implement_controls: ["encryption", "access_controls", "monitoring"]
    - update_policies: true
EOF

    log "Playbooks criados em: $SOC_DIR/playbooks/"
}

setup_monitoring_alerts() {
    log "Configurando alertas e monitoramento..."

    # Regras de detecção
    cat > "$SOC_DIR/rules/detection_rules.yaml" << 'EOF'
rules:

  ransomware_detection:
    name: "Ransomware File Encryption Detection"
    description: "Detecta padrões de criptografia de ransomware"
    severity: "critical"
    query: |
      file.extension: (".encrypted" OR ".locked" OR ".crypt")
      AND process.name: ("*.exe" OR "cryptominer")
    actions:
      - alert_slack: "soc-alerts"
      - create_ticket: "SOC"
      - auto_contain: true

  brute_force_ssh:
    name: "SSH Brute Force Attempts"
    description: "Múltiplas tentativas falhas de SSH"
    severity: "high"
    query: |
      event.category: "authentication"
      AND event.outcome: "failure"
      AND source.ip: *
      | stats count by source.ip
      | where count > 5
    threshold: 5
    timeframe: "5m"
    actions:
      - block_ip: "source.ip"
      - alert_email: "soc-team@company.com"

  data_exfiltration:
    name: "Large Data Transfer Detection"
    description: "Detecta transferências grandes de dados sensíveis"
    severity: "high"
    query: |
      network.bytes: > 100000000
      AND destination.ip: (external_ips)
      AND file.type: ("csv" OR "sql" OR "dump")
    actions:
      - alert_immediate: true
      - isolate_host: "source.hostname"
EOF

    # Configurar ElastAlert
    cat > "$SOC_DIR/config/elastalert/config.yaml" << 'EOF'
rules_folder: /opt/elastalert/rules
run_every:
  minutes: 1
buffer_time:
  minutes: 15
es_host: elasticsearch
es_port: 9200
writeback_index: elastalert_status
alert_time_limit:
  days: 2
EOF

    log "Alertas e monitoramento configurados"
}

generate_documentation() {
    log "Gerando documentação do SOC..."

    # Manual do SOC
    cat > "$SOC_DIR/docs/SOC_MANUAL.md" << 'EOF'
# MANUAL DO CENTRO DE OPERAÇÕES DE SEGURANÇA (SOC)

## 1. VISÃO GERAL
Este documento descreve a operação do SOC implementado em $(hostname).

### 1.1 Objetivos
- Detecção proativa de ameaças
- Resposta rápida a incidentes
- Conformidade com regulamentações
- Melhoria contínua da postura de segurança

### 1.2 Arquitetura
- **SIEM:** Elastic Stack + Wazuh
- **SOAR:** TheHive + Cortex
- **Monitoramento de Rede:** Suricata + Zeek + Arkime
- **Automação:** Scripts Python + Shuffle

## 2. OPERAÇÃO DIÁRIA

### 2.1 Turnos e Responsabilidades
- **Turno 1 (07:00-15:00):** 2 Analistas N1, 1 Analista N2
- **Turno 2 (15:00-23:00):** 2 Analistas N1, 1 Analista N2
- **Turno 3 (23:00-07:00):** 1 Analista N1 (remoto)

### 2.2 Processos
1. Monitoramento contínuo de dashboards
2. Triagem de alertas
3. Investigação de incidentes
4. Documentação de atividades
5. Handover entre turnos

## 3. FERRAMENTAS E ACESSOS

### 3.1 URLs de Acesso
- Kibana: http://$(hostname):5601
- Wazuh Dashboard: https://$(hostname)
- TheHive: http://$(hostname):9000
- Cortex: http://$(hostname):9001
- Arkime: http://$(hostname):8005

### 3.2 Credenciais
- Elasticsearch: admin / $(cat /opt/soc-enterprise/secrets/elastic_password 2>/dev/null || echo 'CHANGE_ME')
- Wazuh: admin / SecretPassword
- TheHive: admin@thehive.local / secret

## 4. PROCEDIMENTOS DE RESPOSTA

### 4.1 Fluxo de Resposta a Incidentes