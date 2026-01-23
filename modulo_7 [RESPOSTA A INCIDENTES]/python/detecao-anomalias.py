#!/usr/bin/env python3
# modulo7/python/detecao-anomalias.py
"""
Sistema Avançado de Detecção de Anomalias
Machine Learning para detecção de comportamentos suspeitos
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import json
import logging
from dataclasses import dataclass
from enum import Enum
import pickle
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import deque
import asyncio
import aiohttp

class TipoAlerta(Enum):
    """Tipos de alertas de segurança"""
    LOGIN_ANOMALO = "login_anomalo"
    TRAFEGO_SUSPEITO = "trafego_suspeito"
    PROCESSO_ANORMAL = "processo_anormal"
    ARQUIVO_SUSPEITO = "arquivo_suspeito"
    COMPORTAMENTO_RANSOMWARE = "comportamento_ransomware"

@dataclass
class AlertaSeguranca:
    """Estrutura de alerta de segurança"""
    id: str
    tipo: TipoAlerta
    severidade: str  # LOW, MEDIUM, HIGH, CRITICAL
    descricao: str
    timestamp: datetime
    evidencia: Dict
    sistema_afetado: str
    recomendacao: str

class SistemaDetecaoAnomalias:
    """Sistema de detecção de anomalias baseado em ML"""

    def __init__(self, config_path: str = "config/detecao.yaml"):
        self.config = self._carregar_config(config_path)
        self.logger = self._configurar_logging()

        # Modelos de Machine Learning
        self.modelos = {
            'login': IsolationForest(contamination=0.1, random_state=42),
            'trafego': IsolationForest(contamination=0.05, random_state=42),
            'processos': IsolationForest(contamination=0.15, random_state=42)
        }

        # Scalers para normalização
        self.scalers = {
            'login': StandardScaler(),
            'trafego': StandardScaler(),
            'processos': StandardScaler()
        }

        # Buffer de dados para treinamento
        self.buffer_dados = {
            'login': deque(maxlen=10000),
            'trafego': deque(maxlen=50000),
            'processos': deque(maxlen=20000)
        }

        # Alertas recentes
        self.alertas_recentes = deque(maxlen=1000)

        # Inicializar modelos
        self._inicializar_modelos()

    def _carregar_config(self, config_path: str) -> Dict:
        """Carregar configuração do sistema"""
        with open(config_path, 'r') as f:
            import yaml
            return yaml.safe_load(f)

    def _configurar_logging(self) -> logging.Logger:
        """Configurar sistema de logs"""
        logger = logging.getLogger('DetecaoAnomalias')
        logger.setLevel(logging.INFO)

        handler = logging.FileHandler('/var/log/detecao_anomalias.log')
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        return logger

    def _inicializar_modelos(self):
        """Inicializar modelos com dados históricos"""
        self.logger.info("Inicializando modelos de detecção...")

        # Carregar dados históricos se disponíveis
        try:
            with open('data/historico_treinamento.pkl', 'rb') as f:
                dados_historicos = pickle.load(f)

            for tipo, dados in dados_historicos.items():
                if tipo in self.modelos and len(dados) > 100:
                    self._treinar_modelo(tipo, dados)

        except FileNotFoundError:
            self.logger.warning("Dados históricos não encontrados. Usando modelo vazio.")

    def _treinar_modelo(self, tipo: str, dados: np.ndarray):
        """Treinar modelo específico"""
        dados_normalizados = self.scalers[tipo].fit_transform(dados)
        self.modelos[tipo].fit(dados_normalizados)
        self.logger.info(f"Modelo {tipo} treinado com {len(dados)} amostras")

    async def monitorar_logins(self, dados_login: Dict) -> Optional[AlertaSeguranca]:
        """Monitorar e detectar logins anômalos"""
        # Extrair features do login
        features = self._extrair_features_login(dados_login)

        # Adicionar ao buffer
        self.buffer_dados['login'].append(features)

        # Verificar anomalia se tivermos dados suficientes
        if len(self.buffer_dados['login']) > 100:
            dados_array = np.array(list(self.buffer_dados['login']))

            # Normalizar e prever
            dados_normalizados = self.scalers['login'].transform(dados_array)
            predicoes = self.modelos['login'].predict(dados_normalizados)

            # Última predição é para o login atual
            if predicoes[-1] == -1:  # -1 indica anomalia no IsolationForest
                return self._criar_alerta_login(dados_login, features)

        return None

    def _extrair_features_login(self, dados: Dict) -> List[float]:
        """Extrair features de um evento de login"""
        hora = dados.get('hora', 0)
        dia_semana = dados.get('dia_semana', 0)
        localizacao = dados.get('localizacao', '')
        dispositivo = dados.get('dispositivo', '')

        # Features básicas
        features = [
            hora,  # Hora do dia (0-23)
            dia_semana,  # Dia da semana (0-6)
            len(localizacao),  # Tamanho da string de localização
            hash(dispositivo) % 100,  # Hash do dispositivo
            dados.get('tentativas_falhas', 0),  # Tentativas falhas recentes
        ]

        return features

    def _criar_alerta_login(self, dados: Dict, features: List) -> AlertaSeguranca:
        """Criar alerta para login anômalo"""
        alerta_id = f"LOGIN-{datetime.now().strftime('%Y%m%d%H%M%S')}"

        return AlertaSeguranca(
            id=alerta_id,
            tipo=TipoAlerta.LOGIN_ANOMALO,
            severidade=self._calcular_severidade_login(features),
            descricao=f"Login anômalo detectado para usuário {dados.get('usuario')}",
            timestamp=datetime.now(),
            evidencia={
                'usuario': dados.get('usuario'),
                'ip': dados.get('ip'),
                'localizacao': dados.get('localizacao'),
                'dispositivo': dados.get('dispositivo'),
                'features': features,
                'score_anomalia': self._calcular_score_anomalia(features, 'login')
            },
            sistema_afetado=dados.get('sistema', 'Desconhecido'),
            recomendacao="Verificar identidade do usuário. Considerar bloqueio temporário."
        )

    async def monitorar_trafego(self, dados_trafego: Dict) -> Optional[AlertaSeguranca]:
        """Monitorar e detectar tráfego anômalo"""
        features = self._extrair_features_trafego(dados_trafego)

        # Adicionar ao buffer
        self.buffer_dados['trafego'].append(features)

        # Verificar para tráfego suspeito conhecido
        if self._e_trafego_suspeito(dados_trafego):
            return self._criar_alerta_trafego(dados_trafego, features, "padrao_conhecido")

        # Verificar anomalia ML
        if len(self.buffer_dados['trafego']) > 1000:
            dados_array = np.array(list(self.buffer_dados['trafego'][-1000:]))
            dados_normalizados = self.scalers['trafego'].transform(dados_array)
            predicoes = self.modelos['trafego'].predict(dados_normalizados)

            if predicoes[-1] == -1:
                return self._criar_alerta_trafego(dados_trafego, features, "anomalia_ml")

        return None

    def _extrair_features_trafego(self, dados: Dict) -> List[float]:
        """Extrair features de tráfego de rede"""
        features = [
            dados.get('bytes_enviados', 0),
            dados.get('bytes_recebidos', 0),
            dados.get('pacotes_enviados', 0),
            dados.get('pacotes_recebidos', 0),
            dados.get('porta_destino', 0),
            dados.get('protocolo', 0),
            hash(dados.get('ip_destino', '')) % 1000,
            dados.get('duracao_conexao', 0),
            dados.get('taxa_transferencia', 0),
        ]

        return features

    def _e_trafego_suspeito(self, dados: Dict) -> bool:
        """Verificar se tráfego corresponde a padrões suspeitos conhecidos"""
        # Portas comumente usadas por malware
        portas_suspeitas = {4444, 6667, 8080, 31337, 12345}

        # IPs/domínios maliciosos conhecidos (lista simplificada)
        destinos_suspeitos = {
            'c2.malware.com', 'download.trojan.ru',
            '185.243.115.230', '45.9.148.117'
        }

        porta = dados.get('porta_destino', 0)
        destino = dados.get('ip_destino', '') or dados.get('dominio_destino', '')

        if porta in portas_suspeitas:
            return True

        if any(suspeito in destino for suspeito in destinos_suspeitos):
            return True

        # Padrão de beaconing (comunicações periódicas)
        if dados.get('intervalo_comunicacao', 0) > 0:
            intervalo = dados['intervalo_comunicacao']
            # Verificar se intervalo é muito regular (possível beaconing)
            if abs(intervalo - round(intervalo)) < 0.1:
                return True

        return False

    def _criar_alerta_trafego(self, dados: Dict, features: List, motivo: str) -> AlertaSeguranca:
        """Criar alerta para tráfego suspeito"""
        alerta_id = f"TRAFEGO-{datetime.now().strftime('%Y%m%d%H%M%S')}"

        descricao = f"Tráfego de rede suspeito detectado"
        if motivo == "padrao_conhecido":
            descricao += " (corresponde a padrão malicioso conhecido)"
        else:
            descricao += " (detectado por modelo de anomalias)"

        return AlertaSeguranca(
            id=alerta_id,
            tipo=TipoAlerta.TRAFEGO_SUSPEITO,
            severidade="HIGH",
            descricao=descricao,
            timestamp=datetime.now(),
            evidencia={
                'origem': dados.get('ip_origem'),
                'destino': dados.get('ip_destino') or dados.get('dominio_destino'),
                'porta': dados.get('porta_destino'),
                'protocolo': dados.get('protocolo'),
                'bytes': dados.get('bytes_enviados', 0) + dados.get('bytes_recebidos', 0),
                'motivo_deteccao': motivo,
                'features': features
            },
            sistema_afetado=dados.get('host_origem', 'Desconhecido'),
            recomendacao="Investigar origem do tráfego. Considerar bloqueio no firewall."
        )

    async def detectar_ransomware(self, dados_sistema: Dict) -> Optional[AlertaSeguranca]:
        """Detectar comportamentos típicos de ransomware"""
        comportamentos_suspeitos = []

        # 1. Alta atividade de criptografia de arquivos
        if dados_sistema.get('taxa_criptografia', 0) > 100:  # Mais de 100 arquivos/min
            comportamentos_suspeitos.append("alta_taxa_criptografia")

        # 2. Extensões de arquivos alteradas
        extensoes_alteradas = dados_sistema.get('extensoes_alteradas', [])
        extensoes_ransomware = {'.locked', '.encrypted', '.crypt', '.crypto'}
        if any(ext in extensoes_ransomware for ext in extensoes_alteradas):
            comportamentos_suspeitos.append("extensoes_ransomware")

        # 3. Arquivos de resgate criados
        arquivos_resgate = dados_sistema.get('arquivos_resgate', [])
        if any('README' in arq or 'HELP' in arq for arq in arquivos_resgate):
            comportamentos_suspeitos.append("arquivo_resgate")

        # 4. Conexões para C2 conhecidos
        conexoes_c2 = dados_sistema.get('conexoes_c2', [])
        if conexoes_c2:
            comportamentos_suspeitos.append("conexao_c2")

        if comportamentos_suspeitos:
            return self._criar_alerta_ransomware(dados_sistema, comportamentos_suspeitos)

        return None

    def _criar_alerta_ransomware(self, dados: Dict, comportamentos: List) -> AlertaSeguranca:
        """Criar alerta de possível ransomware"""
        alerta_id = f"RANSOMWARE-{datetime.now().strftime('%Y%m%d%H%M%S')}"

        return AlertaSeguranca(
            id=alerta_id,
            tipo=TipoAlerta.COMPORTAMENTO_RANSOMWARE,
            severidade="CRITICAL",
            descricao=f"Comportamento de ransomware detectado: {', '.join(comportamentos)}",
            timestamp=datetime.now(),
            evidencia={
                'sistema': dados.get('hostname'),
                'usuario': dados.get('usuario_ativo'),
                'comportamentos_detectados': comportamentos,
                'arquivos_afetados': dados.get('arquivos_criptografados', []),
                'extensoes_alteradas': dados.get('extensoes_alteradas', []),
                'conexoes_suspeitas': dados.get('conexoes_c2', [])
            },
            sistema_afetado=dados.get('hostname', 'Desconhecido'),
            recomendacao=(
                "ISOLAMENTO IMEDIATO REQUERIDO!\n"
                "1. Desconectar sistema da rede\n"
                "2. Desligar para preservar memória\n"
                "3. Notificar equipe de resposta a incidentes\n"
                "4. Iniciar procedimentos de recuperação"
            )
        )

    def _calcular_severidade_login(self, features: List) -> str:
        """Calcular severidade baseado nas features"""
        # Lógica simplificada para exemplo
        hora = features[0]

        if hora < 6 or hora > 22:  # Login fora do horário comercial
            return "HIGH"
        elif features[4] > 5:  # Muitas tentativas falhas
            return "MEDIUM"
        else:
            return "LOW"

    def _calcular_score_anomalia(self, features: List, tipo: str) -> float:
        """Calcular score de anomalia"""
        if tipo not in self.modelos:
            return 0.0

        try:
            features_array = np.array([features])
            features_normalizadas = self.scalers[tipo].transform(features_array)
            score = self.modelos[tipo].score_samples(features_normalizadas)
            return float(score[0])
        except:
            return 0.0

    async def processar_fluxo_monitoramento(self):
        """Processar fluxo contínuo de monitoramento"""
        self.logger.info("Iniciando sistema de detecção de anomalias...")

        while True:
            try:
                # Coletar dados de várias fontes (simulado)
                dados = await self._coletar_dados_monitoramento()

                # Processar cada tipo de dado
                alertas = []

                # Processar logins
                for login in dados.get('logins', []):
                    alerta = await self.monitorar_logins(login)
                    if alerta:
                        alertas.append(alerta)

                # Processar tráfego
                for trafego in dados.get('trafego', []):
                    alerta = await self.monitorar_trafego(trafego)
                    if alerta:
                        alertas.append(alerta)

                # Detectar ransomware
                for sistema in dados.get('sistemas', []):
                    alerta = await self.detectar_ransomware(sistema)
                    if alerta:
                        alertas.append(alerta)

                # Processar alertas
                for alerta in alertas:
                    await self._processar_alerta(alerta)

                # Aguardar próximo ciclo
                await asyncio.sleep(self.config.get('intervalo_monitoramento', 60))

            except Exception as e:
                self.logger.error(f"Erro no fluxo de monitoramento: {e}")
                await asyncio.sleep(300)  # Aguardar 5 minutos em caso de erro

    async def _coletar_dados_monitoramento(self) -> Dict:
        """Coletar dados de monitoramento de várias fontes"""
        # Em produção, isso coletaria dados reais de:
        # - Logs de autenticação (SSH, AD, etc.)
        # - Netflow/sFlow data
        # - Logs de endpoints
        # - SIEM

        # Para exemplo, retornar dados simulados
        return {
            'logins': self._simular_logins(),
            'trafego': self._simular_trafego(),
            'sistemas': self._simular_dados_sistema()
        }

    def _simular_logins(self) -> List[Dict]:
        """Simular eventos de login para teste"""
        import random

        logins = []
        now = datetime.now()

        for _ in range(random.randint(1, 10)):
            logins.append({
                'usuario': f'user{random.randint(1, 100)}',
                'ip': f'192.168.1.{random.randint(1, 254)}',
                'hora': now.hour,
                'dia_semana': now.weekday(),
                'localizacao': random.choice(['SP', 'RJ', 'MG', 'RS', 'Exterior']),
                'dispositivo': random.choice(['Desktop-Win10', 'Laptop-Mac', 'Mobile-Android']),
                'tentativas_falhas': random.randint(0, 10),
                'sistema': 'AD-Domain'
            })

        return logins

    def _simular_trafego(self) -> List[Dict]:
        """Simular tráfego de rede para teste"""
        import random

        trafego = []

        for _ in range(random.randint(5, 20)):
            trafego.append({
                'ip_origem': f'10.0.{random.randint(1, 255)}.{random.randint(1, 254)}',
                'ip_destino': random.choice([
                    '8.8.8.8',  # DNS Google
                    '1.1.1.1',  # Cloudflare
                    '185.243.115.230',  # IP suspeito
                    '45.9.148.117'  # IP suspeito
                ]),
                'porta_destino': random.choice([80, 443, 53, 22, 4444, 6667]),
                'protocolo': random.choice([6, 17]),  # TCP ou UDP
                'bytes_enviados': random.randint(100, 1000000),
                'bytes_recebidos': random.randint(100, 1000000),
                'duracao_conexao': random.uniform(0.1, 3600),
                'intervalo_comunicacao': random.choice([0, 60, 300, 3600]),  # Para beaconing
                'host_origem': f'SRV{random.randint(1, 50)}'
            })

        return trafego

    def _simular_dados_sistema(self) -> List[Dict]:
        """Simular dados de sistema para teste"""
        import random

        sistemas = []

        for i in range(random.randint(1, 5)):
            # 10% de chance de simular ransomware
            tem_ransomware = random.random() < 0.1

            sistema = {
                'hostname': f'WS{i+1}',
                'usuario_ativo': f'user{random.randint(1, 50)}',
                'taxa_criptografia': random.randint(0, 1000) if tem_ransomware else random.randint(0, 10),
                'extensoes_alteradas': ['.locked', '.encrypted'] if tem_ransomware else [],
                'arquivos_resgate': ['README.txt'] if tem_ransomware else [],
                'conexoes_c2': ['185.243.115.230'] if tem_ransomware else [],
                'arquivos_criptografados': [f'file{j}.locked' for j in range(10)] if tem_ransomware else []
            }

            sistemas.append(sistema)

        return sistemas

    async def _processar_alerta(self, alerta: AlertaSeguranca):
        """Processar alerta gerado"""
        self.logger.info(f"ALERTA: {alerta.tipo.value} - {alerta.descricao}")

        # Adicionar à lista de alertas recentes
        self.alertas_recentes.append(alerta)

        # Log detalhado
        self.logger.debug(f"Detalhes do alerta: {json.dumps(alerta.__dict__, default=str)}")

        # Ações baseadas na severidade
        if alerta.severidade in ["HIGH", "CRITICAL"]:
            await self._acionar_resposta_critica(alerta)
        elif alerta.severidade == "MEDIUM":
            await self._acionar_investigacao(alerta)
        else:
            self._registrar_para_analise(alerta)

    async def _acionar_resposta_critica(self, alerta: AlertaSeguranca):
        """Acionar resposta para alertas críticos"""
        self.logger.warning(f"RESPOSTA CRÍTICA ACIONADA para {alerta.id}")

        # Notificar equipe via múltiplos canais
        await self._enviar_notificacao(alerta)

        # Criar ticket de incidente
        await self._criar_ticket_incidente(alerta)

        # Se for ransomware, isolar sistema
        if alerta.tipo == TipoAlerta.COMPORTAMENTO_RANSOMWARE:
            await self._isolar_sistema(alerta.sistema_afetado)

    async def _enviar_notificacao(self, alerta: AlertaSeguranca):
        """Enviar notificação do alerta"""
        # Em produção, integrar com:
        # - Slack/Teams
        # - Email
        # - SMS
        # - PagerDuty/OpsGenie

        mensagem = f"""
        🚨 ALERTA DE SEGURANÇA 🚨

        ID: {alerta.id}
        Tipo: {alerta.tipo.value}
        Severidade: {alerta.severidade}
        Sistema: {alerta.sistema_afetado}
        Descrição: {alerta.descricao}
        Timestamp: {alerta.timestamp}

        Recomendação:
        {alerta.recomendacao}
        """

        self.logger.info(f"Notificação enviada:\n{mensagem}")

    async def _criar_ticket_incidente(self, alerta: AlertaSeguranca):
        """Criar ticket de incidente"""
        # Em produção, integrar com:
        # - Jira
        # - ServiceNow
        # - Redmine

        ticket_info = {
            'titulo': f"Incidente: {alerta.tipo.value} - {alerta.sistema_afetado}",
            'descricao': alerta.descricao,
            'severidade': alerta.severidade,
            'evidencias': json.dumps(alerta.evidencia, default=str),
            'recomendacao': alerta.recomendacao
        }

        self.logger.info(f"Ticket criado: {ticket_info['titulo']}")

    async def _isolar_sistema(self, sistema: str):
        """Isolar sistema da rede"""
        # Em produção, integrar com:
        # - Firewall APIs
        # - Network Switches
        # - Endpoint Isolation

        self.logger.warning(f"Isolando sistema: {sistema}")

        # Comandos simulados para isolamento
        comandos = [
            f"iptables -A INPUT -s {sistema} -j DROP",
            f"iptables -A OUTPUT -d {sistema} -j DROP",
            f"echo 'Isolamento de {sistema} realizado' >> /var/log/isolamentos.log"
        ]

        for comando in comandos:
            self.logger.info(f"Executando: {comando}")

    async def _acionar_investigacao(self, alerta: AlertaSeguranca):
        """Acionar investigação para alertas médios"""
        self.logger.info(f"Investigação acionada para {alerta.id}")

        # Registrar para análise pela equipe SOC
        with open('/var/log/alertas_investigacao.log', 'a') as f:
            f.write(f"{alerta.timestamp} - {alerta.id} - {alerta.descricao}\n")

    def _registrar_para_analise(self, alerta: AlertaSeguranca):
        """Registrar alerta para análise posterior"""
        # Adicionar ao arquivo de alertas de baixa severidade
        with open('/var/log/alertas_baixa.log', 'a') as f:
            f.write(f"{alerta.timestamp} - {alerta.id} - {alerta.tipo.value}\n")

    def salvar_estado(self):
        """Salvar estado do sistema para persistência"""
        estado = {
            'buffer_dados': {k: list(v) for k, v in self.buffer_dados.items()},
            'modelos': {k: pickle.dumps(v) for k, v in self.modelos.items()},
            'scalers': {k: pickle.dumps(v) for k, v in self.scalers.items()},
            'ultimo_treinamento': datetime.now().isoformat()
        }

        with open('estado_detecao.pkl', 'wb') as f:
            pickle.dump(estado, f)

        self.logger.info("Estado do sistema salvo")

# Interface de linha de comando
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Sistema de Detecção de Anomalias')
    parser.add_argument('--modo', choices=['monitorar', 'treinar', 'testar'],
                       default='monitorar', help='Modo de operação')
    parser.add_argument('--config', default='config/detecao.yaml',
                       help='Caminho do arquivo de configuração')

    args = parser.parse_args()

    # Criar instância do sistema
    sistema = SistemaDetecaoAnomalias(args.config)

    if args.modo == 'monitorar':
        # Iniciar monitoramento contínuo
        asyncio.run(sistema.processar_fluxo_monitoramento())

    elif args.modo == 'testar':
        # Executar testes
        print("Modo teste - Simulando detecções...")

        # Testar detecção de ransomware
        dados_teste = {
            'hostname': 'WS-TESTE',
            'usuario_ativo': 'hacker',
            'taxa_criptografia': 500,
            'extensoes_alteradas': ['.locked', '.encrypted'],
            'arquivos_resgate': ['README_DECRYPT.txt'],
            'conexoes_c2': ['185.243.115.230'],
            'arquivos_criptografados': ['documento1.locked', 'foto2.encrypted']
        }

        # Executar de forma síncrona para teste
        import asyncio
        alerta = asyncio.run(sistema.detectar_ransomware(dados_teste))

        if alerta:
            print(f"✅ Ransomware detectado!")
            print(f"ID: {alerta.id}")
            print(f"Severidade: {alerta.severidade}")
            print(f"Descrição: {alerta.descricao}")
            print(f"Recomendação: {alerta.recomendacao}")
        else:
            print("❌ Nenhuma ameaça detectada")

    print("\n✅ Sistema de Detecção de Anomalias executado com sucesso!")