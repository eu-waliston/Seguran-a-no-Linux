#!/usr/bin/env python3
# modulo7/python/coleta-forense.py
"""
Ferramenta de Coleta Forense Avançada
Coleta evidências mantendo integridade forense
"""

import os
import sys
import json
import hashlib
import logging
import subprocess
import datetime
from pathlib import Path
from typing import Dict, List, Optional
import tarfile
import zipfile
import pickle

class ColetaForense:
    """Classe para coleta forense de evidências digitais"""

    def __init__(self, caso_id: str, output_dir: str = "/forensics"):
        self.caso_id = caso_id
        self.output_dir = Path(output_dir) / caso_id
        self.evidencias_dir = self.output_dir / "evidencias"
        self.log_dir = self.output_dir / "logs"

        # Criar estrutura de diretórios
        self._criar_estrutura()

        # Configurar logging
        self._configurar_logging()

        # Inicializar cadeia de custódia
        self.cadeia_custodia = []

    def _criar_estrutura(self):
        """Criar estrutura de diretórios para o caso"""
        diretorios = [
            self.evidencias_dir / "memoria",
            self.evidencias_dir / "disco",
            self.evidencias_dir / "rede",
            self.evidencias_dir / "logs",
            self.evidencias_dir / "artefatos",
            self.log_dir,
            self.output_dir / "relatorios"
        ]

        for dir_path in diretorios:
            dir_path.mkdir(parents=True, exist_ok=True)

    def _configurar_logging(self):
        """Configurar sistema de logs"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_dir / 'coleta.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def registrar_custodia(self, acao: str, descricao: str, hash_evidencia: str = None):
        """Registrar ação na cadeia de custódia"""
        registro = {
            'timestamp': datetime.datetime.now().isoformat(),
            'acao': acao,
            'descricao': descricao,
            'hash_evidencia': hash_evidencia,
            'responsavel': os.getenv('USER', 'unknown')
        }

        self.cadeia_custodia.append(registro)

        # Salvar em arquivo
        with open(self.output_dir / 'cadeia_custodia.json', 'w') as f:
            json.dump(self.cadeia_custodia, f, indent=2, ensure_ascii=False)

    def calcular_hash(self, arquivo_path: Path) -> Dict[str, str]:
        """Calcular múltiplos hashes para um arquivo"""
        hashes = {}
        buffer_size = 65536

        # Inicializar algoritmos
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        try:
            with open(arquivo_path, 'rb') as f:
                while True:
                    data = f.read(buffer_size)
                    if not data:
                        break
                    md5.update(data)
                    sha1.update(data)
                    sha256.update(data)

            hashes = {
                'md5': md5.hexdigest(),
                'sha1': sha1.hexdigest(),
                'sha256': sha256.hexdigest(),
                'tamanho': arquivo_path.stat().st_size
            }

        except Exception as e:
            self.logger.error(f"Erro ao calcular hash de {arquivo_path}: {e}")

        return hashes

    def coletar_memoria(self):
        """Coletar dump de memória"""
        self.logger.info("Iniciando coleta de memória...")

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.evidencias_dir / "memoria" / f"memdump_{timestamp}.lime"

        try:
            # Usar LiME (Linux Memory Extractor) se disponível
            result = subprocess.run(
                ['sudo', 'insmod', '/lib/modules/$(uname -r)/kernel/drivers/char/lime.ko',
                 f'path={output_file}', 'format=lime'],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                hashes = self.calcular_hash(output_file)
                self.registrar_custodia(
                    'COLETA_MEMORIA',
                    f'Dump de memória coletado: {output_file}',
                    hashes.get('sha256')
                )
                self.logger.info(f"Memória coletada: {output_file}")
            else:
                # Fallback para outros métodos
                self._coletar_memoria_fallback(output_file)

        except Exception as e:
            self.logger.error(f"Erro na coleta de memória: {e}")

    def _coletar_memoria_fallback(self, output_file: Path):
        """Método alternativo para coleta de memória"""
        try:
            # Usar dd para coletar memória física
            subprocess.run(
                ['sudo', 'dd', 'if=/dev/mem', f'of={output_file}', 'bs=1M', 'count=1024'],
                check=True
            )

            hashes = self.calcular_hash(output_file)
            self.registrar_custodia(
                'COLETA_MEMORIA_FALLBACK',
                f'Dump de memória (fallback) coletado: {output_file}',
                hashes.get('sha256')
            )

        except Exception as e:
            self.logger.error(f"Erro no fallback de memória: {e}")

    def coletar_artefatos_volateis(self):
        """Coletar artefatos voláteis do sistema"""
        self.logger.info("Coletando artefatos voláteis...")

        artefatos = {
            'processos': 'ps aux',
            'conexoes': 'netstat -tulpn',
            'arquivos_abertos': 'lsof',
            'historico_comandos': 'history',
            'variaveis_ambiente': 'env',
            'modulos_kernel': 'lsmod',
            'agendamentos': 'crontab -l'
        }

        for nome, comando in artefatos.items():
            try:
                output_file = self.evidencias_dir / "artefatos" / f"{nome}.txt"

                result = subprocess.run(
                    comando.split(),
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                with open(output_file, 'w') as f:
                    f.write(f"Comando: {comando}\n")
                    f.write(f"Timestamp: {datetime.datetime.now().isoformat()}\n")
                    f.write("=" * 80 + "\n")
                    f.write(result.stdout)
                    if result.stderr:
                        f.write("\nSTDERR:\n")
                        f.write(result.stderr)

                hashes = self.calcular_hash(output_file)
                self.registrar_custodia(
                    'COLETA_ARTEFATO',
                    f'Artefato coletado: {nome}',
                    hashes.get('sha256')
                )

            except Exception as e:
                self.logger.error(f"Erro ao coletar {nome}: {e}")

    def coletar_arquivos_sensiveis(self):
        """Coletar arquivos sensíveis do sistema"""
        self.logger.info("Coletando arquivos sensíveis...")

        arquivos_sensiveis = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/group',
            '/etc/sudoers',
            '/etc/hosts',
            '/etc/hosts.allow',
            '/etc/hosts.deny',
            '/etc/ssh/sshd_config',
            '/var/log/auth.log',
            '/var/log/secure',
            '/var/log/syslog',
            '/root/.bash_history',
            '/home/*/.bash_history'
        ]

        for padrao in arquivos_sensiveis:
            try:
                import glob
                arquivos = glob.glob(padrao)

                for arquivo in arquivos:
                    if os.path.exists(arquivo):
                        # Criar cópia forense
                        destino = self.evidencias_dir / "artefatos" / \
                                  arquivo.replace('/', '_').lstrip('_')

                        subprocess.run(['cp', arquivo, destino], check=True)

                        # Calcular hash
                        hashes = self.calcular_hash(Path(destino))

                        self.registrar_custodia(
                            'COLETA_ARQUIVO',
                            f'Arquivo sensível coletado: {arquivo}',
                            hashes.get('sha256')
                        )

            except Exception as e:
                self.logger.error(f"Erro ao coletar {padrao}: {e}")

    def coletar_metadados_sistema(self):
        """Coletar metadados do sistema"""
        self.logger.info("Coletando metadados do sistema...")

        metadados = {}

        # Informações do sistema
        metadados['sistema'] = {
            'hostname': subprocess.getoutput('hostname'),
            'kernel': subprocess.getoutput('uname -r'),
            'os': subprocess.getoutput('cat /etc/os-release 2>/dev/null || echo N/A'),
            'uptime': subprocess.getoutput('uptime'),
            'data_hora': datetime.datetime.now().isoformat()
        }

        # Informações de hardware
        metadados['hardware'] = {
            'cpu': subprocess.getoutput('lscpu 2>/dev/null || cat /proc/cpuinfo'),
            'memoria': subprocess.getoutput('free -h'),
            'discos': subprocess.getoutput('lsblk -o NAME,SIZE,TYPE,MOUNTPOINT')
        }

        # Usuários e grupos
        metadados['usuarios'] = {
            'logados': subprocess.getoutput('who'),
            'ultimos_logins': subprocess.getoutput('last -20')
        }

        # Salvar metadados
        output_file = self.evidencias_dir / "metadados_sistema.json"
        with open(output_file, 'w') as f:
            json.dump(metadados, f, indent=2, ensure_ascii=False)

        hashes = self.calcular_hash(output_file)
        self.registrar_custodia(
            'COLETA_METADADOS',
            'Metadados do sistema coletados',
            hashes.get('sha256')
        )

    def criar_imagem_disco(self, dispositivo: str):
        """Criar imagem forense de disco"""
        self.logger.info(f"Criando imagem forense do disco {dispositivo}...")

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        imagem_file = self.evidencias_dir / "disco" / f"disco_{dispositivo.replace('/', '_')}_{timestamp}.img"
        log_file = self.evidencias_dir / "disco" / f"dd_log_{timestamp}.txt"

        try:
            # Criar imagem com dd
            with open(log_file, 'w') as log:
                result = subprocess.run(
                    ['sudo', 'dd', f'if={dispositivo}', f'of={imagem_file}',
                     'bs=4M', 'conv=noerror,sync', 'status=progress'],
                    stderr=subprocess.PIPE,
                    text=True
                )
                log.write(result.stderr)

            # Calcular hash da imagem
            hashes = self.calcular_hash(imagem_file)

            self.registrar_custodia(
                'IMAGEM_DISCO',
                f'Imagem forense criada do dispositivo {dispositivo}',
                hashes.get('sha256')
            )

            # Criar hash log (similar ao FTK)
            hash_log = self.evidencias_dir / "disco" / f"hashlog_{timestamp}.txt"
            with open(hash_log, 'w') as f:
                for algo, valor in hashes.items():
                    f.write(f"{algo.upper()}: {valor}\n")

        except Exception as e:
            self.logger.error(f"Erro ao criar imagem de disco: {e}")

    def gerar_relatorio(self):
        """Gerar relatório forense da coleta"""
        self.logger.info("Gerando relatório de coleta...")

        relatorio = {
            'caso_id': self.caso_id,
            'data_coleta': datetime.datetime.now().isoformat(),
            'sistema_alvo': {
                'hostname': subprocess.getoutput('hostname'),
                'ip': subprocess.getoutput('hostname -I')
            },
            'evidencias_coletadas': [],
            'cadeia_custodia': self.cadeia_custodia,
            'resumo': {
                'total_evidencias': len(self.cadeia_custodia),
                'tamanho_total': self._calcular_tamanho_total(),
                'tempo_coleta': self._calcular_tempo_coleta()
            }
        }

        # Listar evidências coletadas
        evidencias_dir = self.evidencias_dir
        for root, dirs, files in os.walk(evidencias_dir):
            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(evidencias_dir)

                relatorio['evidencias_coletadas'].append({
                    'caminho': str(rel_path),
                    'tamanho': file_path.stat().st_size,
                    'hash': self.calcular_hash(file_path).get('sha256')
                })

        # Salvar relatório
        relatorio_file = self.output_dir / "relatorios" / "relatorio_coleta.json"
        with open(relatorio_file, 'w') as f:
            json.dump(relatorio, f, indent=2, ensure_ascii=False)

        # Gerar versão resumida em Markdown
        self._gerar_relatorio_markdown(relatorio)

        return relatorio

    def _calcular_tamanho_total(self) -> int:
        """Calcular tamanho total das evidências"""
        total = 0
        for root, dirs, files in os.walk(self.evidencias_dir):
            for file in files:
                total += (Path(root) / file).stat().st_size
        return total

    def _calcular_tempo_coleta(self) -> str:
        """Calcular tempo total de coleta"""
        if len(self.cadeia_custodia) < 2:
            return "N/A"

        inicio = datetime.datetime.fromisoformat(self.cadeia_custodia[0]['timestamp'])
        fim = datetime.datetime.fromisoformat(self.cadeia_custodia[-1]['timestamp'])

        return str(fim - inicio)

    def _gerar_relatorio_markdown(self, relatorio: Dict):
        """Gerar relatório em formato Markdown"""
        md_file = self.output_dir / "relatorios" / "relatorio_coleta.md"

        with open(md_file, 'w') as f:
            f.write(f"# RELATÓRIO DE COLETA FORENSE\n\n")
            f.write(f"**Caso ID:** {relatorio['caso_id']}\n")
            f.write(f"**Data da Coleta:** {relatorio['data_coleta']}\n")
            f.write(f"**Sistema Alvo:** {relatorio['sistema_alvo']['hostname']} ")
            f.write(f"({relatorio['sistema_alvo']['ip']})\n\n")

            f.write("## RESUMO\n\n")
            f.write(f"- **Total de Evidências:** {relatorio['resumo']['total_evidencias']}\n")
            f.write(f"- **Tamanho Total:** {relatorio['resumo']['tamanho_total']} bytes\n")
            f.write(f"- **Tempo de Coleta:** {relatorio['resumo']['tempo_coleta']}\n\n")

            f.write("## EVIDÊNCIAS COLETADAS\n\n")
            for evidencia in relatorio['evidencias_coletadas']:
                f.write(f"### {evidencia['caminho']}\n")
                f.write(f"- Tamanho: {evidencia['tamanho']} bytes\n")
                f.write(f"- SHA256: `{evidencia['hash']}`\n\n")

            f.write("## CADEIA DE CUSTÓDIA\n\n")
            f.write("| Timestamp | Ação | Descrição | Hash |\n")
            f.write("|-----------|------|-----------|------|\n")

            for registro in relatorio['cadeia_custodia']:
                hash_display = registro['hash_evidencia'][:16] + "..." if registro['hash_evidencia'] else "N/A"
                f.write(f"| {registro['timestamp']} | {registro['acao']} | {registro['descricao']} | `{hash_display}` |\n")

            f.write("\n---\n")
            f.write("*Relatório gerado automaticamente pela Ferramenta de Coleta Forense*\n")

    def executar_coleta_completa(self):
        """Executar coleta forense completa"""
        self.logger.info(f"Iniciando coleta forense completa para caso {self.caso_id}")

        # Registrar início
        self.registrar_custodia(
            'INICIO_COLETA',
            f'Início da coleta forense - Caso: {self.caso_id}',
            None
        )

        # Executar etapas de coleta
        self.coletar_metadados_sistema()
        self.coletar_artefatos_volateis()
        self.coletar_arquivos_sensiveis()

        # Tentar coletar memória (requer privilégios)
        try:
            self.coletar_memoria()
        except Exception as e:
            self.logger.warning(f"Não foi possível coletar memória: {e}")

        # Coletar logs de rede
        self._coletar_logs_rede()

        # Gerar relatório final
        relatorio = self.gerar_relatorio()

        # Registrar conclusão
        self.registrar_custodia(
            'CONCLUSAO_COLETA',
            'Coleta forense concluída',
            None
        )

        self.logger.info(f"Coleta concluída. Relatório salvo em {self.output_dir}")

        return relatorio

    def _coletar_logs_rede(self):
        """Coletar logs e informações de rede"""
        try:
            # Capturar tráfego de rede por 60 segundos
            pcap_file = self.evidencias_dir / "rede" / "captura_rede.pcap"

            self.logger.info("Capturando tráfego de rede (60 segundos)...")

            # Iniciar captura em background
            tcpdump_proc = subprocess.Popen(
                ['sudo', 'tcpdump', '-i', 'any', '-w', str(pcap_file),
                 '-c', '1000', '-s', '0'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            # Aguardar 60 segundos
            import time
            time.sleep(60)

            # Terminar captura
            tcpdump_proc.terminate()
            tcpdump_proc.wait()

            if pcap_file.exists():
                hashes = self.calcular_hash(pcap_file)
                self.registrar_custodia(
                    'CAPTURA_REDE',
                    'Captura de tráfego de rede realizada',
                    hashes.get('sha256')
                )

        except Exception as e:
            self.logger.error(f"Erro na captura de rede: {e}")

# Interface de linha de comando
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Ferramenta de Coleta Forense')
    parser.add_argument('--caso', required=True, help='ID do caso')
    parser.add_argument('--output', default='/forensics', help='Diretório de saída')
    parser.add_argument('--completa', action='store_true', help='Executar coleta completa')
    parser.add_argument('--disco', help='Dispositivo de disco para imagem')

    args = parser.parse_args()

    # Criar instância do coletor
    coletor = ColetaForense(args.caso, args.output)

    if args.completa:
        # Executar coleta completa
        coletor.executar_coleta_completa()

    if args.disco:
        # Criar imagem de disco específico
        coletor.criar_imagem_disco(args.disco)

    print(f"\n✅ Coleta concluída para caso: {args.caso}")
    print(f"📁 Evidências em: {coletor.output_dir}")
    print(f"📄 Relatório: {coletor.output_dir}/relatorios/relatorio_coleta.md")