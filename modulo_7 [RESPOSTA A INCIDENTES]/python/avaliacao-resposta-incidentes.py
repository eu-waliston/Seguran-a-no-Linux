#!/usr/bin/env python3
# modulo7/avaliacao/avaliacao-resposta-incidentes.py
"""
Sistema de Avaliação de Competências em Resposta a Incidentes
"""

import json
import random
from datetime import datetime
from typing import Dict, List, Tuple
import getpass

class AvaliacaoRespostaIncidentes:
    """Sistema de avaliação de competências em resposta a incidentes"""

    def __init__(self):
        self.candidato = None
        self.pontuacao = 0
        self.total_questoes = 0
        self.respostas = []
        self.nivel_competencia = {
            'Iniciante': (0, 40),
            'Básico': (41, 60),
            'Intermediário': (61, 80),
            'Avançado': (81, 90),
            'Especialista': (91, 100)
        }

    def iniciar_avaliacao(self):
        """Iniciar processo de avaliação"""
        print("=" * 60)
        print("   AVALIAÇÃO DE COMPETÊNCIAS - RESPOSTA A INCIDENTES")
        print("=" * 60)
        print()

        # Coletar informações do candidato
        self.candidato = {
            'nome': input("Nome: "),
            'email': input("Email: "),
            'empresa': input("Empresa/Organização: "),
            'cargo': input("Cargo/Função: "),
            'data': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        print("\n" + "=" * 60)
        print("INSTRUÇÕES:")
        print("- A avaliação contém 50 questões")
        print("- Cada questão vale 2 pontos")
        print("- Tempo estimado: 60 minutos")
        print("- Responda com base na sua experiência prática")
        print("=" * 60)

        input("\nPressione Enter para começar...")

        # Executar avaliação
        self.executar_questoes()

        # Calcular resultados
        self.calcular_resultados()

        # Gerar relatório
        self.gerar_relatorio()

    def executar_questoes(self):
        """Executar todas as questões da avaliação"""
        questoes = self.carregar_questoes()
        self.total_questoes = len(questoes)

        for i, questao in enumerate(questoes, 1):
            print(f"\n{'='*60}")
            print(f"QUESTÃO {i}/{self.total_questoes}")
            print(f"Categoria: {questao['categoria']}")
            print(f"{'='*60}")
            print(f"\n{questao['enunciado']}\n")

            # Exibir alternativas
            for idx, alternativa in enumerate(questao['alternativas'], 1):
                print(f"{idx}. {alternativa['texto']}")

            # Obter resposta
            while True:
                try:
                    resposta = int(input(f"\nSua resposta (1-{len(questao['alternativas'])}): "))
                    if 1 <= resposta <= len(questao['alternativas']):
                        break
                    else:
                        print(f"Por favor, digite um número entre 1 e {len(questao['alternativas'])}")
                except ValueError:
                    print("Por favor, digite um número válido")

            # Verificar resposta
            alternativa_escolhida = questao['alternativas'][resposta - 1]
            correta = alternativa_escolhida['correta']

            if correta:
                self.pontuacao += questao['pontuacao']
                print(f"✅ CORRETO! +{questao['pontuacao']} pontos")
            else:
                print(f"❌ INCORRETO")

                # Mostrar resposta correta
                for alt in questao['alternativas']:
                    if alt['correta']:
                        print(f"Resposta correta: {alt['texto']}")
                        break

            # Registrar resposta
            self.respostas.append({
                'questao_id': questao['id'],
                'resposta_escolhida': resposta,
                'correta': correta,
                'categoria': questao['categoria']
            })

    def carregar_questoes(self) -> List[Dict]:
        """Carregar banco de questões"""
        # Em produção, isso viria de um arquivo JSON ou banco de dados
        questoes = [
            {
                'id': 1,
                'categoria': 'Fundamentos',
                'enunciado': 'Qual é a primeira fase do ciclo de vida de resposta a incidentes segundo o NIST?',
                'alternativas': [
                    {'texto': 'Preparação', 'correta': True},
                    {'texto': 'Identificação', 'correta': False},
                    {'texto': 'Contenção', 'correta': False},
                    {'texto': 'Erradicação', 'correta': False}
                ],
                'pontuacao': 2
            },
            {
                'id': 2,
                'categoria': 'Forense',
                'enunciado': 'Ao coletar evidências digitais, qual princípio garante que os dados não foram alterados?',
                'alternativas': [
                    {'texto': 'Cadeia de custódia', 'correta': False},
                    {'texto': 'Integridade', 'correta': True},
                    {'texto': 'Autenticidade', 'correta': False},
                    {'texto': 'Confidencialidade', 'correta': False}
                ],
                'pontuacao': 2
            },
            {
                'id': 3,
                'categoria': 'Ferramentas',
                'enunciado': 'Qual ferramenta é utilizada para análise de memória RAM em sistemas Linux?',
                'alternativas': [
                    {'texto': 'Wireshark', 'correta': False},
                    {'texto': 'Volatility', 'correta': True},
                    {'texto': 'Autopsy', 'correta': False},
                    {'texto': 'Nmap', 'correta': False}
                ],
                'pontuacao': 2
            },
            {
                'id': 4,
                'categoria': 'Ransomware',
                'enunciado': 'Qual é a ação IMEDIATA recomendada ao detectar um ataque de ransomware em um servidor crítico?',
                'alternativas': [
                    {'texto': 'Desligar o servidor', 'correta': False},
                    {'texto': 'Fazer backup dos dados', 'correta': False},
                    {'texto': 'Isolar da rede', 'correta': True},
                    {'texto': 'Notificar a polícia', 'correta': False}
                ],
                'pontuacao': 2
            },
            {
                'id': 5,
                'categoria': 'Comunicação',
                'enunciado': 'Quando um incidente envolve dados pessoais, em quanto tempo deve ser notificada a autoridade competente segundo a LGPD?',
                'alternativas': [
                    {'texto': '24 horas', 'correta': False},
                    {'texto': '48 horas', 'correta': False},
                    {'texto': '72 horas', 'correta': True},
                    {'texto': '7 dias', 'correta': False}
                ],
                'pontuacao': 2
            }
        ]

        # Adicionar mais questões para completar 50
        for i in range(6, 51):
            questoes.append(self.gerar_questao_simulada(i))

        return random.sample(questoes, 50)  # Embaralhar questões

    def gerar_questao_simulada(self, questao_id: int) -> Dict:
        """Gerar questão simulada para completar o banco"""
        categorias = ['Fundamentos', 'Forense', 'Ferramentas', 'Ransomware', 'Comunicação',
                     'Conformidade', 'Análise de Malware', 'SIEM', 'Playbooks']

        categoria = random.choice(categorias)

        # Questões simuladas (em produção teria questões reais)
        templates = [
            {
                'enunciado': f'Em relação a {categoria}, qual afirmação está CORRETA?',
                'alternativas': [
                    {'texto': 'Alternativa A (correta)', 'correta': True},
                    {'texto': 'Alternativa B (incorreta)', 'correta': False},
                    {'texto': 'Alternativa C (incorreta)', 'correta': False},
                    {'texto': 'Alternativa D (incorreta)', 'correta': False}
                ]
            },
            {
                'enunciado': f'Qual ferramenta é mais adequada para {categoria.lower()}?',
                'alternativas': [
                    {'texto': 'Ferramenta A (correta)', 'correta': True},
                    {'texto': 'Ferramenta B (incorreta)', 'correta': False},
                    {'texto': 'Ferramenta C (incorreta)', 'correta': False},
                    {'texto': 'Ferramenta D (incorreta)', 'correta': False}
                ]
            }
        ]

        template = random.choice(templates)

        return {
            'id': questao_id,
            'categoria': categoria,
            'enunciado': template['enunciado'],
            'alternativas': template['alternativas'],
            'pontuacao': 2
        }

    def calcular_resultados(self):
        """Calcular resultados da avaliação"""
        self.percentual = (self.pontuacao / (self.total_questoes * 2)) * 100

        # Determinar nível de competência
        for nivel, (minimo, maximo) in self.nivel_competencia.items():
            if minimo <= self.percentual <= maximo:
                self.nivel = nivel
                break

        # Análise por categoria
        self.analise_categorias = {}
        for resposta in self.respostas:
            categoria = resposta['categoria']
            if categoria not in self.analise_categorias:
                self.analise_categorias[categoria] = {'total': 0, 'acertos': 0}

            self.analise_categorias[categoria]['total'] += 1
            if resposta['correta']:
                self.analise_categorias[categoria]['acertos'] += 1

    def gerar_relatorio(self):
        """Gerar relatório detalhado da avaliação"""
        print("\n" + "=" * 60)
        print("   RESULTADOS DA AVALIAÇÃO")
        print("=" * 60)

        print(f"\nCandidato: {self.candidato['nome']}")
        print(f"Data: {self.candidato['data']}")
        print(f"Cargo: {self.candidato['cargo']}")

        print(f"\n{'='*40}")
        print(f"PONTUAÇÃO FINAL: {self.pontuacao}/{(self.total_questoes * 2)}")
        print(f"PERCENTUAL: {self.percentual:.1f}%")
        print(f"NÍVEL DE COMPETÊNCIA: {self.nivel}")
        print(f"{'='*40}")

        # Análise por categoria
        print("\nANÁLISE POR CATEGORIA:")
        print("-" * 40)

        for categoria, dados in self.analise_categorias.items():
            percentual_categoria = (dados['acertos'] / dados['total']) * 100
            print(f"{categoria}: {dados['acertos']}/{dados['total']} ({percentual_categoria:.1f}%)")

        # Recomendações
        print("\nRECOMENDAÇÕES:")
        print("-" * 40)

        if self.percentual < 60:
            print("📚 Áreas para melhoria:")
            print("1. Realizar treinamentos básicos em resposta a incidentes")
            print("2. Estudar o framework NIST para resposta a incidentes")
            print("3. Praticar em laboratórios de simulação")
            print("4. Participar de exercícios de mesa (tabletop exercises)")
        elif self.percentual < 80:
            print("🎯 Próximos passos:")
            print("1. Aprimorar conhecimentos em análise forense")
            print("2. Aprofundar em ferramentas específicas")
            print("3. Participar de simulados avançados")
            print("4. Obter certificações intermediárias")
        else:
            print("🏆 Excelente desempenho!")
            print("1. Considerar certificações avançadas (GCIH, GCFA)")
            print("2. Mentorar outros profissionais")
            print("3. Contribuir com a comunidade de segurança")
            print("4. Especializar-se em áreas específicas")

        # Salvar relatório
        self.salvar_relatorio_json()

        print(f"\n📄 Relatório salvo em: avaliacoes/{self.candidato['nome'].replace(' ', '_')}_{self.candidato['data'][:10]}.json")
        print("✅ Avaliação concluída!")

    def salvar_relatorio_json(self):
        """Salvar relatório em formato JSON"""
        relatorio = {
            'candidato': self.candidato,
            'resultados': {
                'pontuacao': self.pontuacao,
                'total_possivel': self.total_questoes * 2,
                'percentual': self.percentual,
                'nivel_competencia': self.nivel
            },
            'analise_detalhada': self.analise_categorias,
            'respostas': self.respostas,
            'recomendacoes': self.gerar_recomendacoes_detalhadas()
        }

        # Criar diretório se não existir
        import os
        os.makedirs('avaliacoes', exist_ok=True)

        # Salvar arquivo
        nome_arquivo = f"avaliacoes/{self.candidato['nome'].replace(' ', '_')}_{self.candidato['data'][:10]}.json"
        with open(nome_arquivo, 'w', encoding='utf-8') as f:
            json.dump(relatorio, f, indent=2, ensure_ascii=False)

    def gerar_recomendacoes_detalhadas(self) -> Dict:
        """Gerar recomendações detalhadas por categoria"""
        recomendacoes = {}

        for categoria, dados in self.analise_categorias.items():
            percentual = (dados['acertos'] / dados['total']) * 100

            if percentual < 50:
                recomendacoes[categoria] = {
                    'nivel': 'Necessita melhoria urgente',
                    'acoes': [
                        'Realizar treinamento básico na área',
                        'Praticar com exercícios práticos',
                        'Buscar mentoria de especialistas'
                    ]
                }
            elif percentual < 75:
                recomendacoes[categoria] = {
                    'nivel': 'Pode melhorar',
                    'acoes': [
                        'Aprofundar conhecimentos teóricos',
                        'Participar de workshops',
                        'Estudar casos reais'
                    ]
                }
            else:
                recomendacoes[categoria] = {
                    'nivel': 'Proficiente',
                    'acoes': [
                        'Manter conhecimentos atualizados',
                        'Compartilhar conhecimento com outros',
                        'Buscar especialização avançada'
                    ]
                }

        return recomendacoes

# Executar avaliação
if __name__ == "__main__":
    avaliacao = AvaliacaoRespostaIncidentes()
    avaliacao.iniciar_avaliacao()