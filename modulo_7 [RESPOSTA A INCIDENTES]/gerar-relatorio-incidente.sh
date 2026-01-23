#!/bin/bash
# modulo7/scripts/gerar-relatorio-incidente.sh

echo "=== GERADOR DE RELATÓRIO DE INCIDENTE ==="

# Configurações
INCIDENT_ID="$1"
RELATORIO_DIR="/relatorios/incidentes"
TEMPLATE_DIR="/templates/relatorios"
DATA_HORA=$(date +"%Y-%m-%d_%H%M%S")

# Verificar parâmetro
if [ -z "$INCIDENT_ID" ]; then
    echo "Uso: $0 <ID_INCIDENTE>"
    echo "Exemplo: $0 INC-2024-001"
    exit 1
fi

# Criar diretório do relatório
REPORT_DIR="$RELATORIO_DIR/$INCIDENT_ID"
mkdir -p "$REPORT_DIR"

# Função para gerar seção do relatório
gerar_secao() {
    local titulo="$1"
    local conteudo="$2"
    local arquivo="$3"

    echo "# $titulo" >> "$arquivo"
    echo "" >> "$arquivo"
    echo "$conteudo" >> "$arquivo"
    echo "" >> "$arquivo"
    echo "---" >> "$arquivo"
    echo "" >> "$arquivo"
}

# Iniciar relatório
REPORT_FILE="$REPORT_DIR/relatorio_${INCIDENT_ID}_${DATA_HORA}.md"
echo "Gerando relatório: $REPORT_FILE"

# Cabeçalho do relatório
cat > "$REPORT_FILE" << EOF
# RELATÓRIO DE INCIDENTE DE SEGURANÇA
## ID: $INCIDENT_ID
## Data do Relatório: $(date +"%d/%m/%Y %H:%M:%S")
## Classificação: CONFIDENCIAL

---
EOF

# Coletar informações básicas
gerar_secao "1. RESUMO EXECUTIVO" "$(
echo "Este relatório documenta o incidente de segurança identificado como $INCIDENT_ID."
echo "O incidente foi detectado em $(date -d '2 hours ago' +'%d/%m/%Y %H:%M')."
echo ""
echo "**Impacto:**"
echo "- 3 servidores afetados"
echo "- 4 horas de downtime"
echo "- Dados sensíveis potencialmente comprometidos"
echo ""
echo **"Status Atual:** Incidente contido e em fase de recuperação**"
)" "$REPORT_FILE"

# Linha do tempo
gerar_secao "2. LINHA DO TEMPO" "$(
echo "| Data/Hora | Evento | Responsável |"
echo "|-----------|--------|-------------|"
echo "| $(date -d '4 hours ago' +'%H:%M') | Detecção inicial | SIEM |"
echo "| $(date -d '3 hours ago' +'%H:%M') | Notificação da equipe | Analista SOC |"
echo "| $(date -d '2 hours 30min ago' +'%H:%M') | Início da contenção | CSIRT |"
echo "| $(date -d '1 hour ago' +'%H:%M') | Isolamento completo | Admin Rede |"
echo "| $(date +'%H:%M') | Início da recuperação | Admin Sistemas |"
)" "$REPORT_FILE"

# Análise técnica
gerar_secao "3. ANÁLISE TÉCNICA" "$(
echo "### 3.1 Vetor de Ataque"
echo "O ataque iniciou através de:"
echo "- Email phishing com anexo malicioso"
echo "- Exploração de vulnerabilidade CVE-2023-12345"
echo ""
echo "### 3.2 Técnicas Utilizadas"
echo "1. **T1566 - Phishing**: Email com anexo .docm malicioso"
echo "2. **T1059 - Command Line**: PowerShell para download de payload"
echo "3. **T1486 - Data Encrypted for Impact**: Criptografia de arquivos"
echo ""
echo "### 3.3 Indicadores de Comprometimento (IOCs)"
echo "- Hash SHA256: a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef"
echo "- Domínio C2: malicious-c2[.]com"
echo "- IP: 185.243.115.230"
echo "- Nome do arquivo: invoice.docm"
)" "$REPORT_FILE"

# Impacto
gerar_secao "4. IMPACTO" "$(
echo "### 4.1 Impacto Técnico"
echo "- **Sistemas Afetados:** 3 servidores (SRV-FILE01, SRV-WEB01, SRV-DB01)"
echo "- **Dados Comprometidos:** Arquivos de configuração, logs, backups locais"
echo "- **Tempo de Inatividade:** 4 horas"
echo ""
echo "### 4.2 Impacto de Negócio"
echo "- **Financeiro:** R\$ 15.000,00 estimado"
echo "- **Reputação:** Risco médio"
echo "- **Conformidade:** Potencial violação LGPD"
echo ""
echo "### 4.3 Análise de Riscos"
echo "- **Probabilidade de Recorrência:** Alta"
echo "- **Severidade do Impacto:** Alta"
echo "- **Classificação de Risco:** Alto"
)" "$REPORT_FILE"

# Resposta
gerar_secao "5. RESPOSTA AO INCIDENTE" "$(
echo "### 5.1 Ações de Contenção"
echo "1. Isolamento de rede dos sistemas afetados"
echo "2. Bloqueio de comunicações C2 no firewall"
echo "3. Desabilitação de contas comprometidas"
echo "4. Coleta de evidências forenses"
echo ""
echo "### 5.2 Ações de Erradicação"
echo "1. Remoção completa do malware"
echo "2. Limpeza de artefatos de persistência"
echo "3. Revisão de permissões e acessos"
echo "4. Aplicação de patches de segurança"
echo ""
echo "### 5.3 Ações de Recuperação"
echo "1. Restauração de sistemas a partir de backups"
echo "2. Validação de integridade dos dados"
echo "3. Reconfiguração de sistemas"
echo "4. Retorno gradual aos serviços"
)" "$REPORT_FILE"

# Lições aprendidas
gerar_secao "6. LIÇÕES APRENDIDAS" "$(
echo "### 6.1 O que Funcionou Bem"
echo "- Resposta rápida da equipe CSIRT"
echo - Efetividade dos procedimentos de isolamento"
echo "- Qualidade dos backups para recuperação"
echo ""
echo "### 6.2 Áreas de Melhoria"
echo "1. **Detecção:** Tempo para detecção pode ser reduzido"
echo "2. **Treinamento:** Usuários precisam de mais treinamento anti-phishing"
echo "3. **Controles:** Implementar MFA para todos os acessos"
echo "4. **Monitoramento:** Expandir cobertura de monitoramento"
echo ""
echo "### 6.3 Ações Corretivas"
echo "| Prazo | Ação | Responsável |"
echo "|-------|------|-------------|"
echo "| Imediato | Implementar regras de detecção melhoradas | Analista SOC |"
echo "| 7 dias | Treinamento de conscientização | RH |"
echo "| 30 dias | Implementar MFA em todos os sistemas | Admin Segurança |"
echo "| 60 dias | Revisar e atualizar política de backup | Admin Backup |"
)" "$REPORT_FILE"

# Conclusão
gerar_secao "7. CONCLUSÃO" "$(
echo "O incidente $INCIDENT_ID foi tratado com sucesso pela equipe de resposta."
echo "Todas as ameaças foram erradicadas e os sistemas foram recuperados."
echo ""
echo "**Recomendações Finais:**"
echo "1. Implementar todas as ações corretivas dentro dos prazos estabelecidos"
echo "2. Realizar exercício de resposta a incidentes trimestralmente"
echo "3. Revisar e atualizar os playbooks de resposta"
echo "4. Monitorar continuamente os IOCs relacionados"
echo ""
echo "**Próximos Passos:**"
echo "- Monitoramento aumentado por 30 dias"
echo - Reunião de revisão em 7 dias"
echo "- Atualização deste relatório se novas informações surgirem"
)" "$REPORT_FILE"

# Anexos
gerar_secao "8. ANEXOS" "$(
echo "1. [Evidências Forenses](/forensics/$INCIDENT_ID)"
echo "2. [Logs do Incidente](/logs/$INCIDENT_ID)"
echo "3. [Playbook Executado](/playbooks/ransomware-response.yaml)"
echo "4. [Checklist de Resposta](/checklists/resposta-incidente.md)"
echo ""
echo "**Arquivos Associados:**"
echo "- $REPORT_DIR/evidencias_hashes.txt"
echo "- $REPORT_DIR/linha_tempo_detalhada.csv"
echo "- $REPORT_DIR/analise_malware.pdf"
)" "$REPORT_FILE"

# Assinaturas
cat >> "$REPORT_FILE" << EOF

---
## ASSINATURAS

**Equipe de Resposta a Incidentes:**

| Nome | Função | Assinatura | Data |
|------|--------|------------|------|
| João Silva | Líder CSIRT | _______________ | $(date +'%d/%m/%Y') |
| Maria Santos | Analista Forense | _______________ | $(date +'%d/%m/%Y') |
| Pedro Costa | Admin de Sistemas | _______________ | $(date +'%d/%m/%Y') |

**Aprovação da Gerência:**

| Nome | Função | Assinatura | Data |
|------|--------|------------|------|
| Carlos Oliveira | Gerente de Segurança | _______________ | $(date +'%d/%m/%Y') |
| Ana Rodrigues | Diretora de TI | _______________ | $(date +'%d/%m/%Y') |

---
*Este relatório é confidencial e destinado apenas ao uso autorizado.*
*Distribuição controlada conforme política de segurança da informação.*
EOF

# Gerar versão PDF (se pandoc estiver instalado)
if command -v pandoc &> /dev/null; then
    echo "Gerando versão PDF..."
    pandoc "$REPORT_FILE" -o "${REPORT_FILE%.md}.pdf" \
        --template="$TEMPLATE_DIR/template-relatorio.tex" \
        --pdf-engine=xelatex
fi

# Gerar versão HTML
if command -v pandoc &> /dev/null; then
    echo "Gerando versão HTML..."
    pandoc "$REPORT_FILE" -o "${REPORT_FILE%.md}.html" \
        --template="$TEMPLATE_DIR/template-relatorio.html" \
        --self-contained
fi

echo "✅ Relatório gerado com sucesso!"
echo "📄 Markdown: $REPORT_FILE"
echo "📊 HTML: ${REPORT_FILE%.md}.html"
echo "📎 PDF: ${REPORT_FILE%.md}.pdf"
echo ""
echo "📋 Próximos passos:"
echo "1. Revisar o relatório"
echo "2. Obter assinaturas"
echo "3. Distribuir conforme política"
echo "4. Arquivar no sistema de gestão"