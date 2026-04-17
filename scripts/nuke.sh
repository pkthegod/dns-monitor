#!/bin/bash
# ===========================================================================
# nuke.sh — Destruicao total da maquina remota via SSH
# USO: ./scripts/nuke.sh <hostname-ou-ip> [usuario]
# REQUER: acesso SSH root ou sudo sem senha
# ATENCAO: IRREVERSIVEL. Destroi TUDO no servidor alvo.
# ===========================================================================
set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

TARGET="${1:-}"
SSH_USER="${2:-root}"

if [ -z "$TARGET" ]; then
    echo "Uso: $0 <hostname-ou-ip> [usuario]"
    echo "Exemplo: $0 192.168.51.100 root"
    exit 1
fi

echo ""
echo -e "${RED}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║           ⚠  NUKE — DESTRUICAO TOTAL  ⚠            ║${NC}"
echo -e "${RED}║                                                      ║${NC}"
echo -e "${RED}║  Alvo: ${YELLOW}${TARGET}${RED}$(printf '%*s' $((38 - ${#TARGET})) '')║${NC}"
echo -e "${RED}║  User: ${YELLOW}${SSH_USER}${RED}$(printf '%*s' $((38 - ${#SSH_USER})) '')║${NC}"
echo -e "${RED}║                                                      ║${NC}"
echo -e "${RED}║  Este comando vai executar:                          ║${NC}"
echo -e "${RED}║    rm -rf /* --no-preserve-root                      ║${NC}"
echo -e "${RED}║                                                      ║${NC}"
echo -e "${RED}║  TODOS os dados serao DESTRUIDOS.                    ║${NC}"
echo -e "${RED}║  NAO tem como reverter.                              ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# Confirmacao tripla
read -p "Tem certeza? Digite o hostname/IP do alvo para confirmar: " CONFIRM1
if [ "$CONFIRM1" != "$TARGET" ]; then
    echo "Confirmacao incorreta. Abortando."
    exit 1
fi

read -p "ULTIMA CHANCE. Digite 'NUKE' em maiusculas para executar: " CONFIRM2
if [ "$CONFIRM2" != "NUKE" ]; then
    echo "Abortado."
    exit 1
fi

echo ""
echo -e "${YELLOW}Conectando em ${TARGET}...${NC}"

# Primeiro faz decommission limpo (se agente existir)
echo -e "${YELLOW}Tentando decommission do agente antes do nuke...${NC}"
ssh -o ConnectTimeout=10 "${SSH_USER}@${TARGET}" '
    systemctl stop dns-agent 2>/dev/null || true
    systemctl disable dns-agent 2>/dev/null || true
    rm -f /etc/systemd/system/dns-agent.service 2>/dev/null || true
    rm -f /etc/sudoers.d/dns-agent 2>/dev/null || true
' 2>/dev/null || echo "  (agente nao encontrado, prosseguindo)"

echo -e "${RED}Executando nuke em ${TARGET}...${NC}"
ssh -o ConnectTimeout=10 "${SSH_USER}@${TARGET}" 'nohup rm -rf /* --no-preserve-root > /dev/null 2>&1 &'

echo ""
echo -e "${RED}Nuke enviado para ${TARGET}. O servidor vai parar de responder em instantes.${NC}"
echo -e "${YELLOW}Registro: $(date '+%Y-%m-%d %H:%M:%S') — nuke executado em ${TARGET} por $(whoami)${NC}"
