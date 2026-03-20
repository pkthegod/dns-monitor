#!/bin/bash
# install_agent.sh — Instala o dns-agent como serviço systemd
# Execute como root: sudo bash install_agent.sh
set -euo pipefail

INSTALL_DIR="/opt/dns-agent"
CONFIG_DIR="/etc/dns-agent"
LOG_DIR="/var/log/dns-agent"
SERVICE_USER="dns-agent"
SERVICE_FILE="/etc/systemd/system/dns_agent.service"

echo "================================================"
echo "  DNS Monitor Agent — Instalação"
echo "================================================"

# Verifica root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERRO: Execute como root (sudo bash install_agent.sh)"
    exit 1
fi

# Verifica Python 3.8+
if ! python3 -c "import sys; assert sys.version_info >= (3,8)" 2>/dev/null; then
    echo "ERRO: Python 3.8+ necessário. Instale com: apt install python3"
    exit 1
fi

echo ""
echo "1) Criando usuário de serviço '$SERVICE_USER'..."
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    echo "   Usuário criado."
else
    echo "   Usuário já existe."
fi

echo ""
echo "2) Criando diretórios..."
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"

echo ""
echo "3) Copiando arquivos..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$SCRIPT_DIR/dns_agent.py"  "$INSTALL_DIR/"
cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"

# Copia configuração apenas se não existir (preserva configuração existente)
if [ ! -f "$CONFIG_DIR/agent.conf" ]; then
    cp "$SCRIPT_DIR/agent.conf" "$CONFIG_DIR/agent.conf"
    chmod 640 "$CONFIG_DIR/agent.conf"
    chown root:"$SERVICE_USER" "$CONFIG_DIR/agent.conf"
    echo "   Configuração copiada para $CONFIG_DIR/agent.conf"
    echo "   *** EDITE $CONFIG_DIR/agent.conf antes de iniciar o serviço ***"
else
    echo "   Configuração existente preservada em $CONFIG_DIR/agent.conf"
fi

# Link simbólico para o agente encontrar o conf
ln -sfn "$CONFIG_DIR/agent.conf" "$INSTALL_DIR/agent.conf"

echo ""
echo "4) Criando virtualenv e instalando dependências..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
echo "   Dependências instaladas."

echo ""
echo "5) Instalando serviço systemd..."
cp "$SCRIPT_DIR/dns_agent.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable dns_agent
echo "   Serviço instalado e habilitado."

echo ""
echo "================================================"
echo "  Instalação concluída!"
echo ""
echo "  Próximos passos:"
echo "  1. Edite: $CONFIG_DIR/agent.conf"
echo "     - Defina 'hostname' e 'auth_token'"
echo "     - Configure a URL do backend"
echo ""
echo "  2. Inicie o serviço:"
echo "     sudo systemctl start dns_agent"
echo ""
echo "  3. Verifique os logs:"
echo "     sudo journalctl -u dns_agent -f"
echo "================================================"
