#!/bin/bash
# install_agent.sh — Instala o dns-agent como serviço systemd
# Execute como root: sudo bash install_agent.sh
set -euo pipefail

INSTALL_DIR="/opt/dns-agent"
CONFIG_DIR="/etc/dns-agent"
LOG_DIR="/var/log/dns-agent"
SERVICE_USER="dns-agent"
SERVICE_FILE="/etc/systemd/system/dns_agent.service"
ENV_FILE="$CONFIG_DIR/env"

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
cp "$SCRIPT_DIR/dns_agent.py"    "$INSTALL_DIR/"
cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"

# Copia agent.conf apenas se não existir (preserva configuração existente)
if [ ! -f "$CONFIG_DIR/agent.conf" ]; then
    cp "$SCRIPT_DIR/agent.conf" "$CONFIG_DIR/agent.conf"
    chmod 640 "$CONFIG_DIR/agent.conf"
    chown root:"$SERVICE_USER" "$CONFIG_DIR/agent.conf"
    echo "   agent.conf copiado para $CONFIG_DIR/agent.conf"
else
    echo "   agent.conf existente preservado em $CONFIG_DIR/agent.conf"
fi

# Link simbólico para o agente encontrar o conf
ln -sfn "$CONFIG_DIR/agent.conf" "$INSTALL_DIR/agent.conf"

# Cria o arquivo env se não existir — sem ele o systemd não sobe o serviço
if [ ! -f "$ENV_FILE" ]; then
    echo "   Criando $ENV_FILE com template..."
    cat > "$ENV_FILE" << 'ENVEOF'
# Segredos do agente DNS Monitor
# Preencha os 3 valores abaixo antes de iniciar o serviço
# Documentação: README.md → Instalação do Agente

AGENT_HOSTNAME=TROQUE_PELO_HOSTNAME
AGENT_TOKEN=TROQUE_POR_TOKEN_SEGURO
AGENT_BACKEND=http://IP_DO_BACKEND:8000
ENVEOF
    chmod 640 "$ENV_FILE"
    chown root:"$SERVICE_USER" "$ENV_FILE"
    echo "   $ENV_FILE criado com template."
else
    echo "   $ENV_FILE existente preservado."
fi

echo ""
echo "4) Configurando permissões sudo para controle do serviço DNS..."
SUDOERS_FILE="/etc/sudoers.d/dns-agent"
cat > "$SUDOERS_FILE" << 'SUDOEOF'
# Permissões do dns-agent para controlar serviços DNS remotamente
# Gerado por install_agent.sh — não edite manualmente
Defaults:dns-agent !use_pty
dns-agent ALL=(root) NOPASSWD: /usr/bin/systemctl stop bind9, \
                                /usr/bin/systemctl stop named, \
                                /usr/bin/systemctl stop unbound, \
                                /usr/bin/systemctl disable --now bind9, \
                                /usr/bin/systemctl disable --now named, \
                                /usr/bin/systemctl disable --now unbound, \
                                /usr/bin/systemctl enable --now bind9, \
                                /usr/bin/systemctl enable --now named, \
                                /usr/bin/systemctl enable --now unbound, \
                                /usr/bin/systemctl start bind9, \
                                /usr/bin/systemctl start named, \
                                /usr/bin/systemctl start unbound, \
                                /usr/bin/apt-get purge -y bind9, \
                                /usr/bin/apt-get purge -y unbound, \
                                /usr/bin/apt-get purge -y named
SUDOEOF
chmod 440 "$SUDOERS_FILE"
# Validar sintaxe — se inválido, remove e continua sem sudo
if visudo -c -f "$SUDOERS_FILE" &>/dev/null; then
    echo "   Permissões sudo configuradas em $SUDOERS_FILE"
else
    echo "   AVISO: falha ao validar sudoers — removendo regra"
    rm -f "$SUDOERS_FILE"
fi

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

# ---------------------------------------------------------------------------
# Verificação do arquivo env antes de encerrar
# ---------------------------------------------------------------------------
echo ""
echo "================================================"
echo "  Verificando $ENV_FILE..."
echo "================================================"

ENV_OK=true

check_var() {
    local var="$1"
    local value
    value=$(grep -E "^${var}=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- | tr -d ' ')
    if [ -z "$value" ] || \
       [ "$value" = "TROQUE_PELO_HOSTNAME" ] || \
       [ "$value" = "TROQUE_POR_TOKEN_SEGURO" ] || \
       [ "$value" = "http://IP_DO_BACKEND:8000" ]; then
        echo "  ✗  $var — NÃO preenchido"
        ENV_OK=false
    else
        echo "  ✓  $var"
    fi
}

check_var "AGENT_HOSTNAME"
check_var "AGENT_TOKEN"
check_var "AGENT_BACKEND"

echo ""
if [ "$ENV_OK" = true ]; then
    echo "  Arquivo env OK — iniciando serviço..."
    echo ""
    systemctl start dns_agent
    echo ""
    echo "================================================"
    echo "  Instalação concluída e serviço iniciado!"
    echo ""
    echo "  Verifique os logs:"
    echo "    sudo journalctl -u dns_agent -f"
    echo "================================================"
else
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║  AÇÃO NECESSÁRIA antes de iniciar        ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""
    echo "  Edite o arquivo de segredos:"
    echo "    sudo nano $ENV_FILE"
    echo ""
    echo "  Preencha os 3 campos marcados com ✗ acima."
    echo "  Os valores devem ser:"
    echo ""
    echo "    AGENT_HOSTNAME  — nome único desta máquina"
    echo "    AGENT_TOKEN     — token do backend (backend/.env → AGENT_TOKEN)"
    echo "    AGENT_BACKEND   — URL do servidor, ex: http://192.168.1.10:8000"
    echo ""
    echo "  Após preencher, inicie o serviço:"
    echo "    sudo systemctl start dns_agent"
    echo "    sudo journalctl -u dns_agent -f"
    echo "================================================"
fi
