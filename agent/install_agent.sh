#!/bin/bash
# install_agent.sh — Instala o dns-agent como serviço systemd
# Compatível com Debian 12+ e Ubuntu 22.04+
# Execute como root: bash install_agent.sh
set -eu
(set -o pipefail) 2>/dev/null || true


INSTALL_DIR="/opt/dns-agent"
CONFIG_DIR="/etc/dns-agent"
LOG_DIR="/var/log/dns-agent"
SERVICE_USER="dns-agent"
SERVICE_FILE="/etc/systemd/system/dns_agent.service"
ENV_FILE="$CONFIG_DIR/env"

echo "================================================"
echo "  DNS Monitor Agent — Instalação"
echo "================================================"

# ---------------------------------------------------------------------------
# 0. Verificações iniciais
# ---------------------------------------------------------------------------

# Verifica root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERRO: Execute como root: bash install_agent.sh"
    exit 1
fi

# Verifica apt (Debian/Ubuntu)
if ! command -v apt-get &>/dev/null; then
    echo "ERRO: apt-get não encontrado. Este script é para Debian/Ubuntu."
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. Dependências do sistema via apt
# ---------------------------------------------------------------------------
echo ""
echo "1) Instalando dependências do sistema..."

# sudo — pode não estar presente em instalações mínimas
if ! command -v sudo &>/dev/null; then
    echo "   sudo não encontrado — instalando..."
    apt-get install -y --no-install-recommends sudo
    echo "   sudo instalado."
else
    echo "   sudo já presente."
fi

# Python e pacotes necessários para o agente
PKGS_NEEDED=()
for pkg in python3 python3-venv python3-pip python3-pytest; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        PKGS_NEEDED+=("$pkg")
    fi
done

if [ ${#PKGS_NEEDED[@]} -gt 0 ]; then
    echo "   Instalando: ${PKGS_NEEDED[*]}"
    apt-get update -qq
    apt-get install -y --no-install-recommends "${PKGS_NEEDED[@]}"
    echo "   Pacotes instalados."
else
    echo "   Pacotes Python já presentes."
fi

# Verifica Python 3.8+
if ! python3 -c "import sys; assert sys.version_info >= (3,8)" 2>/dev/null; then
    echo "ERRO: Python 3.8+ necessário — versão instalada é muito antiga."
    exit 1
fi

PYTHON_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "   Python $PYTHON_VER OK."

# ---------------------------------------------------------------------------
# 2. Usuário de serviço
# ---------------------------------------------------------------------------
echo ""
echo "2) Criando usuário de serviço '$SERVICE_USER'..."
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    echo "   Usuário criado."
else
    echo "   Usuário já existe."
fi

# ---------------------------------------------------------------------------
# 3. Diretórios
# ---------------------------------------------------------------------------
echo ""
echo "3) Criando diretórios..."
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"
echo "   $INSTALL_DIR, $CONFIG_DIR, $LOG_DIR — OK."

# ---------------------------------------------------------------------------
# 4. Arquivos do agente
# ---------------------------------------------------------------------------
echo ""
echo "4) Copiando arquivos..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$SCRIPT_DIR/dns_agent.py"     "$INSTALL_DIR/"
cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"

# agent.toml — preferencial (TOML); preserva se já existir
if [ -f "$SCRIPT_DIR/agent.toml" ]; then
    if [ ! -f "$CONFIG_DIR/agent.toml" ]; then
        cp "$SCRIPT_DIR/agent.toml" "$CONFIG_DIR/agent.toml"
        chmod 640 "$CONFIG_DIR/agent.toml"
        chown root:"$SERVICE_USER" "$CONFIG_DIR/agent.toml"
        echo "   agent.toml copiado para $CONFIG_DIR/agent.toml"
    else
        echo "   agent.toml existente preservado."
    fi
    ln -sfn "$CONFIG_DIR/agent.toml" "$INSTALL_DIR/agent.toml"
fi

# agent.conf — fallback legado; preserva se já existir
if [ ! -f "$CONFIG_DIR/agent.toml" ] && [ ! -f "$CONFIG_DIR/agent.conf" ]; then
    cp "$SCRIPT_DIR/agent.conf" "$CONFIG_DIR/agent.conf"
    chmod 640 "$CONFIG_DIR/agent.conf"
    chown root:"$SERVICE_USER" "$CONFIG_DIR/agent.conf"
    echo "   agent.conf copiado para $CONFIG_DIR/agent.conf (fallback)"
    ln -sfn "$CONFIG_DIR/agent.conf" "$INSTALL_DIR/agent.conf"
elif [ -f "$CONFIG_DIR/agent.conf" ] && [ ! -f "$CONFIG_DIR/agent.toml" ]; then
    echo "   agent.conf legado preservado (considere migrar para agent.toml)."
    ln -sfn "$CONFIG_DIR/agent.conf" "$INSTALL_DIR/agent.conf"
fi

# Arquivo de segredos — prioridade:
#   1. env na mesma pasta do install_agent.sh → copia (sempre atualiza)
#   2. /etc/dns-agent/env já existe           → preserva
#   3. nenhum encontrado                       → cria template
ENV_COPIED=false
if [ -f "$SCRIPT_DIR/env" ]; then
    cp "$SCRIPT_DIR/env" "$ENV_FILE"
    chmod 640 "$ENV_FILE"
    chown root:"$SERVICE_USER" "$ENV_FILE"
    ENV_COPIED=true
    echo "   env copiado de $SCRIPT_DIR/env para $ENV_FILE"
elif [ -f "$ENV_FILE" ]; then
    echo "   $ENV_FILE existente preservado."
else
    cat > "$ENV_FILE" << 'ENVEOF'
# Segredos do agente DNS Monitor
# Preencha os 3 valores antes de iniciar o serviço
# Documentação: README.md → Instalação do Agente

AGENT_HOSTNAME=TROQUE_PELO_HOSTNAME
AGENT_TOKEN=TROQUE_POR_TOKEN_SEGURO
AGENT_BACKEND=http://IP_DO_BACKEND:8000
ENVEOF
    chmod 640 "$ENV_FILE"
    chown root:"$SERVICE_USER" "$ENV_FILE"
    echo "   $ENV_FILE criado com template — preencha antes de iniciar."
fi

# ---------------------------------------------------------------------------
# 5. Sudoers — controle remoto do serviço DNS
# ---------------------------------------------------------------------------
echo ""
echo "5) Configurando permissões sudo para controle remoto do DNS..."
SUDOERS_FILE="/etc/sudoers.d/dns-agent"
cat > "$SUDOERS_FILE" << 'SUDOEOF'
# dns-agent — permissões de controle remoto do serviço DNS
# Gerado por install_agent.sh — não edite manualmente
# Inclui bind9, named (alias Debian) e unbound
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
if visudo -c -f "$SUDOERS_FILE" &>/dev/null; then
    echo "   Sudoers configurado em $SUDOERS_FILE"
else
    echo "   AVISO: falha ao validar sudoers — removendo regra"
    rm -f "$SUDOERS_FILE"
fi

# ---------------------------------------------------------------------------
# 6. Virtualenv e dependências Python
# ---------------------------------------------------------------------------
echo ""
echo "6) Criando virtualenv e instalando dependências..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
echo "   Dependências instaladas."

# ---------------------------------------------------------------------------
# 7. Serviço systemd
# ---------------------------------------------------------------------------
echo ""
echo "7) Instalando serviço systemd..."
cp "$SCRIPT_DIR/dns_agent.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable dns_agent
echo "   Serviço instalado e habilitado."

# ---------------------------------------------------------------------------
# 8. Verificação do arquivo env
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
if [ "$ENV_COPIED" = true ] && [ "$ENV_OK" != true ]; then
    # env copiado da pasta mas ainda tem placeholders — arquivo incompleto
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║  env copiado mas com valores inválidos   ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""
    echo "  O arquivo $SCRIPT_DIR/env ainda contém placeholders."
    echo "  Edite e execute o instalador novamente:"
    echo "    nano $SCRIPT_DIR/env"
    echo "    bash $SCRIPT_DIR/install_agent.sh"
    echo "================================================"
elif [ "$ENV_OK" = true ]; then
    systemctl start dns_agent
    echo "================================================"
    echo "  Instalação concluída e serviço iniciado!"
    echo ""
    echo "  Verifique os logs:"
    echo "    journalctl -u dns_agent -f"
    echo "================================================"
else
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║  AÇÃO NECESSÁRIA antes de iniciar        ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""
    echo "  Edite o arquivo de segredos:"
    echo "    nano $ENV_FILE"
    echo ""
    echo "  Preencha os 3 campos marcados com ✗ acima."
    echo ""
    echo "    AGENT_HOSTNAME  — nome único desta máquina"
    echo "    AGENT_TOKEN     — token do backend (backend/.env → AGENT_TOKEN)"
    echo "    AGENT_BACKEND   — URL do servidor, ex: http://192.168.1.10:8000"
    echo ""
    echo "  Após preencher, inicie o serviço:"
    echo "    systemctl start dns_agent"
    echo "    journalctl -u dns_agent -f"
    echo "================================================"
fi