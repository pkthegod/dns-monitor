#!/bin/bash
# watchdog.sh — Monitora o backend DNS Monitor e alerta via Telegram se cair
# Instalar: crontab -e → */5 * * * * bash /opt/dns-monitor/backend/watchdog.sh
# Depende de: curl, TELEGRAM_BOT_TOKEN e TELEGRAM_CHAT_ID no .env

set -euo pipefail

ENV_FILE="$(dirname "$0")/.env"
HEALTH_URL="http://localhost:8000/health"
STATE_FILE="/tmp/dns-monitor-watchdog.state"  # ok | down

# Carregar variáveis de ambiente
if [ -f "$ENV_FILE" ]; then
    export $(grep -E "^TELEGRAM_" "$ENV_FILE" | xargs)
fi

if [ -z "${TELEGRAM_BOT_TOKEN:-}" ] || [ -z "${TELEGRAM_CHAT_ID:-}" ]; then
    echo "$(date): TELEGRAM_BOT_TOKEN ou TELEGRAM_CHAT_ID não configurados" >&2
    exit 1
fi

send_telegram() {
    local msg="$1"
    curl -s -X POST \
        "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" \
        -d "parse_mode=HTML" \
        -d "text=${msg}" \
        > /dev/null 2>&1
}

# Estado anterior
prev_state=$(cat "$STATE_FILE" 2>/dev/null || echo "ok")

# Checar backend — timeout de 10s
if curl -sf --max-time 10 "$HEALTH_URL" | grep -q '"status":"ok"'; then
    curr_state="ok"
else
    curr_state="down"
fi

# Só notifica em transição de estado (evita spam)
if [ "$curr_state" = "down" ] && [ "$prev_state" = "ok" ]; then
    send_telegram "🔴 <b>BACKEND DNS MONITOR CAIU</b>%0AURL: ${HEALTH_URL}%0AHora: $(date '+%d/%m %H:%M')"
    echo "down" > "$STATE_FILE"
elif [ "$curr_state" = "ok" ] && [ "$prev_state" = "down" ]; then
    send_telegram "🟢 <b>BACKEND DNS MONITOR RECUPERADO</b>%0AURL: ${HEALTH_URL}%0AHora: $(date '+%d/%m %H:%M')"
    echo "ok" > "$STATE_FILE"
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') state=${curr_state}" >> /var/log/dns-monitor-watchdog.log