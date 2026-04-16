#!/bin/bash
# ===========================================================================
# update_all_agents.sh — Emite comando update_agent para todos os agentes
# Uso: ./scripts/update_all_agents.sh
# Requer: AGENT_TOKEN definido em .env ou passado como argumento
# ===========================================================================
set -euo pipefail

URL="${BACKEND_URL:-http://localhost:8000}"
TOKEN="${AGENT_TOKEN:-$1}"

if [ -z "$TOKEN" ]; then
    echo "Uso: AGENT_TOKEN=xxx ./scripts/update_all_agents.sh"
    echo "  ou: ./scripts/update_all_agents.sh <token>"
    exit 1
fi

echo "=== Listando agentes em $URL ==="
AGENTS=$(curl -sf -H "Authorization: Bearer $TOKEN" "$URL/api/v1/agents" \
    | python3 -c "import sys,json; [print(a['hostname']) for a in json.load(sys.stdin)]")

if [ -z "$AGENTS" ]; then
    echo "Nenhum agente encontrado."
    exit 0
fi

COUNT=0
for HOST in $AGENTS; do
    echo -n "  $HOST → update_agent... "
    RESP=$(curl -sf -X POST "$URL/api/v1/commands" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"hostname\": \"$HOST\", \"command\": \"update_agent\", \"issued_by\": \"admin\"}")
    ID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id','?'))" 2>/dev/null || echo "?")
    echo "ok (cmd #$ID)"
    COUNT=$((COUNT + 1))
done

echo "=== $COUNT comando(s) emitido(s). Agentes atualizam no proximo poll (ate 60s). ==="
