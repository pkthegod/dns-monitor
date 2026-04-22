#!/usr/bin/env bash
# smoke-test-security.sh — Valida fixes C1/C2/C3 de 2026-04-22
#
# Uso:
#   BASE=http://localhost:8000 \
#   ADMIN_USER=admin ADMIN_PASS='...' \
#   CLIENT_USER=cliente1 CLIENT_PASS='...' \
#   ./scripts/smoke-test-security.sh
#
# Exit code 0 = todos passam, !=0 = algum falhou.

set -u

BASE="${BASE:-http://localhost:8000}"
ADMIN_USER="${ADMIN_USER:-}"
ADMIN_PASS="${ADMIN_PASS:-}"
CLIENT_USER="${CLIENT_USER:-}"
CLIENT_PASS="${CLIENT_PASS:-}"

PASS=0
FAIL=0
ADMIN_COOKIES=$(mktemp)
CLIENT_COOKIES=$(mktemp)
trap 'rm -f "$ADMIN_COOKIES" "$CLIENT_COOKIES"' EXIT

ok()   { echo "  ✅ $*"; PASS=$((PASS+1)); }
fail() { echo "  ❌ $*"; FAIL=$((FAIL+1)); }
hdr()  { echo; echo "── $* ──"; }

# Helper: assert HTTP status code
expect_status() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "$actual" == "$expected" ]]; then ok "$desc → $actual"
  else fail "$desc → esperava $expected, veio $actual"
  fi
}

hdr "0. Health check"
status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/health")
expect_status "GET /health" 200 "$status"

hdr "1. /session/token deve estar deprecated (410)"
status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/v1/session/token")
expect_status "GET /api/v1/session/token (sem cookie)" 410 "$status"

hdr "2. /session/whoami sem cookie → 401"
status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/v1/session/whoami")
expect_status "GET /api/v1/session/whoami (anônimo)" 401 "$status"

hdr "3. WS /ws/live sem cookie nem token → reject"
# Usa curl com Upgrade header — Upgrade vai falhar, mas a primeira resposta HTTP indica auth
status=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  "$BASE/ws/live")
# Esperado: 401 (rejeita antes de upgrade) ou 403
if [[ "$status" == "401" ]] || [[ "$status" == "403" ]]; then
  ok "WS sem auth → $status"
else
  fail "WS sem auth → esperava 401/403, veio $status"
fi

if [[ -z "$ADMIN_USER" || -z "$ADMIN_PASS" ]]; then
  echo
  echo "⚠️  ADMIN_USER/ADMIN_PASS não informados — pulando testes admin/client"
  echo
else
  hdr "4. Admin login + whoami"
  status=$(curl -s -o /dev/null -w "%{http_code}" -c "$ADMIN_COOKIES" \
    -X POST "$BASE/admin/login" \
    -d "username=$ADMIN_USER&password=$ADMIN_PASS")
  expect_status "POST /admin/login" 303 "$status"

  body=$(curl -s -b "$ADMIN_COOKIES" "$BASE/api/v1/session/whoami")
  if echo "$body" | grep -q '"kind":"admin"'; then
    ok "GET /api/v1/session/whoami → kind=admin"
  else
    fail "whoami admin retornou: $body"
  fi

  hdr "5. Admin acessa /api/v1/agents (cookie suficiente)"
  status=$(curl -s -o /dev/null -w "%{http_code}" -b "$ADMIN_COOKIES" "$BASE/api/v1/agents")
  expect_status "GET /api/v1/agents (admin cookie)" 200 "$status"

  hdr "6. Admin acessa /api/v1/dashboard/data"
  status=$(curl -s -o /dev/null -w "%{http_code}" -b "$ADMIN_COOKIES" \
    "$BASE/api/v1/dashboard/data?period=1h")
  expect_status "GET /api/v1/dashboard/data (admin)" 200 "$status"
fi

if [[ -z "$CLIENT_USER" || -z "$CLIENT_PASS" ]]; then
  echo
  echo "⚠️  CLIENT_USER/CLIENT_PASS não informados — pulando testes de isolamento client"
  echo
else
  hdr "7. Client login"
  status=$(curl -s -o /dev/null -w "%{http_code}" -c "$CLIENT_COOKIES" \
    -X POST "$BASE/client/login" \
    -d "username=$CLIENT_USER&password=$CLIENT_PASS")
  expect_status "POST /client/login" 303 "$status"

  body=$(curl -s -b "$CLIENT_COOKIES" "$BASE/api/v1/session/whoami")
  if echo "$body" | grep -q '"kind":"client"'; then
    ok "GET /api/v1/session/whoami → kind=client"
  else
    fail "whoami client retornou: $body"
  fi

  hdr "8. 🔴 REGRESSÃO CRÍTICA: client NÃO deve acessar /api/v1/agents"
  status=$(curl -s -o /dev/null -w "%{http_code}" -b "$CLIENT_COOKIES" "$BASE/api/v1/agents")
  if [[ "$status" == "401" || "$status" == "403" ]]; then
    ok "Client em /api/v1/agents → $status (bloqueado, correto)"
  else
    fail "Client conseguiu acessar /api/v1/agents — status $status — VAZAMENTO!"
  fi

  hdr "9. 🔴 REGRESSÃO CRÍTICA: client NÃO deve mandar comandos"
  status=$(curl -s -o /dev/null -w "%{http_code}" -b "$CLIENT_COOKIES" \
    -X POST "$BASE/api/v1/commands" \
    -H "Content-Type: application/json" \
    -d '{"hostname":"qualquer-host","command":"stop"}')
  if [[ "$status" == "401" || "$status" == "403" ]]; then
    ok "Client em POST /api/v1/commands → $status (bloqueado, correto)"
  else
    fail "Client conseguiu mandar comando — status $status — RCE CROSS-TENANT!"
  fi

  hdr "10. 🔴 REGRESSÃO CRÍTICA: /session/token não vaza mais o token"
  body=$(curl -s -b "$CLIENT_COOKIES" "$BASE/api/v1/session/token")
  if echo "$body" | grep -q '"token"'; then
    fail "/session/token AINDA RETORNA O TOKEN: $body"
  else
    ok "/session/token não retorna AGENT_TOKEN (resposta: $(echo $body | head -c 100))"
  fi

  hdr "11. Client acessa endpoint próprio (/api/v1/client/data)"
  status=$(curl -s -o /dev/null -w "%{http_code}" -b "$CLIENT_COOKIES" \
    "$BASE/api/v1/client/data?period=24h")
  expect_status "GET /api/v1/client/data (client cookie)" 200 "$status"
fi

echo
echo "═══════════════════════════════════════"
echo "  Resultado: $PASS passou, $FAIL falhou"
echo "═══════════════════════════════════════"
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
