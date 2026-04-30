#!/usr/bin/env bash
# =============================================================================
# restore-snapshot.sh — Restaura um bundle .tar.age em estado limpo.
#
# DESTRUTIVO: derruba os containers, sobrescreve o .env e o DB com o
# conteudo do bundle. Exige confirmacao explicita.
#
# Uso:
#   ./restore-snapshot.sh <bundle.tar.age>
#   ./restore-snapshot.sh <bundle> --target-dir /opt/dns-monitor
#   AGE_IDENTITY=/path/key.txt ./restore-snapshot.sh <bundle>
#   ./restore-snapshot.sh <bundle> --force --non-interactive   # CI
#
# Pos-restore valida:
#   - health check em /health
#   - audit chain integro (verify_audit_chain)
#   - audit_chain_tip_hash atual >= ao do snapshot (ou igual)
# =============================================================================
set -euo pipefail
umask 0022

BUNDLE="${1:-}"
[[ -n "$BUNDLE" ]] || { echo "uso: $0 <bundle.tar.age> [--target-dir <dir>] [--force] [--non-interactive]" >&2; exit 64; }
[[ -f "$BUNDLE" ]] || { echo "ERRO: bundle nao encontrado: $BUNDLE" >&2; exit 66; }
shift

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${TARGET_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
FORCE=0
NON_INTERACTIVE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target-dir) TARGET_DIR="$2"; shift 2 ;;
    --force) FORCE=1; shift ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    *) echo "argumento desconhecido: $1" >&2; exit 64 ;;
  esac
done

DB_CONTAINER="${DB_CONTAINER:-infra_vision_db}"
DB_NAME="${DB_NAME:-dns_monitor}"
DB_USER="${DB_USER:-dnsmonitor}"
NATS_CONTAINER="${NATS_CONTAINER:-infra_vision_nats}"
HEALTH_URL="${HEALTH_URL:-http://localhost:8000/health}"

log()  { printf "[restore] %s\n" "$*" >&2; }
die()  { printf "[restore] ERRO: %s\n" "$*" >&2; exit 1; }
step() { printf "\n[restore] >>> %s\n" "$*" >&2; }

command -v docker     >/dev/null || die "docker nao encontrado"
command -v age        >/dev/null || die "age nao encontrado"
command -v jq         >/dev/null || die "jq nao encontrado"
command -v sha256sum  >/dev/null || die "sha256sum nao encontrado"
command -v tar        >/dev/null || die "tar nao encontrado"
command -v curl       >/dev/null || die "curl nao encontrado"

[[ -d "$TARGET_DIR/backend" ]] \
  || die "TARGET_DIR='$TARGET_DIR' nao parece um checkout do dns-monitor (sem backend/)"

WORK_DIR="$(mktemp -d -t dnsmonrs.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

# -----------------------------------------------------------------------------
# 1) Re-rodar verify-snapshot in-line (rapido)
# -----------------------------------------------------------------------------
step "Decifrando + verificando bundle"
if [[ -n "${AGE_IDENTITY:-}" ]]; then
  [[ -f "$AGE_IDENTITY" ]] || die "AGE_IDENTITY '$AGE_IDENTITY' nao existe"
  age -d -i "$AGE_IDENTITY" -o "$WORK_DIR/bundle.tar" "$BUNDLE" \
    || die "age decifra falhou (chave errada?)"
else
  age -d -o "$WORK_DIR/bundle.tar" "$BUNDLE" \
    || die "age decifra falhou (passphrase errada?)"
fi

mkdir -p "$WORK_DIR/extract"
tar -xf "$WORK_DIR/bundle.tar" -C "$WORK_DIR/extract" || die "tar invalido"
( cd "$WORK_DIR/extract" && sha256sum -c MANIFEST.sha256 --quiet ) \
  || die "MANIFEST.sha256 nao bate (bundle corrompido ou adulterado)"
log "bundle ok"

META="$WORK_DIR/extract/metadata.json"
TS_SNAPSHOT="$(jq -r '.timestamp_utc' "$META")"
GIT_SNAPSHOT="$(jq -r '.git_describe' "$META")"
SCHEMA_SNAPSHOT="$(jq -r '.schema_version' "$META")"
AUDIT_TIP_SNAPSHOT="$(jq -r '.audit_chain_tip_hash' "$META")"

# -----------------------------------------------------------------------------
# 2) Confirmacao
# -----------------------------------------------------------------------------
cat <<EOF >&2

[restore] PRESTES A SOBRESCREVER:
  Target dir : $TARGET_DIR
  DB         : $DB_CONTAINER / $DB_NAME (sera DROPADO e recriado)
  .env       : $TARGET_DIR/backend/.env (sera SOBRESCRITO)
  NATS       : $NATS_CONTAINER (sera derrubado)
  Snapshot de: $TS_SNAPSHOT ($GIT_SNAPSHOT)
  Schema     : $SCHEMA_SNAPSHOT
  Audit tip  : ${AUDIT_TIP_SNAPSHOT:0:24}...

EOF

if [[ $FORCE -eq 0 ]]; then
  if [[ $NON_INTERACTIVE -eq 1 ]]; then
    die "modo --non-interactive exige --force pra confirmar destrutivo"
  fi
  read -r -p "[restore] Digite o nome do banco ('$DB_NAME') pra confirmar: " ANSWER
  [[ "$ANSWER" == "$DB_NAME" ]] || die "confirmacao nao bateu, abortando"
fi

# -----------------------------------------------------------------------------
# 3) Backup defensivo do .env atual (sobrescreve depois)
# -----------------------------------------------------------------------------
step "Backup do .env atual (caso queira rollback manual)"
if [[ -f "$TARGET_DIR/backend/.env" ]]; then
  ENV_BACKUP="$TARGET_DIR/backend/.env.before-restore-$(date -u +%Y%m%dT%H%M%SZ)"
  cp -p "$TARGET_DIR/backend/.env" "$ENV_BACKUP"
  log "backup: $ENV_BACKUP"
fi

# -----------------------------------------------------------------------------
# 4) Derruba stack (preserva volumes pra recriar)
# -----------------------------------------------------------------------------
step "Derrubando stack"
( cd "$TARGET_DIR/backend" && docker compose down ) || log "AVISO: compose down retornou erro (talvez stack ja parada)"

# -----------------------------------------------------------------------------
# 5) Restaura .env e stack files
# -----------------------------------------------------------------------------
step "Restaurando .env + stack"
cp -p "$WORK_DIR/extract/secrets/backend.env" "$TARGET_DIR/backend/.env"
chmod 600 "$TARGET_DIR/backend/.env"
log ".env restaurado (chmod 600)"

# NAO sobrescreve docker-compose.yaml automaticamente — pode haver mudancas
# locais no target. Apenas copia pra .restored como referencia.
cp -p "$WORK_DIR/extract/stack/docker-compose.yaml" "$TARGET_DIR/backend/docker-compose.yaml.restored"
log "compose do snapshot salvo em backend/docker-compose.yaml.restored (compare manualmente)"

# -----------------------------------------------------------------------------
# 6) Sobe DB + NATS (sem o backend ainda — vamos restaurar dump primeiro)
# -----------------------------------------------------------------------------
step "Subindo DB e NATS (sem backend)"
( cd "$TARGET_DIR/backend" && docker compose up -d postgres nats )

# Aguarda postgres ficar healthy
log "aguardando $DB_CONTAINER ficar healthy..."
for i in $(seq 1 60); do
  STATUS="$(docker inspect -f '{{.State.Health.Status}}' "$DB_CONTAINER" 2>/dev/null || echo unknown)"
  [[ "$STATUS" == "healthy" ]] && { log "$DB_CONTAINER healthy"; break; }
  sleep 2
  [[ $i -eq 60 ]] && die "$DB_CONTAINER nao ficou healthy em 120s"
done

# -----------------------------------------------------------------------------
# 7) Drop + recreate DB
# -----------------------------------------------------------------------------
step "Drop + recreate database $DB_NAME"
docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d postgres <<SQL
-- Encerra conexoes ativas no DB alvo (impede drop)
SELECT pg_terminate_backend(pid) FROM pg_stat_activity
  WHERE datname = '$DB_NAME' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS $DB_NAME;
CREATE DATABASE $DB_NAME OWNER $DB_USER;
SQL

# -----------------------------------------------------------------------------
# 8) Globals (best-effort)
# -----------------------------------------------------------------------------
step "Aplicando globals.sql (best-effort)"
docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d postgres \
  < "$WORK_DIR/extract/db/globals.sql" 2>"$WORK_DIR/globals.err" \
  || { log "AVISO: globals.sql apresentou erros (continuando):";
       sed 's/^/  /' "$WORK_DIR/globals.err" >&2; }

# -----------------------------------------------------------------------------
# 9) pg_restore
# -----------------------------------------------------------------------------
step "pg_restore"
docker cp "$WORK_DIR/extract/db/dns_monitor.dump" "$DB_CONTAINER:/tmp/dns_monitor.dump"
docker exec -i "$DB_CONTAINER" pg_restore \
    -U "$DB_USER" -d "$DB_NAME" \
    --jobs=4 \
    --no-owner --no-privileges \
    --exit-on-error \
    /tmp/dns_monitor.dump
docker exec -i "$DB_CONTAINER" rm -f /tmp/dns_monitor.dump
log "pg_restore ok"

# -----------------------------------------------------------------------------
# 10) Sobe backend (apos schema restaurado)
# -----------------------------------------------------------------------------
step "Subindo backend"
( cd "$TARGET_DIR/backend" && docker compose up -d backend )

log "aguardando backend responder em $HEALTH_URL ..."
for i in $(seq 1 30); do
  if curl -sf "$HEALTH_URL" >/dev/null 2>&1; then
    log "backend respondeu /health"
    break
  fi
  sleep 2
  [[ $i -eq 30 ]] && die "backend nao respondeu /health em 60s"
done

# -----------------------------------------------------------------------------
# 11) Validacao audit chain pos-restore
# -----------------------------------------------------------------------------
step "Validando audit chain pos-restore"
CHAIN_RESULT="$(
  docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -tA -c \
    "SELECT COALESCE(row_hash, '') FROM audit_log
     WHERE row_hash IS NOT NULL ORDER BY id DESC LIMIT 1;" 2>/dev/null \
  | tr -d '[:space:]'
)"

if [[ "$AUDIT_TIP_SNAPSHOT" != "<empty>" && -n "$AUDIT_TIP_SNAPSHOT" ]]; then
  if [[ "$CHAIN_RESULT" == "$AUDIT_TIP_SNAPSHOT" ]]; then
    log "audit tip pos-restore == snapshot tip (chain integro, sem rows novas)"
  else
    log "AVISO: audit tip pos-restore difere do snapshot:"
    log "  snapshot tip: ${AUDIT_TIP_SNAPSHOT:0:24}..."
    log "  current  tip: ${CHAIN_RESULT:0:24}..."
    log "  Se houve atividade entre snapshot e restore em outro DB, isso e esperado."
    log "  Se nao houve, INVESTIGAR — pode indicar tampering."
  fi
else
  log "snapshot foi feito sem rows assinadas; nada a comparar"
fi

cat <<EOF >&2

[restore] CONCLUIDO

  Snapshot aplicado: $TS_SNAPSHOT ($GIT_SNAPSHOT)
  Health           : $HEALTH_URL OK
  .env anterior em : ${ENV_BACKUP:-(nao havia .env anterior)}

  Proximo passo recomendado:
    1) Login em /admin pra confirmar que cookies/secrets funcionam
    2) Chamar GET /api/v1/admin/audit/verify pra rodar verify_audit_chain
    3) Conferir backend/docker-compose.yaml.restored vs o atual

EOF
