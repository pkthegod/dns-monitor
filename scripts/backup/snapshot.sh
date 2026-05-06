#!/usr/bin/env bash
# =============================================================================
# snapshot.sh — Cria bundle cifrado e replicavel do dns-monitor.
#
# Captura: schema+dados do TimescaleDB, .env do backend, docker-compose,
# provisioning do Grafana, dados do NATS jetstream, metadata com audit
# chain tip e git commit. Resultado: 1 arquivo .tar.age.
#
# Restore com: scripts/backup/restore-snapshot.sh <bundle.tar.age>
#
# Uso:
#   ./snapshot.sh                  # cria bundle em $BACKUP_DIR
#   ./snapshot.sh --dry-run        # so reporta o que faria
#   BACKUP_DIR=/mnt/backups ./snapshot.sh
#
# Requisitos: bash >=4, docker, age (https://age-encryption.org), jq, gzip
#
# Cifra:
#   - Se BACKUP_AGE_RECIPIENTS_FILE definido: multi-recipient (recomendado).
#   - Senao: passphrase via prompt interativo (age -p).
#
# =============================================================================
set -euo pipefail
umask 0077  # bundles so visiveis pro dono

# -----------------------------------------------------------------------------
# Config (override via env)
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${PROJECT_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)}"

BACKUP_DIR="${BACKUP_DIR:-$PROJECT_DIR/.backups}"
DB_CONTAINER="${DB_CONTAINER:-infra_vision_db}"
DB_NAME="${DB_NAME:-dns_monitor}"
DB_USER="${DB_USER:-dnsmonitor}"
NATS_CONTAINER="${NATS_CONTAINER:-infra_vision_nats}"
INCLUDE_NATS="${INCLUDE_NATS:-1}"   # 1=inclui jetstream data, 0=pula

# Multi-recipient: arquivo com pubkeys age (uma por linha, # = comentario)
BACKUP_AGE_RECIPIENTS_FILE="${BACKUP_AGE_RECIPIENTS_FILE:-}"

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

# -----------------------------------------------------------------------------
# Logging helpers
# -----------------------------------------------------------------------------
log()  { printf "[snapshot] %s\n" "$*" >&2; }
die()  { printf "[snapshot] ERRO: %s\n" "$*" >&2; exit 1; }
step() { printf "\n[snapshot] >>> %s\n" "$*" >&2; }

# -----------------------------------------------------------------------------
# Pre-flight checks
# -----------------------------------------------------------------------------
step "Pre-flight"

command -v docker >/dev/null  || die "docker nao encontrado no PATH"
command -v age    >/dev/null  || die "age nao encontrado. Instale: https://age-encryption.org (ou: apt install age / brew install age)"
command -v jq     >/dev/null  || die "jq nao encontrado. Instale: apt install jq / brew install jq"
command -v gzip   >/dev/null  || die "gzip nao encontrado"
command -v sha256sum >/dev/null || die "sha256sum nao encontrado"
command -v tar    >/dev/null  || die "tar nao encontrado"

docker inspect "$DB_CONTAINER" >/dev/null 2>&1 \
  || die "container '$DB_CONTAINER' nao existe ou docker daemon offline"

DB_RUNNING=$(docker inspect -f '{{.State.Running}}' "$DB_CONTAINER" 2>/dev/null || echo "false")
[[ "$DB_RUNNING" == "true" ]] \
  || die "container '$DB_CONTAINER' nao esta rodando (snapshot em DB parado e inseguro: pode pegar checkpoint inconsistente)"

if [[ -n "$BACKUP_AGE_RECIPIENTS_FILE" ]]; then
  [[ -f "$BACKUP_AGE_RECIPIENTS_FILE" ]] \
    || die "BACKUP_AGE_RECIPIENTS_FILE='$BACKUP_AGE_RECIPIENTS_FILE' nao existe"
  CIPHER_MODE="recipients"
  log "Cifra: multi-recipient ($BACKUP_AGE_RECIPIENTS_FILE)"
else
  CIPHER_MODE="passphrase"
  log "Cifra: passphrase (configure BACKUP_AGE_RECIPIENTS_FILE pra multi-recipient)"
fi

[[ -f "$PROJECT_DIR/backend/.env" ]] \
  || die "backend/.env nao encontrado em $PROJECT_DIR/backend/. Sem .env, snapshot nao e replicavel."

mkdir -p "$BACKUP_DIR"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
GIT_COMMIT="$(git -C "$PROJECT_DIR" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
GIT_DESC="$(git -C "$PROJECT_DIR" describe --tags --always --dirty 2>/dev/null || echo unknown)"
BUNDLE_NAME="dns-monitor-snapshot-${TS}-${GIT_COMMIT}"
WORK_DIR="$(mktemp -d -t dnsmonbk.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

log "Working dir: $WORK_DIR"
log "Output dir : $BACKUP_DIR"
log "Bundle name: $BUNDLE_NAME.tar.age"
log "Git        : $GIT_DESC ($GIT_COMMIT)"

if [[ $DRY_RUN -eq 1 ]]; then
  log "DRY RUN — abortando antes de qualquer escrita."
  exit 0
fi

# -----------------------------------------------------------------------------
# Capture: globals (roles)
# -----------------------------------------------------------------------------
step "Postgres globals (roles)"
mkdir -p "$WORK_DIR/db"
# pg_dumpall --globals-only precisa de superuser. POSTGRES_USER e superuser
# por default no container Timescale official. Se falhar, registra warning.
if ! docker exec -i "$DB_CONTAINER" pg_dumpall --globals-only -U "$DB_USER" \
       > "$WORK_DIR/db/globals.sql" 2>"$WORK_DIR/db/globals.err"; then
  log "AVISO: pg_dumpall globals falhou. Conteudo do erro:"
  sed 's/^/  /' "$WORK_DIR/db/globals.err" >&2
  log "Continuando sem globals — restore precisara de um POSTGRES_USER configurado."
  echo "-- pg_dumpall --globals-only falhou em $TS" > "$WORK_DIR/db/globals.sql"
fi
GLOBALS_BYTES=$(wc -c < "$WORK_DIR/db/globals.sql")
log "globals.sql: $GLOBALS_BYTES bytes"

# -----------------------------------------------------------------------------
# Capture: pg_dump custom format (paralelizavel no restore)
# -----------------------------------------------------------------------------
step "pg_dump $DB_NAME (custom format)"
docker exec -i "$DB_CONTAINER" pg_dump \
    -U "$DB_USER" -d "$DB_NAME" \
    --format=custom --compress=6 \
    --no-owner --no-privileges \
  > "$WORK_DIR/db/dns_monitor.dump"

DUMP_BYTES=$(wc -c < "$WORK_DIR/db/dns_monitor.dump")
log "dns_monitor.dump: $(numfmt --to=iec --suffix=B $DUMP_BYTES 2>/dev/null || echo "$DUMP_BYTES bytes")"

# -----------------------------------------------------------------------------
# Capture: audit chain tip (pra detectar tampering pos-restore)
# -----------------------------------------------------------------------------
step "Audit chain tip"
AUDIT_TIP="$(
  docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -tA -c \
    "SELECT COALESCE(row_hash, '') FROM audit_log
     WHERE row_hash IS NOT NULL ORDER BY id DESC LIMIT 1;" 2>/dev/null \
  || echo ""
)"
AUDIT_TIP="${AUDIT_TIP//[$'\r\n ']}"
if [[ -z "$AUDIT_TIP" ]]; then
  log "audit_log sem rows assinadas (chain ainda nao iniciado ou tabela vazia)"
  AUDIT_TIP="<empty>"
else
  log "audit tip: ${AUDIT_TIP:0:16}..."
fi

# -----------------------------------------------------------------------------
# Capture: schema introspection (versoes, contagens)
# -----------------------------------------------------------------------------
step "DB metadata"
PG_VERSION="$(docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -tA -c "SHOW server_version;" 2>/dev/null | tr -d '[:space:]' || echo unknown)"
TS_VERSION="$(docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -tA -c "SELECT extversion FROM pg_extension WHERE extname='timescaledb';" 2>/dev/null | tr -d '[:space:]' || echo unknown)"
DB_SIZE_BYTES="$(docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -tA -c "SELECT pg_database_size('$DB_NAME');" 2>/dev/null | tr -d '[:space:]' || echo 0)"
ROW_COUNTS="$(docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -tA -F$'\t' -c \
  "SELECT 'agents',COUNT(*) FROM agents UNION ALL
   SELECT 'audit_log',COUNT(*) FROM audit_log UNION ALL
   SELECT 'alerts_log',COUNT(*) FROM alerts_log UNION ALL
   SELECT 'agent_commands',COUNT(*) FROM agent_commands UNION ALL
   SELECT 'client_users',COUNT(*) FROM client_users;" 2>/dev/null \
  | jq -Rs 'split("\n") | map(select(length>0)) | map(split("\t")) | map({(.[0]): (.[1]|tonumber)}) | add' \
  || echo '{}')"

# -----------------------------------------------------------------------------
# Capture: .env (segredos do backend)
# -----------------------------------------------------------------------------
step "backend/.env"
mkdir -p "$WORK_DIR/secrets"
cp -p "$PROJECT_DIR/backend/.env" "$WORK_DIR/secrets/backend.env"
ENV_BYTES=$(wc -c < "$WORK_DIR/secrets/backend.env")
log "backend.env: $ENV_BYTES bytes (sera cifrado dentro do bundle, que tambem e cifrado)"

# -----------------------------------------------------------------------------
# Capture: stack (compose + nats config + schemas + agent code)
# -----------------------------------------------------------------------------
step "stack files"
mkdir -p "$WORK_DIR/stack"
cp -p "$PROJECT_DIR/backend/docker-compose.yaml" "$WORK_DIR/stack/docker-compose.yaml"
cp -p "$PROJECT_DIR/backend/timescaledb.yaml"   "$WORK_DIR/stack/timescaledb.yaml" 2>/dev/null || true
cp -p "$PROJECT_DIR/backend/schemas.sql"        "$WORK_DIR/stack/schemas.sql"
cp -p "$PROJECT_DIR/backend/Dockerfile"         "$WORK_DIR/stack/Dockerfile" 2>/dev/null || true
cp -p "$PROJECT_DIR/backend/nats-server.conf"   "$WORK_DIR/stack/nats-server.conf" 2>/dev/null || true

# Codigo do agente (tem que casar com o que esta no DB)
mkdir -p "$WORK_DIR/stack/agent"
cp -p "$PROJECT_DIR/agent/dns_agent.py" "$WORK_DIR/stack/agent/dns_agent.py" 2>/dev/null || true

# -----------------------------------------------------------------------------
# Capture: NATS jetstream (mensagens em flight)
# -----------------------------------------------------------------------------
if [[ $INCLUDE_NATS -eq 1 ]] && docker inspect "$NATS_CONTAINER" >/dev/null 2>&1; then
  step "NATS jetstream data"
  mkdir -p "$WORK_DIR/nats"
  # Dump do volume /data via tar dentro do container -> stdout -> arquivo local
  if docker exec "$NATS_CONTAINER" tar -C /data -cf - . 2>/dev/null > "$WORK_DIR/nats/jetstream.tar"; then
    NATS_BYTES=$(wc -c < "$WORK_DIR/nats/jetstream.tar")
    log "jetstream.tar: $(numfmt --to=iec --suffix=B $NATS_BYTES 2>/dev/null || echo "$NATS_BYTES bytes")"
  else
    log "AVISO: dump NATS falhou (pode estar parado). Pulando."
    rm -rf "$WORK_DIR/nats"
  fi
fi

# -----------------------------------------------------------------------------
# Imagens fixadas (tags do compose)
# -----------------------------------------------------------------------------
IMAGES_JSON="$(grep -E '^\s*image:' "$WORK_DIR/stack/docker-compose.yaml" \
  | awk '{print $2}' | jq -R . | jq -s .)"

# -----------------------------------------------------------------------------
# metadata.json
# -----------------------------------------------------------------------------
step "metadata.json"
HOST_INFO="$(uname -a 2>/dev/null || echo unknown)"
jq -n \
  --arg ts "$TS" \
  --arg git_commit "$GIT_COMMIT" \
  --arg git_desc "$GIT_DESC" \
  --arg pg_version "$PG_VERSION" \
  --arg ts_version "$TS_VERSION" \
  --arg audit_tip "$AUDIT_TIP" \
  --arg cipher_mode "$CIPHER_MODE" \
  --arg host "$HOST_INFO" \
  --argjson db_size_bytes "${DB_SIZE_BYTES:-0}" \
  --argjson images "$IMAGES_JSON" \
  --argjson row_counts "$ROW_COUNTS" \
  --arg schema_version "v1.5-c2-audit-chain" \
  --arg snapshot_format "1" \
  '{
    snapshot_format: $snapshot_format,
    timestamp_utc: $ts,
    git_commit: $git_commit,
    git_describe: $git_desc,
    schema_version: $schema_version,
    pg_version: $pg_version,
    timescaledb_version: $ts_version,
    db_size_bytes: $db_size_bytes,
    audit_chain_tip_hash: $audit_tip,
    docker_images_pinned: $images,
    row_counts: $row_counts,
    cipher_mode: $cipher_mode,
    captured_on_host: $host
  }' > "$WORK_DIR/metadata.json"

cat "$WORK_DIR/metadata.json" >&2

# -----------------------------------------------------------------------------
# MANIFEST.sha256 (hash de tudo, exceto o proprio MANIFEST)
# -----------------------------------------------------------------------------
step "MANIFEST.sha256"
( cd "$WORK_DIR" && find . -type f ! -name MANIFEST.sha256 -print0 \
  | sort -z \
  | xargs -0 sha256sum > MANIFEST.sha256 )
log "$(wc -l < "$WORK_DIR/MANIFEST.sha256") arquivos no manifest"

# -----------------------------------------------------------------------------
# Tar + age (cifra)
# -----------------------------------------------------------------------------
step "Empacotando + cifrando"
TAR_PATH="$WORK_DIR/$BUNDLE_NAME.tar"
( cd "$WORK_DIR" && tar -cf "$TAR_PATH" \
    metadata.json MANIFEST.sha256 db secrets stack \
    $( [[ -d nats ]] && echo nats ) )

OUT_PATH="$BACKUP_DIR/$BUNDLE_NAME.tar.age"

if [[ "$CIPHER_MODE" == "recipients" ]]; then
  # Multi-recipient: -R aceita arquivo com pubkeys
  age -R "$BACKUP_AGE_RECIPIENTS_FILE" -o "$OUT_PATH" "$TAR_PATH"
else
  # Passphrase interativa
  age -p -o "$OUT_PATH" "$TAR_PATH"
fi

# -----------------------------------------------------------------------------
# Final report
# -----------------------------------------------------------------------------
OUT_BYTES=$(wc -c < "$OUT_PATH")
OUT_SHA="$(sha256sum "$OUT_PATH" | awk '{print $1}')"

cat <<EOF >&2

[snapshot] OK

  Bundle : $OUT_PATH
  Size   : $(numfmt --to=iec --suffix=B $OUT_BYTES 2>/dev/null || echo "$OUT_BYTES bytes")
  SHA-256: $OUT_SHA
  Cipher : $CIPHER_MODE

  Audit chain tip (no momento do snapshot):
    ${AUDIT_TIP}

  Para validar sem aplicar:
    scripts/backup/verify-snapshot.sh "$OUT_PATH"

  Para restaurar (DESTRUTIVO):
    scripts/backup/restore-snapshot.sh "$OUT_PATH"

EOF
