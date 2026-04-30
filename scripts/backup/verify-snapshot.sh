#!/usr/bin/env bash
# =============================================================================
# verify-snapshot.sh — Decifra e valida um bundle SEM aplicar nada.
#
# Verifica:
#   - cifra age (passphrase ou identity file)
#   - integridade do tar
#   - todos os SHA-256 do MANIFEST batem
#   - metadata.json bem formado
#   - schema_version conhecido
#
# Uso:
#   ./verify-snapshot.sh <bundle.tar.age>
#   AGE_IDENTITY=/path/to/key.txt ./verify-snapshot.sh <bundle>
# =============================================================================
set -euo pipefail

BUNDLE="${1:-}"
[[ -n "$BUNDLE" ]] || { echo "uso: $0 <bundle.tar.age>" >&2; exit 64; }
[[ -f "$BUNDLE" ]] || { echo "ERRO: bundle nao encontrado: $BUNDLE" >&2; exit 66; }

command -v age        >/dev/null || { echo "ERRO: age nao encontrado" >&2; exit 1; }
command -v jq         >/dev/null || { echo "ERRO: jq nao encontrado"  >&2; exit 1; }
command -v sha256sum  >/dev/null || { echo "ERRO: sha256sum nao encontrado" >&2; exit 1; }
command -v tar        >/dev/null || { echo "ERRO: tar nao encontrado" >&2; exit 1; }

WORK_DIR="$(mktemp -d -t dnsmonvf.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

log() { printf "[verify] %s\n" "$*" >&2; }
die() { printf "[verify] FALHA: %s\n" "$*" >&2; exit 1; }
ok()  { printf "[verify] OK: %s\n" "$*" >&2; }

log "Bundle: $BUNDLE ($(wc -c < "$BUNDLE") bytes)"
log "SHA-256: $(sha256sum "$BUNDLE" | awk '{print $1}')"

# -----------------------------------------------------------------------------
# 1) Decifra
# -----------------------------------------------------------------------------
log "Decifrando..."
if [[ -n "${AGE_IDENTITY:-}" ]]; then
  [[ -f "$AGE_IDENTITY" ]] || die "AGE_IDENTITY '$AGE_IDENTITY' nao existe"
  age -d -i "$AGE_IDENTITY" -o "$WORK_DIR/bundle.tar" "$BUNDLE" \
    || die "age decifra falhou (chave errada?)"
else
  age -d -o "$WORK_DIR/bundle.tar" "$BUNDLE" \
    || die "age decifra falhou (passphrase errada? configure AGE_IDENTITY pra chaves)"
fi
ok "decifrado"

# -----------------------------------------------------------------------------
# 2) Extrai
# -----------------------------------------------------------------------------
mkdir -p "$WORK_DIR/extract"
tar -xf "$WORK_DIR/bundle.tar" -C "$WORK_DIR/extract" || die "tar invalido"
ok "tar extraido"

# -----------------------------------------------------------------------------
# 3) metadata.json
# -----------------------------------------------------------------------------
META="$WORK_DIR/extract/metadata.json"
[[ -f "$META" ]] || die "metadata.json ausente"
jq empty "$META" || die "metadata.json mal-formado"

SCHEMA="$(jq -r '.schema_version' "$META")"
TS="$(jq -r '.timestamp_utc' "$META")"
GIT="$(jq -r '.git_describe' "$META")"
PG="$(jq -r '.pg_version' "$META")"
AUDIT_TIP="$(jq -r '.audit_chain_tip_hash' "$META")"
SIZE="$(jq -r '.db_size_bytes' "$META")"

log "metadata:"
log "  schema_version: $SCHEMA"
log "  timestamp_utc : $TS"
log "  git           : $GIT"
log "  pg_version    : $PG"
log "  db_size_bytes : $SIZE"
if [[ ${#AUDIT_TIP} -gt 24 ]]; then
  log "  audit_tip     : ${AUDIT_TIP:0:24}..."
else
  log "  audit_tip     : ${AUDIT_TIP}"
fi

case "$SCHEMA" in
  v1.5-c2-audit-chain) ok "schema_version reconhecido" ;;
  *) log "AVISO: schema_version='$SCHEMA' desconhecido pro restore atual" ;;
esac

# -----------------------------------------------------------------------------
# 4) MANIFEST.sha256 — verifica todo arquivo
# -----------------------------------------------------------------------------
MANIFEST="$WORK_DIR/extract/MANIFEST.sha256"
[[ -f "$MANIFEST" ]] || die "MANIFEST.sha256 ausente"

( cd "$WORK_DIR/extract" && sha256sum -c MANIFEST.sha256 --quiet ) \
  || die "MANIFEST.sha256: hash mismatch (bundle adulterado ou corrompido)"

FILE_COUNT=$(wc -l < "$MANIFEST")
ok "MANIFEST.sha256: $FILE_COUNT arquivos validados"

# -----------------------------------------------------------------------------
# 5) Componentes obrigatorios presentes
# -----------------------------------------------------------------------------
for f in db/dns_monitor.dump db/globals.sql secrets/backend.env stack/docker-compose.yaml stack/schemas.sql; do
  [[ -f "$WORK_DIR/extract/$f" ]] || die "componente obrigatorio ausente: $f"
done
ok "componentes obrigatorios presentes"

# -----------------------------------------------------------------------------
# 6) pg_dump header sanity check
#
# Tenta `pg_restore -l` em 3 camadas:
#   1. Binario local (mais rapido se estiver instalado)
#   2. Container Postgres rodando (DB_CONTAINER, default infra_vision_db) —
#      garante que a versao do pg_restore casa com o servidor
#   3. Skip com warning se nem um nem outro
# -----------------------------------------------------------------------------
DUMP="$WORK_DIR/extract/db/dns_monitor.dump"
DB_CONTAINER="${DB_CONTAINER:-infra_vision_db}"

# pg_restore_l_listing: imprime o listing em stdout e retorna:
#   0 = ok, 1 = falhou (dump invalido), 127 = ferramenta indisponivel
#
# Cada comando que pode falhar tem `|| rc=$?` pra capturar exit sem o
# `set -e` abortar a funcao. `local rc=$?` direto NAO funciona porque
# `local` retorna 0 e mascara o exit anterior.
pg_restore_l_listing() {
  local rc=0
  if command -v pg_restore >/dev/null 2>&1; then
    pg_restore -l "$DUMP" 2>"$WORK_DIR/pg_restore.err" || rc=$?
    return $rc
  fi
  if command -v docker >/dev/null 2>&1 \
     && docker inspect "$DB_CONTAINER" >/dev/null 2>&1 \
     && [[ "$(docker inspect -f '{{.State.Running}}' "$DB_CONTAINER" 2>/dev/null)" == "true" ]]; then
    log "  pg_restore: usando container $DB_CONTAINER (binario local indisponivel)"
    docker cp "$DUMP" "$DB_CONTAINER:/tmp/_verify.dump" 2>"$WORK_DIR/pg_restore.err" || return 1
    docker exec "$DB_CONTAINER" pg_restore -l /tmp/_verify.dump 2>"$WORK_DIR/pg_restore.err" || rc=$?
    docker exec "$DB_CONTAINER" rm -f /tmp/_verify.dump >/dev/null 2>&1 || true
    return $rc
  fi
  return 127
}

# `set -e` aborta o subshell se a funcao falhar — `|| RC=$?` captura sem abortar.
# Sem `|| true` antes pra preservar o RC real.
RC=0
LISTING="$(pg_restore_l_listing)" || RC=$?
if [[ $RC -eq 0 ]]; then
  ENTRIES=$(echo "$LISTING" | grep -cE '^\s*[0-9]+;' || true)
  ok "pg_restore -l ok ($ENTRIES entries)"
elif [[ $RC -eq 127 ]]; then
  log "AVISO: pg_restore indisponivel (sem binario local nem container '$DB_CONTAINER' rodando) — header nao validado"
else
  log "AVISO: pg_restore -l falhou (exit=$RC):"
  sed 's/^/  /' "$WORK_DIR/pg_restore.err" >&2
fi

echo
ok "Bundle valido. Pronto pra restore."
