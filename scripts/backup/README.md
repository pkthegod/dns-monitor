# dns-monitor — Snapshot/Restore (Fase 1)

Bundle cifrado, auto-contido e replicável da stack inteira.
Captura DB + .env + compose + nats-server.conf + dados NATS num único
arquivo `.tar.age`. Restaurado em qualquer máquina nova com Docker em ~5min.

## Componentes

| Script | Faz |
|---|---|
| `snapshot.sh` | Cria bundle cifrado em `$BACKUP_DIR` |
| `verify-snapshot.sh` | Decifra + valida hashes (sem aplicar) |
| `restore-snapshot.sh` | DESTRUTIVO: derruba stack, restaura DB e .env |

## Requisitos

```bash
# Debian/Ubuntu
sudo apt install age jq curl
# macOS
brew install age jq

# Docker já assumido
```

`age` é o que cifra. Sem ele, nada roda.

## Configuração de cifra

**Recomendado**: multi-recipient. Cada operador gera seu par e a chave pública
vai num arquivo compartilhado. Bundle é cifrado pra todos os recipients
listados — qualquer um deles consegue decifrar com a sua privada.

```bash
# Cada operador gera 1 vez:
age-keygen -o ~/.config/dns-monitor-backup/key.txt
# Saída: "Public key: age1abc..." — guarde isso

# Operador admin junta as pubkeys num arquivo:
mkdir -p /etc/dns-monitor-backup
cat > /etc/dns-monitor-backup/recipients.txt <<EOF
# Paulo (laptop)
age1abc...
# Cofre offline
age1def...
EOF
chmod 644 /etc/dns-monitor-backup/recipients.txt

# Snapshot usando multi-recipient:
export BACKUP_AGE_RECIPIENTS_FILE=/etc/dns-monitor-backup/recipients.txt
./scripts/backup/snapshot.sh
```

**Fallback** (passphrase única): se `BACKUP_AGE_RECIPIENTS_FILE` não estiver
setado, `snapshot.sh` pede passphrase interativa. Bom pra teste/dev,
**ruim pra produção** (single point of loss).

## Uso típico

### Criar snapshot

```bash
# Defaults: bundle vai pra <project>/.backups/
./scripts/backup/snapshot.sh

# Custom:
BACKUP_DIR=/mnt/backups ./scripts/backup/snapshot.sh

# Dry-run (so reporta, nao escreve nada):
./scripts/backup/snapshot.sh --dry-run
```

Saída: `dns-monitor-snapshot-20260430T120000Z-abc123def456.tar.age`.

### Validar bundle (sem restaurar)

```bash
./scripts/backup/verify-snapshot.sh /path/to/bundle.tar.age

# Com chave:
AGE_IDENTITY=~/.config/dns-monitor-backup/key.txt \
  ./scripts/backup/verify-snapshot.sh /path/to/bundle.tar.age
```

Esperado: `OK: Bundle valido. Pronto pra restore.`

### Restore (DESTRUTIVO)

```bash
# Modo interativo (pede pra digitar nome do banco pra confirmar):
./scripts/backup/restore-snapshot.sh /path/to/bundle.tar.age

# Modo CI/automatizado:
./scripts/backup/restore-snapshot.sh /path/to/bundle.tar.age \
  --force --non-interactive

# Restaurar em outra pasta (replica em maquina nova):
./scripts/backup/restore-snapshot.sh /path/to/bundle.tar.age \
  --target-dir /opt/dns-monitor-replica
```

O script:
1. Decifra + verifica hashes
2. Pede confirmação (ou exige `--force --non-interactive`)
3. Faz backup defensivo do `.env` atual (`.env.before-restore-<timestamp>`)
4. `docker compose down` + sobe DB+NATS
5. `DROP DATABASE` + `CREATE DATABASE` + `pg_restore`
6. Sobe backend + health check
7. Valida que o `audit_chain_tip_hash` atual ≥ ao do snapshot

## Conteúdo do bundle

```
dns-monitor-snapshot-<timestamp>-<git>.tar.age
└── (cifrado age)
    └── tar
        ├── metadata.json          ← timestamp, git_commit, pg_version,
        │                            schema_version, audit_chain_tip_hash,
        │                            row_counts, docker_images_pinned
        ├── MANIFEST.sha256        ← sha256 de tudo
        ├── db/
        │   ├── globals.sql        ← roles (pg_dumpall --globals-only)
        │   └── dns_monitor.dump   ← pg_dump custom format
        ├── secrets/
        │   └── backend.env        ← .env do backend
        ├── stack/
        │   ├── docker-compose.yaml
        │   ├── timescaledb.yaml
        │   ├── schemas.sql        ← DDL de referência
        │   ├── Dockerfile
        │   ├── nats-server.conf   ← config NATS isolation P4
        │   └── agent/
        │       └── dns_agent.py   ← código atual do agente
        └── nats/
            └── jetstream.tar      ← /data do container NATS
```

## Cron (sugestão pra dev)

```cron
# /etc/cron.d/dns-monitor-backup
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
BACKUP_DIR=/var/backups/dns-monitor
BACKUP_AGE_RECIPIENTS_FILE=/etc/dns-monitor-backup/recipients.txt

0 3 * * * paulo /opt/dns-monitor/scripts/backup/snapshot.sh >> /var/log/dns-monitor-backup.log 2>&1

# Limpa bundles > 7 dias (mantem semanais com nome 'weekly-' se quiser)
0 4 * * * paulo find /var/backups/dns-monitor -name 'dns-monitor-snapshot-*.tar.age' -mtime +7 -delete
```

## Garantias e limitações da Fase 1

✅ **Consistente**: `pg_dump` usa snapshot transacional — todas as tabelas
no mesmo MVCC point. `audit_log` hash chain valida pós-restore.

✅ **Replicável**: Bundle + chave age + Docker → stack idêntica em outra
máquina, sem dependência de Docker Hub se as imagens já estão cacheadas
localmente. Caso contrário, baixa as tags pinadas (Fase 2 vai embutir).

✅ **Detectável**: hashes SHA-256 + cifra autenticada (ChaCha20-Poly1305 do
age) — qualquer flip de bit é rejeitado.

❌ **RPO 24h** (com cron diário). Pra RPO menor → Fase 2 (WAL archiving).

❌ **Não testa restore automaticamente**. Pra ter certeza que funciona,
rode `restore-snapshot.sh` em VM/staging periodicamente. Backup que nunca
foi restaurado é teatro.

❌ **Imagens Docker pinadas, não embutidas**. Se Docker Hub sair do ar
ou tag for removida, restore quebra. Fase 2 vai opcionalmente embutir
(`docker save`).

## Roadmap

- **Fase 1 (este arquivo)**: snapshot diário local + restore manual
- **Fase 2**: WAL archiving contínuo + auto-test de restore via cron + alerting
- **Fase 3**: push pra B2/S3/Wasabi com client-side encryption
- **Fase 4**: streaming replication + failover (Patroni)
