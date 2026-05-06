# Infra-Vision

Monitoramento distribuído de servidores DNS (Bind9/Unbound) para ISPs e operadores.
Agentes em Linux coletam métricas, latência DNS e estatísticas de query
(RCODEs/QPS/cache hits) e empurram pra um backend central, que serve um painel
admin com RBAC e portal cliente self-service (com mapas 2D/3D do trace
DNS, gauges de SSL/conectividade, relatórios PDF). Comandos remotos
(start/stop/diagnóstico/auto-update) chegam ao agente em tempo real
via NATS JetStream — com HTTP polling como fallback.

---

## Arquitetura

```
┌────────────────────────────┐    NATS push (dns.commands.<host>)      ┌───────────────────────┐
│   Maquina monitorada       │ ◄─────────────────────────────────────  │   Servidor central    │
│                            │    HTTP poll fallback (60s adaptativo)  │                       │
│   dns_agent.py             │                                         │   FastAPI :8000       │
│   ├─ heartbeat 5min        │ ─── HTTP/JSON (push: metricas) ───────► │   ├─ /admin   (RBAC)  │
│   ├─ check completo 12x/d  │                                         │   ├─ /client  (portal)│
│   ├─ quick probe 60s       │                                         │   ├─ /dashboard       │
│   ├─ dns stats 10min       │                                         │   └─ /speedtest       │
│   ├─ fingerprint hardware  │ ─── NATS publish (dns.stats.<host>) ──► │                       │
│   └─ self-update via /opt  │ ─── NATS publish (...ack)         ────► │   TimescaleDB / PG15  │
└────────────────────────────┘                                         │   NATS JetStream      │
       (50–100 hosts)                                                  │   Telegram + webhooks │
                                                                       └───────────────────────┘
```

**Stack**

| Componente   | Tecnologia                                              |
|--------------|---------------------------------------------------------|
| Agente       | Python 3.10+, psutil, dnspython, schedule, nats-py      |
| Backend      | FastAPI, asyncpg, APScheduler, nats-py                  |
| Banco        | TimescaleDB 2.17 / PostgreSQL 15 — 9 hypertables        |
| Mensageria   | NATS 2.10 + JetStream (durable consumers)               |
| Frontend     | HTML + CSS + vanilla JS (sem build step) + Leaflet/Globe.gl |
| Dashboards   | Embutidos no painel admin (`/dashboard`, `/speedtest`)   |
| Notificações | Telegram + webhooks (Slack / Teams / PagerDuty / JSON)  |
| Deploy       | Docker Compose (1 worker — scheduler único)             |

---

## Estrutura do repositório

```
infra-vision/
├── README.md
├── CHANGELOG.md                    histórico de releases
├── CONTRIBUTING.md                 fluxo de contribuição
├── DBAAction.sql / DBAUpdate.sql   referência operacional do banco
├── DBAreference.sql
├── test_payload.py                 utilitario de diagnóstico
│
├── agent/
│   ├── dns_agent.py                agente principal (auto-contido)
│   ├── agent.toml                  configuração TOML (sem segredos)
│   ├── env.example                 template de segredos
│   ├── dns_agent.service           unit systemd
│   ├── install_agent.sh            instalador (cria sudoers + dirs)
│   ├── setup_dns_stats.sh          habilita extended-statistics no Bind9/Unbound
│   ├── requirements.txt
│   └── test_agent.py               153 testes do agente
│
├── backend/
│   ├── main.py                     bootstrap FastAPI + SecurityHeaders/CSRF/RateLimit
│   ├── routes_admin.py             rotas /admin (RBAC admin/viewer)
│   ├── routes_agent.py             rotas /api/v1/* (ingest, commands)
│   ├── routes_client.py            rotas /client (portal cliente)
│   ├── ws.py                       WebSocket /ws/live (broadcast real-time)
│   ├── middlewares.py              CSP, CSRF, rate-limit, security headers
│   ├── auth.py                     cookies admin/client + role-based RBAC
│   ├── db.py                       camada asyncpg + TimescaleDB
│   ├── schemas.sql                 DDL completo + hash-chain do audit_log
│   ├── nats_client.py              conexão JetStream
│   ├── nats_handlers.py            handlers (command_ack, dns_stats)
│   ├── scheduler_jobs.py           jobs: alertas offline, daily report, retention
│   ├── security.py                 detecção de scans/brute-force + honeypots
│   ├── webhooks.py                 Slack/Teams/PagerDuty/genérico
│   ├── email_report.py             relatório mensal por email
│   ├── telegram_bot.py             alertas Telegram (anti-spam)
│   ├── static/                     admin.html + client.html + dashboard + speedtest
│   ├── docker-compose.yaml         backend + db + nats
│   ├── Dockerfile
│   ├── requirements.txt
│   └── test_backend.py             283 testes
│
├── docs/security/                  política de disclosure + relatórios
├── docs/onda1-p5-tls-nats.md       plano de migração TLS NATS via WS+CF
├── scripts/
│   ├── backup/snapshot.sh          snapshot replicável cifrado (AES-256)
│   ├── backup/restore-snapshot.sh
│   ├── backup/verify-snapshot.sh   validação automatizada
│   ├── smoke-test-security.sh      testa isolamento multi-tenant
│   └── update_all_agents.sh
└── specs/                          specs por feature (007/010/012/013) + roadmap
```

---

## Pré-requisitos

**Servidor central**
- Linux (Debian/Ubuntu recomendado)
- Docker + Compose plugin
- Portas: 8000 (API; via nginx+CF em prod), 4222 (NATS — em transição pra `wss://` via Onda 1 P5)

**Cada agente**
- Linux com Bind9, Unbound ou Named
- Python 3.10+
- Acesso HTTP à porta 8000 do servidor + (recomendado) NATS:4222 pra comandos em tempo real

---

## Deploy do backend

```bash
git clone https://github.com/pkthegod/dns-monitor.git
cd dns-monitor/backend

cp .env.example .env
# Edite .env — senhas SEM @ # / ? %  (postgres parser quebra)
# Gere secrets fortes com:
#   python3 -c "import secrets; print(secrets.token_hex(32))"
# Os 4 secrets críticos: AGENT_TOKEN, ADMIN_SESSION_SECRET,
# CLIENT_SESSION_SECRET, AUDIT_HMAC_KEY

docker compose build --no-cache backend
docker compose up -d

curl http://localhost:8000/health
# → {"status":"ok","db":"connected","nats":"connected"}
```

Os dashboards ficam embutidos no painel admin (`/dashboard` para
métricas DNS, `/speedtest` para conectividade SSL/portas).

---

## Instalação do agente

```bash
scp agent/* usuario@maquina:/tmp/dns-agent/
ssh usuario@maquina

sudo mkdir -p /etc/dns-agent
sudo nano /etc/dns-agent/env
```

```dotenv
AGENT_HOSTNAME=NS1_NOME_CLIENTE
AGENT_TOKEN=mesmo_AGENT_TOKEN_do_backend
AGENT_BACKEND=http://IP_SERVIDOR:8000
```

```bash
sudo chmod 640 /etc/dns-agent/env
sudo bash /tmp/dns-agent/install_agent.sh
```

O instalador cria:
- `/opt/dns-agent/` — venv + código (writable pelo user `dns-agent` pra self-update)
- `/var/lib/dns-agent/` — state (last query stats pra delta)
- `/var/log/dns-agent/`
- `/etc/dns-agent/agent.toml` — config TOML
- `/etc/sudoers.d/dns-agent` — permissões mínimas (`systemctl` específicos)
- Unit systemd habilitado

Pra habilitar NATS (recomendado — comandos em tempo real):

```toml
# /etc/dns-agent/agent.toml
[nats]
enabled = true
url = "nats://IP_PUBLICO_DO_BACKEND:4222"
```

Pra habilitar extended-statistics no Bind9/Unbound (libera RCODEs/QPS):

```bash
sudo /opt/dns-agent/setup_dns_stats.sh
```

---

## Funcionamento do agente

| Evento                | Frequência                     | O que faz                                           |
|-----------------------|--------------------------------|-----------------------------------------------------|
| Heartbeat             | 5 min                          | hostname + timestamp + versão + fingerprint         |
| Quick Probe DNS       | 60s                            | resolve 1 domínio, fail-fast (latência online)      |
| Check completo        | 12×/dia (00:00…22:00 par)      | métricas + DNS multi-domínio + service status       |
| DNS stats             | 10 min                         | RCODEs/QPS/cache hits via rndc/unbound-control      |
| Poll de comandos HTTP | 60s (idle 600s após 2 vazios)  | fallback se NATS off                                |
| NATS subscribe        | real-time                      | `dns.commands.<hostname>` — push instantâneo        |
| NATS healthcheck      | 60s                            | loga estado da conexão (anti-disconnect silencioso) |
| Auto-update           | sob demanda (`update_agent`)   | baixa nova versão de `/api/v1/agent/latest`         |

**Métricas coletadas:** CPU (% + load), RAM (% + swap), disco (por partição,
ok/warning/critical), I/O (bytes + ops desde boot), DNS (latência + IPs +
RCODEs por domínio), serviço DNS (active/inactive + versão).

---

## Comandos remotos

| Comando        | Efeito                                              | Reversível       |
|----------------|-----------------------------------------------------|------------------|
| `restart`      | Reinicia o serviço DNS                              | —                |
| `stop`         | Para o serviço (mantém habilitado no boot)          | sim — `enable`   |
| `disable`      | Para + desabilita no boot                           | sim — `enable`   |
| `enable`       | Habilita + inicia                                   | —                |
| `purge`        | Remove o pacote do sistema                          | **NÃO**          |
| `decommission` | Para serviço + remove agente do banco               | **NÃO**          |
| `run_script`   | Executa diagnóstico (`dns_validate`, `dig_test`...) | —                |
| `update_agent` | Self-update do agente via `/api/v1/agent/latest`    | reversível por replay |
| `dnstop`       | Stream de top-talkers                               | —                |

**Segurança operacional:**
- `purge` exige fluxo two-step com `confirm_token` HMAC válido por 5 min
- `decommission` registra antes de remover (audit chain imutável)
- Idempotência anti-replay: comandos já executados via HTTP polling são
  rejeitados se reaparecerem via NATS pós-reconnect

Emissão via API (admin):

```bash
curl -X POST http://localhost:8000/api/v1/commands \
  -H "Cookie: admin_session=…" \
  -H "Content-Type: application/json" \
  -d '{"hostname":"NS1_X","command":"restart"}'
```

Ou pelo painel: `/admin` → menu de ações do agente.

---

## Portais e dashboards

| URL              | Função                                                                |
|------------------|-----------------------------------------------------------------------|
| `/admin/login`   | Login admin (RBAC: `admin` write, `viewer` read-only)                 |
| `/admin`         | Inventário de agentes, comandos, clientes, admin users                |
| `/dashboard`     | DNS metrics — agregado de todos os hosts (admin)                      |
| `/speedtest`     | Resultados de speedtest (admin)                                       |
| `/client/login`  | Login cliente — auth por hostnames associados                         |
| `/client`        | Portal self-service: hero status, KPIs, "Testar meu DNS", relatórios  |
| `/admin/help`    | Documentação operacional                                              |
| `/client/help`   | FAQ pro cliente final                                                 |

Frontend é vanilla JS modularizado (extração de `admin.html` em
`admin-{agents,clients,commands}.js`) — sem build step. WebSocket
`/ws/live` empurra updates pro painel admin.

---

## Banco de dados

| Tabela / view          | Tipo       | Chunk | Retenção | Observação                                |
|------------------------|------------|-------|----------|-------------------------------------------|
| `agent_heartbeats`     | hypertable | 1h    | 30 d     |                                            |
| `metrics_cpu`          | hypertable | 6h    | 1 ano    |                                            |
| `metrics_ram`          | hypertable | 6h    | 1 ano    |                                            |
| `metrics_disk`         | hypertable | 6h    | 1 ano    |                                            |
| `metrics_io`           | hypertable | 6h    | 1 ano    |                                            |
| `dns_checks`           | hypertable | 1 d   | 1 ano    |                                            |
| `dns_service_status`   | hypertable | 1 d   | 1 ano    |                                            |
| `speedtest_scans`      | hypertable | 1 d   | 1 ano    |                                            |
| `dns_query_stats`      | hypertable | 1 d   | 1 ano    | RCODEs/QPS/cache (extended-statistics)    |
| `agents`               | tabela     | —     | —        | inclui fingerprint + last_seen            |
| `agent_commands`       | tabela     | —     | —        | + índice único de alertas abertos         |
| `alerts_log`           | tabela     | —     | —        | dedupe via `idx_alerts_open_unique`       |
| `audit_log`            | tabela     | —     | —        | hash-chain imutável (prev_hash + row_hash) |
| `admin_users`          | tabela     | —     | —        | RBAC admin/viewer + senha bcrypt          |
| `client_users`         | tabela     | —     | —        | hostnames[] associados                    |
| `daily_reports`        | tabela     | —     | —        | PDF cacheado por cliente/dia              |
| `speedtest_domains`    | tabela     | —     | —        | resultados por domínio                    |

Compressão automática após 7 dias (~90% de economia em disco).

---

## Segurança

Foco do release v1.5 — auditado em `docs/security/`.

| Camada                    | Controle                                                                                |
|---------------------------|-----------------------------------------------------------------------------------------|
| Network                   | Rate-limit global 200 rpm/IP em `/api/*` + retry-after no 429                           |
| AuthN admin               | Cookies HMAC-SHA256 + rotação sem downtime (`*_SESSION_SECRET_PREV`)                    |
| AuthZ admin               | RBAC `admin` (mutativo) vs `viewer` (read-only)                                          |
| AuthN cliente             | Cookies separados; portal só vê hostnames associados (multi-tenant isolation)            |
| AuthN agente              | Bearer `AGENT_TOKEN` em rotas de ingest                                                  |
| CSRF                      | Validação de Origin/Referer em POST/PATCH/DELETE com cookie                             |
| CSP                       | `script-src 'self' 'unsafe-inline'` em transição pra nonce-only (refactor B em curso)   |
| Headers                   | X-Frame-Options, X-Content-Type-Options, Referrer-Policy, frame-ancestors 'none'         |
| Race conditions           | `asyncio.Lock` em rate-limiters; `ON CONFLICT DO NOTHING` em alerts; xmax em upsert      |
| DoS                       | PDF rate-limit (1/10min) + timeout 10s + audit (Fase A4)                                 |
| Detecção                  | Honeypots (`/wp-admin`, `/.env`, `/.git`...) + auto-block 30 min                         |
| Audit                     | Hash-chain imutável (SHA-256 + `verify_audit_chain`)                                     |
| Backup                    | Snapshot AES-256 cifrado + verify automatizado (`pg_restore` no container)              |
| Disclosure                | `docs/security/disclosure.md` — 48h triage / 30d critical / 90d coordinated             |
| CI                        | CodeQL + Dependabot (`.github/`)                                                         |

Smoke test de isolamento multi-tenant: `bash scripts/smoke-test-security.sh`.

---

## Alertas

**Telegram** (anti-spam, dedupe por `(hostname, alert_type, severity)` enquanto
o alerta estiver aberto):

| Condição                  | Severidade   |
|---------------------------|--------------|
| CPU ≥ 80% / 95%           | warn / crit  |
| RAM ≥ 85% / 95%           | warn / crit  |
| Disco ≥ 80% / 90%         | warn / crit  |
| Latência DNS ≥ 200/1000ms | warn / crit  |
| SERVFAIL spike            | critical     |
| DNS silence               | critical     |
| NXDOMAIN absurdo          | critical     |
| Falha resolução / serviço | critical     |
| Agente offline > 10 min   | critical     |

**Webhooks** (auto-detecta formato pela URL): Slack attachments, Teams
MessageCard, PagerDuty Events v2, JSON genérico. Configurar no CRUD do
cliente — disparado automaticamente em alertas critical.

**Relatórios:** PDF mensal cacheado por cliente; daily report agendado às
23:59. Email mensal opcional (template Tokyo Night).

---

## Backup e restore

```bash
# Snapshot replicavel cifrado (AES-256-CBC)
sudo bash scripts/backup/snapshot.sh /caminho/para/output

# Verificacao automatizada — usa pg_restore do container quando local falta
sudo bash scripts/backup/verify-snapshot.sh /caminho/para/snapshot.tar.gz.enc

# Restore
sudo bash scripts/backup/restore-snapshot.sh /caminho/para/snapshot.tar.gz.enc
```

Cobre: schemas + dados + secrets do `.env` (cifrados separadamente). Retenção
manual — defina em cron conforme política.

---

## Testes

```bash
# Backend (283 testes — RBAC, CSP, race conditions, idempotência, NATS isolation)
cd backend && PYTHONPATH=. pytest test_backend.py -v

# Agente (157 testes — config, polling adaptativo, NATS replay, hardening auto-update)
cd agent && PYTHONPATH=. pytest test_agent.py -v
```

**Total: 440 testes** (283 + 157). Tudo passando antes de qualquer deploy
em produção. CI roda automaticamente via GitHub Actions (CodeQL).

---

## Operação

```bash
# Status geral
curl -s http://localhost:8000/health
docker compose ps

# Logs do backend
docker compose logs -f backend

# Banco
docker exec -it infra_vision_db psql -U dnsmonitor -d dns_monitor

# NATS — listar consumers ativos
docker compose exec nats nats consumer ls dns-commands

# Drenar fila JetStream de um host (depois de longo offline)
docker compose exec nats nats consumer rm dns-commands agent-NS1_HOST --force

# Rebuild do backend após mudança de código
docker compose build --no-cache backend
docker compose up -d --force-recreate backend

# Agente
sudo systemctl status dns-agent
sudo journalctl -u dns-agent -f
sudo systemctl restart dns-agent
```

---

## Branches

`main` — única branch ativa. Deploys diretos com testes passando. Histórico
detalhado de releases em `CHANGELOG.md`.

---

## Licença

MIT — ver `LICENSE`.
