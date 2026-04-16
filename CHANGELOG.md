# Changelog — DNS Monitor

---

## [v0.3.0] — 2026-04-16 — Painel Admin, Quick Probe & Auto-update

### Novidades

#### Painel Admin (`/admin`)

- Tela de login com autenticação por usuário/senha (`ADMIN_USER` / `ADMIN_PASSWORD`)
- CRUD completo de agentes: adicionar, editar, remover, ativar/desativar
- Visualização de status ao vivo (online/offline/stale) com auto-refresh
- Emissão de comandos remotos (restart, stop, enable, disable, purge)
- Histórico de comandos por agente
- Auto-purge de agentes inativos configurável
- Logo e favicon SVG próprios
- Proteção de todas as rotas admin via sessão/cookie

#### DNS Quick Probe (feature 007)

- Teste DNS leve a cada 60s (configurável via `quick_probe_interval`)
- Resultado armazenado em memória, enviado no próximo heartbeat como `dns_checks[]`
- Domínio configurável via `quick_probe_domain` (default: primeiro domínio do `agent.conf`)
- Timeout independente via `quick_probe_timeout` (default: 2s)
- Habilitar/desabilitar via `quick_probe_enabled` (default: true)
- Intervalo mínimo enforced: 10s
- Backend processa `dns_checks` tanto em `type=check` quanto em `type=heartbeat`

#### Auto-update do agente

- Endpoint `GET /agent/version` retorna versão atual do agente no servidor
- Endpoint `GET /agent/download` serve o `dns_agent.py` mais recente
- Agente verifica versão remota e faz self-update com validação de sintaxe (`py_compile`)
- Rollback automático se o novo arquivo não compilar

#### Geolocalização e diagnóstico

- Script de diagnóstico para troubleshooting remoto
- Script de geolocalização de agentes
- `AGENT_VERSION` bumped para `1.1.0`

#### Continuous aggregates (TimescaleDB)

- `metrics_cpu_1h`, `metrics_ram_1h`, `dns_checks_1h` — views materializadas por hora
- Políticas de refresh automático a cada 1h
- Reduz volume de dados ~90% para queries históricas no Grafana

### Correções

| # | Problema | Correção |
|---|---|---|
| 17 | `ADMIN_USER`/`ADMIN_PASSWORD` não passavam pro container | Adicionados ao `docker-compose.yaml` |

### Testes

- `test_agent.py`: 117 testes (+37 cobrindo Quick Probe, schedule, auto-update)
- `test_backend.py`: 141 testes (+71 cobrindo admin, login, heartbeat+dns_checks)
- Total: **258 testes** (anterior: 242)
- Testes `TestCollectLoad` marcados `skipif` no Windows (`os.getloadavg` é Unix-only)
- Assert de `agent_version` usa `da.AGENT_VERSION` em vez de string hardcoded

---

## [v0.2.0] — 2026-03-20 — Controle Remoto de Agentes

### Novidades

#### Controle remoto

- Novo endpoint `POST /commands` — emite comandos para agentes via banco ou API
- Novo endpoint `GET /commands/{hostname}` — agente consulta comandos pendentes
- Novo endpoint `POST /commands/{id}/result` — agente reporta resultado da execução
- Novo endpoint `GET /commands/{hostname}/history` — histórico de comandos por host
- Tabela `agent_commands` no banco com status `pending` → `done` / `failed` / `expired`
- Comandos suportados: `stop`, `disable`, `enable`, `purge`
- `purge` exige `confirm_token` — proteção contra execução acidental
- Polling a cada 12h configurável + consulta imediata na inicialização do agente
- Comandos emitidos durante downtime do agente são capturados no próximo poll

#### Fingerprint de hardware

- Geração de SHA256 baseado em hostname + MAC address + `/etc/machine-id`
- Enviado em todo payload (heartbeat e check)
- Registrado no banco em `agents.fingerprint` com timestamps de primeiro e último registro
- Backend gera `WARNING` nos logs quando fingerprint muda — detecta cópias não autorizadas
- Redefinição via SQL após troca de hardware legítima

#### Instalador (`install_agent.sh`)

- Instala automaticamente: `sudo`, `python3`, `python3-venv`, `python3-pip`, `python3-pytest`
- Verifica e instala apenas pacotes ausentes — não reinstala o que já tem
- Detecta arquivo `env` na pasta do script e copia automaticamente — sem edição manual em reinstalações
- Cria `/etc/sudoers.d/dns-agent` com permissões exatas para controle do DNS
- Numeração de etapas e mensagens de saída revisadas

### Correções

| # | Problema | Correção |
|---|---|---|
| 11 | `NoNewPrivileges=true` impedia `sudo` | Removido do `dns_agent.service` |
| 12 | `ProtectSystem=strict` bloqueava `/run/sudo` | Adicionado `/run/sudo` ao `ReadWritePaths` |
| 13 | `use_pty` forçava terminal mesmo com `NOPASSWD` | `Defaults:dns-agent !use_pty` no sudoers |
| 14 | `enable bind9` sem `--now` não batia com o sudoers | Adicionado `--now` nas entradas de enable/disable |
| 15 | `bind9` é alias no Debian — systemctl recusava | `SERVICE_ALIASES = {"bind9": "named"}` no agente |
| 16 | `--workers 2` duplicava o APScheduler no Telegram | Alterado para `--workers 1` no Dockerfile |

### Documentação

- `README.md` atualizado com arquitetura bididicional, seções de controle remoto e fingerprint
- `DB_ADMIN.sql` — nova seção 10: comandos remotos e fingerprint
- `DNS_Monitor_Erros.docx` — erros 11 a 16 documentados com causa raiz e correção

### Testes

- `test_agent.py`: 80 testes (+21 cobrindo fingerprint, `_execute_command`, `poll_commands`)
- `test_backend.py`: 70 testes (+21 cobrindo endpoints de comandos e fingerprint)
- Total: **242 testes** (anterior: 200)

---

## [v0.1.0] — 2026-03-19 — Versão Base

### Agente (`dns_agent.py`)

- Coleta de métricas: CPU, RAM, disco, I/O, load average via `psutil`
- Testes de resolução DNS com retry automático — Unbound e Bind9/Named (auto-detectado)
- Heartbeat a cada 5 minutos
- Checks completos 4×/dia: 00:00, 06:00, 12:00, 18:00
- Configuração via `agent.conf` com interpolação de variáveis `%(VAR)s`
- Segredos isolados em `/etc/dns-agent/env` via `EnvironmentFile` no systemd
- Sem segredos no repositório

### Backend

- API FastAPI com autenticação por token Bearer
- TimescaleDB com 7 hypertables, compressão automática após 7 dias e retenção configurável
- Alertas com deduplicação — CPU, RAM, disco, DNS, offline
- Relatórios consolidados via Telegram nos horários configurados
- Endpoints: `POST /metrics`, `GET /agents`, `GET /alerts`, `GET /health`
- `_SafeJSONResponse` com encoder customizado para `datetime` e `Decimal`
- `_parse_ts()` — conversão de ISO 8601 string para `datetime` antes do asyncpg
- `_split_sql()` — executa `schemas.sql` statement a statement

### Grafana

- Dashboard de visão geral: agentes online/offline, alertas abertos, taxa de sucesso DNS, latência
- Dashboard de detalhe por host: CPU, RAM, disco, I/O, load average, latência DNS, resultados DNS
- Provisioning automático via YAML
- Datasource TimescaleDB com `uid: timescaledb-dns`

### Infraestrutura

- Deploy via Docker Compose — TimescaleDB (PostgreSQL 15) + FastAPI + Grafana 12
- Instalador `install_agent.sh` com criação de usuário de sistema, diretórios e serviço systemd
- `.gitignore` separando segredos de configuração pública

### Documentação

- `README.md` com guia completo de deploy
- `IMPLEMENTACAO.md` com guia detalhado passo a passo
- `DB_ADMIN.sql` com referência de administração do banco
- `DNS_Monitor_Erros.docx` com 10 erros de implementação documentados

### Testes

- `test_backend.py`: 49 testes — autenticação, payload, thresholds, deduplicação, schema, `/health`
- `test_agent.py`: 59 testes — load_config, DNS, métricas, payload, send, alertas
- `test_grafana.py`: 92 testes — estrutura, datasource, SQL, thresholds, provisioning
- Total: **200 testes**
