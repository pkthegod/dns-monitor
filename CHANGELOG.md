# Changelog — DNS Monitor

---

## [v0.7.2] — 2026-04-17 — Extracao de modulos (main.py -44%)

### Refatoracao

#### main.py dividido em modulos
- `models.py` (80 linhas): todos os modelos Pydantic (AgentPayload, SystemModel, etc.)
- `auth.py` (154 linhas): autenticacao Bearer, cookies HMAC, rate limiting, password hashing
- `routes_client.py` (291 linhas): portal do cliente, CRUD clientes, dns-test, report, client data
- `main.py`: 1348 → 760 linhas (-44%)
- Re-exporta todos os simbolos para compatibilidade total com testes existentes
- Reload cascata: `importlib.reload(main)` recarrega auth/models/routes automaticamente

### Testes

- 165 passed, 2 skipped (zero regressao)

---

## [v0.7.1] — 2026-04-17 — Refactor: queries unificadas, deprecations, rate limiter

### Refatoracao

#### Queries duplicadas eliminadas
- `dashboard_data` e `client_data` tinham 5 queries SQL quase identicas (CPU, RAM, DNS latency, DNS history, alerts)
- Extraidas para `db.get_aggregated_metrics(period, hostnames=None)` — funcao unica com filtro opcional por hostnames
- `main.py`: -70 linhas de SQL duplicado
- Mesma funcao serve dashboard admin (sem filtro) e portal do cliente (com hostnames)

#### asyncio.get_event_loop() → get_running_loop()
- `main.py` endpoint `/tools/geolocate` usava `get_event_loop()` — deprecated no Python 3.12+, removido no 3.14
- Corrigido para `get_running_loop()` (seguro em contexto async)

#### Rate limiter dedicado para acoes com cooldown
- `client_dns_test` reutilizava `_record_failed_login` como rate limiter generico — poluia auditoria de login
- Novo rate limiter: `_check_cooldown(key, seconds)` + `_record_action(key)` — semantica clara, separado de login

### Testes

- 165 passed, 2 skipped (sem regressao)

---

## [v0.6.1] — 2026-04-17 — Grafana removido, zoom temporal, hardening A+

### Mudancas

#### Grafana removido
- Container grafana removido do docker-compose
- Volume grafana_data removido
- -1 servico, -1 porta (3000), -1 senha (GRAFANA_PASSWORD)
- Dashboard e portal proprios substituem completamente

#### Zoom temporal + drill-down por host
- Seletor de periodo: 1h / 24h / 7d nos dashboards e portal
- Filtro por hostname no dashboard admin
- Bucket automatico: 5min (1h), 30min (6h), 1h (24h), 6h (7d)
- Alertas filtrados pelo mesmo periodo e host
- Portal do cliente com seletor de periodo

#### Security hardening final
- Cookies com nonce aleatorio (previne session fixation)
- TTL reduzido: admin 4h, cliente 12h
- Timing attack mitigado: dummy bcrypt para users inexistentes
- Audit log persistente: tabela audit_log no DB
- Request logging: POST/PATCH/DELETE em /api/ logados com IP
- Mensagens de erro sanitizadas (sem detalhes internos)
- HSTS + CSP headers adicionados

### Testes

- 303 testes passando (165 backend + 138 agent)

---

## [v0.6.0] — 2026-04-17 — Security Hardening (Grade A)

### Seguranca

#### Input Validation (SEC-7)
- Interface do dnstop validada com regex `^[a-zA-Z0-9._-]+$` — previne RCE
- Domain e resolver do dig_trace validados com regex
- Hostname no payload do agente validado (max 128 chars, alfanumerico)

#### Token removido do HTML (SEC-8)
- `window.__TOKEN__` NUNCA mais injetado no frontend
- Novo endpoint `GET /api/v1/session/token` retorna token via cookie httponly
- app.js: `fetchSessionToken()` busca token com credentials same-origin
- Token nao aparece no source HTML, DevTools, ou network tab

#### Security Headers (SEC-9)
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Content-Security-Policy` com whitelist de origens (self, cdn.jsdelivr.net, fonts)
- `X-Frame-Options: DENY` — previne clickjacking
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`
- `Cache-Control: no-store, private` em todos os endpoints /api/

#### Session Hardening
- Cookies com nonce aleatorio (`secrets.token_hex`) — previne session fixation
- TTL reduzido: admin 4h (era 24h), cliente 12h (era 24h)
- Timing attack mitigado: dummy bcrypt verify para users inexistentes

#### Audit Log
- Tabela `audit_log` (actor, action, target, detail, ip, timestamp)
- Logados: login ok/falho (admin + cliente), comandos emitidos, clientes criados

#### Error Sanitization
- Health endpoint retorna "unavailable" em vez de detalhes do DB
- Erros genericos para o frontend, detalhes so no log do servidor

### Testes

- 303 testes passando (165 backend + 138 agent)

---

## [v0.5.0] — 2026-04-16 — Portal do Cliente, Token Embutido & NATS

### Novidades

#### Portal do Cliente (feature 010)

- Tabela `client_users` (username, password_hash, hostnames[], active)
- CRUD completo de clientes no admin: GET/POST/PATCH/DELETE /api/v1/clients
- Login proprio em `/client/login` com cookie `client_session`
- Portal read-only em `/client` com dashboard filtrado por hostnames
- Graficos: CPU, RAM, DNS latencia, top dominios — so dos hosts do cliente
- Auto-refresh a cada 60s

#### Token Embutido no Admin (feature 010 fase 1)

- Backend injeta `window.__TOKEN__` no HTML quando sessao admin valida
- Admin e dashboard nao precisam mais de campo de token manual
- Dashboard auto-carrega quando vindo do admin

#### NATS Messaging (feature 012 fases 1-2)

- Container NATS com JetStream no docker-compose (172.20.0.13)
- `nats_client.py`: client async com connect, publish, js_publish, subscribe
- POST /commands publica no NATS JetStream — entrega em < 1s
- Agente subscreve dns.commands.{hostname} via NATS (thread separada)
- ACK de resultado via NATS + HTTP redundante
- Fallback: se NATS off, HTTP polling continua (opt-in via agent.toml)

#### Design System e Refatoracao

- `base.css` (311 linhas): tokens Tokyo Night, componentes compartilhados
- `admin.css` (347 linhas): CSS extraido do admin.html
- `app.js` (172 linhas): token(), apiFetch(), toast tipado, inline errors
- Toast system: 4 tipos (success/error/warning/info) com icones SVG
- Inline errors: showInlineError(), showInlineEmpty(), showInlineLoading()
- Animacoes: fadeIn, slideUp, scaleIn com stagger
- admin.html: 1689 → 1008 linhas (-40%)

### Correcoes

| # | Problema | Correcao |
|---|---|---|
| 20 | Tela de credenciais invalidas era HTML cru branco | Redirect para login com mensagem estilizada |
| 21 | Cache do browser impedia ver token embutido | Documentacao de Ctrl+Shift+R / aba anonima |

### Testes

- `test_agent.py`: 138 testes
- `test_backend.py`: 165 testes
- Total: **303 testes** (anterior: 289)
- `AGENT_VERSION`: `1.2.0` → `1.3.0`

---

## [v0.4.0] — 2026-04-16 — API Versioning, TOML Config & Adaptive Polling

### Novidades

#### API Versioning (feature 008)

- Todas as rotas de API movidas para `/api/v1/` via `APIRouter`
- `/health`, `/admin/*`, `/static/*` permanecem na raiz
- Rotas legacy (sem prefixo) mantidas para backward compat com agentes v1.0.0
- Admin panel atualizado (`API_BASE = '/api/v1'`)
- +10 testes de verificacao de rotas

#### Migracao ConfigParser para TOML (feature 009)

- Nova classe `Config` com interface identica a ConfigParser (`get`, `getint`, `getfloat`, `getboolean`)
- `load_config()` le `.toml` (preferencial) com expansao `${VAR}`, fallback para `.conf`
- `agent.toml` criado com tipos nativos (int, float, bool)
- `tomli` adicionado ao `requirements.txt` para Python <3.11
- `install_agent.sh` prioriza `.toml`, preserva `.conf` legado
- +16 testes Config/TOML

#### Polling adaptativo de comandos

- Poll a cada 60s (era 12h) — comandos remotos respondem em ate 60s
- Apos 2 polls vazios (2 min), entra em idle (`command_poll_idle_interval`, default 600s)
- Quando encontra comando, reseta para polling ativo (60s)
- +5 testes TestAdaptivePolling

### Correcoes

| # | Problema | Correcao |
|---|---|---|
| 18 | CRLF em install_agent.sh quebrava bash no Linux | `sed -i 's/\r$//'` + `.gitattributes` forcando LF |
| 19 | Agentes v1.0.0 davam 404 apos API versioning | Rotas legacy registradas no backend para backward compat |

### Testes

- `test_agent.py`: 138 testes (+21)
- `test_backend.py`: 151 testes (+10)
- Total: **289 testes** (anterior: 258)
- `AGENT_VERSION`: `1.1.0` -> `1.2.0`

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
