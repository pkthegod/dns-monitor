# Changelog — DNS Monitor

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
