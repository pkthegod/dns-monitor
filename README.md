# DNS Monitor

Sistema distribuído de monitoramento DNS para redes Linux com Unbound ou Bind9. Coleta métricas de sistema, testa resolução DNS em até 50 máquinas, centraliza os dados em TimescaleDB, exibe dashboards em Grafana e permite **controle remoto dos serviços DNS** diretamente do servidor central.

---

## Arquitetura

```
┌─────────────────────────────────┐   HTTP/JSON (push)   ┌──────────────────────────────┐
│        Máquina monitorada       │ ──────────────────►  │       Servidor central       │
│                                 │                      │                              │
│  dns_agent.py                   │ ◄──────────────────  │  FastAPI  (porta 8000)       │
│  ├─ heartbeat a cada 5 min      │   comandos (poll)    │  TimescaleDB / PostgreSQL 15 │
│  ├─ check DNS 4×/dia            │                      │  Grafana  (porta 3000)       │
│  ├─ métricas CPU/RAM/disco/I/O  │                      │  Alertas → Telegram          │
│  ├─ fingerprint de hardware     │                      │                              │
│  └─ poll de comandos a cada 12h │                      │  agent_commands (banco)      │
└─────────────────────────────────┘                      └──────────────────────────────┘
         (repita para N máquinas)
```

**Stack:**

| Componente | Tecnologia |
|---|---|
| Agente | Python 3.8+, psutil, dnspython, schedule |
| Backend | FastAPI, asyncpg, APScheduler |
| Banco | TimescaleDB (PostgreSQL 15) — 8 hypertables + 1 tabela de comandos |
| Dashboards | Grafana 12, PostgreSQL datasource |
| Deploy | Docker Compose (1 worker — scheduler único) |

---

## Estrutura do Repositório

```
dns-monitor/
├── README.md
├── IMPLEMENTACAO.md          ← guia detalhado de deploy
├── DB_ADMIN.sql              ← referência de administração do banco
├── .gitignore
├── test_grafana.py           ← 92 testes dos dashboards
├── test_payload.py           ← utilitário de diagnóstico de payload
│
├── agent/
│   ├── dns_agent.py          ← agente principal
│   ├── agent.conf            ← configuração (sem segredos, usa %(VAR)s)
│   ├── env.example           ← template de segredos
│   ├── dns_agent.service     ← unit systemd
│   ├── install_agent.sh      ← instalador (cria sudoers automaticamente)
│   ├── requirements.txt
│   └── test_agent.py         ← 80 testes do agente
│
├── backend/
│   ├── main.py               ← API FastAPI + endpoints de comandos
│   ├── db.py                 ← camada asyncpg / TimescaleDB + fingerprint
│   ├── schemas.sql           ← DDL completo (hypertables + agent_commands)
│   ├── telegram_bot.py       ← alertas Telegram
│   ├── docker-compose.yaml
│   ├── Dockerfile
│   ├── .env.example          ← template de segredos do backend
│   ├── requirements.txt
│   └── test_backend.py       ← 70 testes do backend
│
└── grafana/
    ├── dashboards/
    │   ├── overview.json     ← visão geral de todos os agentes
    │   └── host-detail.json  ← detalhe por host com seletor
    └── provisioning/
        ├── datasources/timescaledb.yaml
        └── dashboards/provider.yaml
```

---

## Pré-requisitos

**Servidor central:**

- Linux (Debian/Ubuntu recomendado)
- Docker + Docker Compose plugin
- Porta 8000 (API) e 3000 (Grafana) acessíveis

**Cada máquina monitorada:**

- Linux com Unbound, Bind9 ou Named
- Python 3.8+
- Acesso HTTP à porta 8000 do servidor central

---

## Deploy do Backend

### 1. Clonar e configurar

```bash
git clone https://github.com/pkthegod/dns-monitor.git
cd dns-monitor/backend

cp .env.example .env
nano .env
```

Preencha o `.env` — **senhas sem `@`, `#`, `/`, `?`, `%`:**

```dotenv
POSTGRES_USER=dnsmonitor
POSTGRES_PASSWORD=SenhaSemCaracteresEspeciais
POSTGRES_DB=dns_monitor

# Gere com: python3 -c "import secrets; print(secrets.token_hex(32))"
AGENT_TOKEN=cole_o_token_gerado_aqui

GRAFANA_USER=admin
GRAFANA_PASSWORD=OutraSenhaSemEspeciais

TELEGRAM_BOT_TOKEN=        # opcional
TELEGRAM_CHAT_ID=          # opcional
```

### 2. Subir os serviços

```bash
docker compose build --no-cache backend
docker compose up -d

# Verificar
curl http://localhost:8000/health
# → {"status":"ok","db":"connected"}
```

### 3. Importar os dashboards no Grafana

```bash
# Grafana em http://SEU_IP:3000 (admin / GRAFANA_PASSWORD)
# Importe APÓS o datasource estar provisionado

curl -s -u admin:'SUA_SENHA' \
  -X POST http://localhost:3000/api/dashboards/import \
  -H "Content-Type: application/json" \
  -d "{\"dashboard\": $(cat ../grafana/dashboards/overview.json), \"overwrite\": true, \"folderId\": 0}"

curl -s -u admin:'SUA_SENHA' \
  -X POST http://localhost:3000/api/dashboards/import \
  -H "Content-Type: application/json" \
  -d "{\"dashboard\": $(cat ../grafana/dashboards/host-detail.json), \"overwrite\": true, \"folderId\": 0}"
```

> **Grafana 12:** se precisar reimportar, remova temporariamente `grafana/provisioning/dashboards/provider.yaml`, reinicie o Grafana, reimporte via API e restaure o arquivo.

---

## Instalação do Agente

### 1. Copiar os arquivos

```bash
scp agent/* usuario@maquina:/tmp/dns-agent/
ssh usuario@maquina
```

### 2. Criar o arquivo de segredos

```bash
sudo mkdir -p /etc/dns-agent
sudo nano /etc/dns-agent/env
```

```bash
AGENT_HOSTNAME=nome-desta-maquina
AGENT_TOKEN=mesmo_token_do_backend_env
AGENT_BACKEND=http://IP_DO_SERVIDOR:8000
```

```bash
sudo chmod 640 /etc/dns-agent/env
sudo chown root:dns-agent /etc/dns-agent/env 2>/dev/null || true
```

### 3. Instalar

```bash
sudo bash /tmp/dns-agent/install_agent.sh
```

O instalador cria automaticamente:

- `/opt/dns-agent/` — virtualenv e código
- `/etc/dns-agent/agent.conf` — configuração
- `/etc/dns-agent/env` — template de segredos (preencha antes de iniciar)
- `/etc/sudoers.d/dns-agent` — permissões para controle remoto do DNS
- Serviço systemd habilitado

```bash
sudo systemctl start dns_agent
sudo journalctl -u dns_agent -f
# → Payload enviado com sucesso (tipo=heartbeat)
```

> **Debian/Ubuntu com Bind9:** o serviço real é `named` — o agente resolve isso automaticamente via `SERVICE_ALIASES`.

---

## Funcionamento do Agente

| Evento | Frequência | O que envia |
|---|---|---|
| Heartbeat | A cada 5 min | hostname, timestamp, versão, fingerprint |
| Check completo | 00:00, 06:00, 12:00, 18:00 | métricas + testes DNS + fingerprint |
| Poll de comandos | A cada 12h + na inicialização | consulta comandos pendentes no backend |

**Métricas coletadas por check:**

- CPU: percentual, contagem de cores, frequência, load average
- RAM: uso percentual, MB usados/total, swap
- Disco: uso por partição, alerta ok/warning/critical
- I/O: bytes e operações de leitura/escrita desde o boot
- DNS: latência por domínio, IPs resolvidos, sucesso/falha, tentativas

---

## Controle Remoto de Agentes

O servidor pode enviar comandos para qualquer agente. O agente consulta o backend a cada 12h e na inicialização — comandos emitidos durante downtime são capturados no próximo poll.

### Comandos disponíveis

| Comando | Efeito | Reversível |
|---|---|---|
| `stop` | Para o serviço DNS imediatamente | Sim — use `enable` |
| `disable` | Para e desabilita no boot | Sim — use `enable` |
| `enable` | Ativa e inicia o serviço | — |
| `purge` | Remove o pacote do sistema | **Não** |

### Emitir via banco de dados

```sql
-- Parar DNS de um agente
INSERT INTO agent_commands (hostname, command, issued_by)
VALUES ('HOSTNAME_AQUI', 'stop', 'admin');

-- Reativar
INSERT INTO agent_commands (hostname, command, issued_by)
VALUES ('HOSTNAME_AQUI', 'enable', 'admin');

-- Acompanhar execução
SELECT id, command, status, executed_at, result
FROM agent_commands
WHERE hostname = 'HOSTNAME_AQUI'
ORDER BY issued_at DESC;
```

### Emitir via API

```bash
# Stop
curl -s -X POST http://localhost:8000/commands \
  -H "Authorization: Bearer SEU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"hostname": "HOSTNAME_AQUI", "command": "stop"}'

# Purge — retorna confirm_token obrigatório
curl -s -X POST http://localhost:8000/commands \
  -H "Authorization: Bearer SEU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"hostname": "HOSTNAME_AQUI", "command": "purge"}'

# Histórico de comandos
curl -s http://localhost:8000/commands/HOSTNAME_AQUI/history \
  -H "Authorization: Bearer SEU_TOKEN"
```

> O agente precisa reiniciar para fazer o poll imediatamente — caso contrário aguarda as próximas 12h.

---

## Fingerprint de Hardware

Cada agente gera um SHA256 baseado em hostname + MAC address + `/etc/machine-id`. Esse fingerprint é enviado em todo payload e registrado no banco. Se mudar, o backend gera um `WARNING` nos logs — indicando possível cópia não autorizada ou migração de hardware.

```sql
-- Ver fingerprints registrados
SELECT hostname, fingerprint, fingerprint_first_seen, fingerprint_last_seen
FROM agents ORDER BY hostname;

-- Redefinir após troca de hardware legítima
UPDATE agents SET fingerprint = NULL, fingerprint_first_seen = NULL,
    fingerprint_last_seen = NULL WHERE hostname = 'HOSTNAME_AQUI';
```

---

## Banco de Dados

| Tabela | Tipo | Chunk | Retenção |
|---|---|---|---|
| `agent_heartbeats` | hypertable | 1h | 30 dias |
| `metrics_cpu` | hypertable | 6h | 1 ano |
| `metrics_ram` | hypertable | 6h | 1 ano |
| `metrics_disk` | hypertable | 6h | 1 ano |
| `metrics_io` | hypertable | 6h | 1 ano |
| `dns_checks` | hypertable | 1 dia | 1 ano |
| `dns_service_status` | hypertable | 1 dia | 1 ano |
| `agents` | tabela | — | — |
| `alerts_log` | tabela | — | — |
| `agent_commands` | tabela | — | — |

Compressão automática após 7 dias em todas as hypertables (~90% de redução em disco).

---

## Alertas via Telegram

Configure `TELEGRAM_BOT_TOKEN` e `TELEGRAM_CHAT_ID` no `.env` do backend.

| Condição | Severidade |
|---|---|
| CPU ≥ 80% | warning |
| CPU ≥ 95% | critical |
| RAM ≥ 85% | warning |
| RAM ≥ 95% | critical |
| Disco ≥ 80% | warning |
| Disco ≥ 90% | critical |
| Latência DNS ≥ 200ms | warning |
| Latência DNS ≥ 1000ms | critical |
| Falha na resolução DNS | critical |
| Serviço DNS inativo | critical |
| Agente offline > 10 min | critical |

Alertas são deduplicados — o mesmo tipo não repete enquanto o alerta anterior estiver aberto. Relatórios consolidados enviados nos horários configurados (padrão: 00:00, 06:00, 12:00, 18:00).

---

## Testes

```bash
# Backend (70 testes)
cd backend
PYTHONPATH=. pytest test_backend.py -v

# Agente (80 testes)
cd agent
PYTHONPATH=. pytest test_agent.py -v

# Dashboards Grafana (92 testes)
pytest test_grafana.py -v
```

Total: **242 testes** — todos devem passar antes de qualquer deploy.

---

## Comandos de Operação

```bash
# Status geral
curl -s http://localhost:8000/agents | python3 -m json.tool
curl -s http://localhost:8000/health

# Logs do backend
docker compose logs -f backend

# Rebuild após mudança de código
docker compose build --no-cache backend
docker compose up -d --force-recreate backend

# Banco de dados
docker exec -it dns_monitor_db psql -U dnsmonitor -d dns_monitor

# Agente (na máquina monitorada)
sudo systemctl status dns_agent
sudo journalctl -u dns_agent -f
sudo systemctl restart dns_agent
```

---

## Segurança

| Arquivo | Repositório | Produção |
|---|---|---|
| `backend/.env` | ❌ ignorado | `/opt/dns-monitor/backend/.env` |
| `agent/env` | ❌ ignorado | `/etc/dns-agent/env` (chmod 640) |
| `agent/agent.conf` | ✅ sem segredos | lê vars do ambiente via `%(VAR)s` |
| `/etc/sudoers.d/dns-agent` | ❌ gerado pelo installer | apenas comandos systemctl específicos |
| `backend/.env.example` | ✅ template | referência |
| `agent/env.example` | ✅ template | referência |

---

## Branches

| Branch | Propósito |
|---|---|
| `main` | Estável — produção |
| `dev` | Desenvolvimento — próximas funcionalidades |

---

## Licença

MIT
