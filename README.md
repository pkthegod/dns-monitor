# DNS Monitor

Sistema distribuído de monitoramento DNS para redes Linux com Unbound ou Bind9. Coleta métricas de sistema e testa resolução DNS em até 50 máquinas, centraliza os dados em TimescaleDB e exibe tudo em dashboards Grafana com alertas via Telegram.

---

## Arquitetura

```
┌─────────────────────────────────┐      HTTP/JSON      ┌──────────────────────────────┐
│        Máquina monitorada       │ ──────────────────► │         Servidor central      │
│                                 │                      │                              │
│  dns_agent.py                   │                      │  FastAPI  (porta 8000)       │
│  ├─ heartbeat a cada 5 min      │                      │  TimescaleDB / PostgreSQL 15 │
│  ├─ check DNS 4×/dia            │                      │  Grafana  (porta 3000)       │
│  └─ métricas CPU/RAM/disco/I/O  │                      │  Alertas → Telegram          │
└─────────────────────────────────┘                      └──────────────────────────────┘
         (repita para N máquinas)
```

**Stack:**

| Componente | Tecnologia |
|---|---|
| Agente | Python 3.8+, psutil, dnspython, schedule |
| Backend | FastAPI, asyncpg, APScheduler |
| Banco | TimescaleDB (PostgreSQL 15) — 7 hypertables |
| Dashboards | Grafana 12, PostgreSQL datasource |
| Deploy | Docker Compose |

---

## Estrutura do Repositório

```
dns-monitor/
├── README.md
├── IMPLEMENTACAO.md          ← guia detalhado de deploy
├── .gitignore
├── test_grafana.py           ← 92 testes dos dashboards
├── test_payload.py           ← diagnóstico de payload (utilitário)
│
├── agent/
│   ├── dns_agent.py          ← agente principal
│   ├── agent.conf            ← configuração (sem segredos)
│   ├── env.example           ← template de segredos
│   ├── dns_agent.service     ← unit systemd
│   ├── install_agent.sh      ← instalador
│   ├── requirements.txt
│   └── test_agent.py         ← 59 testes do agente
│
├── backend/
│   ├── main.py               ← API FastAPI
│   ├── db.py                 ← camada asyncpg / TimescaleDB
│   ├── schemas.sql           ← DDL completo (7 hypertables + views)
│   ├── telegram_bot.py       ← alertas Telegram
│   ├── docker-compose.yaml
│   ├── Dockerfile
│   ├── .env.example          ← template de segredos do backend
│   ├── requirements.txt
│   └── test_backend.py       ← 49 testes do backend
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
- Linux com Unbound ou Bind9
- Python 3.8+
- Acesso HTTP à porta 8000 do servidor central

---

## Deploy do Backend

### 1. Clonar e configurar

```bash
git clone https://github.com/seu-usuario/dns-monitor.git
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
# Acessar Grafana em http://SEU_IP:3000 (admin / GRAFANA_PASSWORD)

curl -s -u admin:'SUA_SENHA' \
  -X POST http://localhost:3000/api/dashboards/import \
  -H "Content-Type: application/json" \
  -d "{\"dashboard\": $(cat ../grafana/dashboards/overview.json), \"overwrite\": true, \"folderId\": 0}"

curl -s -u admin:'SUA_SENHA' \
  -X POST http://localhost:3000/api/dashboards/import \
  -H "Content-Type: application/json" \
  -d "{\"dashboard\": $(cat ../grafana/dashboards/host-detail.json), \"overwrite\": true, \"folderId\": 0}"
```

> **Nota Grafana 12:** importe os dashboards apenas *após* o datasource estar provisionado. Se precisar reimportar, remova temporariamente `grafana/provisioning/dashboards/provider.yaml`, reinicie o Grafana, reimporte via API e restaure o arquivo.

---

## Instalação do Agente

Execute em cada máquina a ser monitorada:

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

sudo systemctl start dns_agent
sudo journalctl -u dns_agent -f
# → Payload enviado com sucesso (tipo=heartbeat)
```

O `agent.conf` lê `%(AGENT_HOSTNAME)s`, `%(AGENT_TOKEN)s` e `%(AGENT_BACKEND)s` diretamente do ambiente — nenhum segredo fica no arquivo de configuração.

---

## Funcionamento do Agente

| Evento | Frequência | O que envia |
|---|---|---|
| Heartbeat | A cada 5 min | hostname, timestamp, versão |
| Check completo | 00:00, 06:00, 12:00, 18:00 | métricas + testes DNS |

**Métricas coletadas por check:**
- CPU: percentual, contagem de cores, frequência, load average
- RAM: uso percentual, MB usados/total, swap
- Disco: uso por partição, alerta ok/warning/critical
- I/O: bytes e operações de leitura/escrita desde o boot
- DNS: latência por domínio, IPs resolvidos, sucesso/falha, tentativas

---

## Banco de Dados

Sete hypertables TimescaleDB com compressão automática após 7 dias e retenção configurável:

| Tabela | Chunk | Retenção |
|---|---|---|
| `agent_heartbeats` | 1h | 30 dias |
| `metrics_cpu` | 6h | 1 ano |
| `metrics_ram` | 6h | 1 ano |
| `metrics_disk` | 6h | 1 ano |
| `metrics_io` | 6h | 1 ano |
| `dns_checks` | 1 dia | 1 ano |
| `dns_service_status` | 1 dia | 1 ano |

View `v_agent_current_status` consolida o estado atual de cada agente para o Grafana.

---

## Alertas via Telegram

Configure `TELEGRAM_BOT_TOKEN` e `TELEGRAM_CHAT_ID` no `.env` do backend. Alertas disparados:

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

Alertas são deduplicados — o mesmo tipo não repete enquanto o alerta anterior estiver aberto.

---

## Testes

```bash
# Backend (49 testes)
cd backend
PYTHONPATH=. pytest test_backend.py -v

# Agente (59 testes)
cd agent
PYTHONPATH=. pytest test_agent.py -v

# Dashboards Grafana (92 testes)
pytest test_grafana.py -v
```

Total: **200 testes**, todos devem passar antes de qualquer deploy.

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
| `backend/.env.example` | ✅ template | referência |
| `agent/env.example` | ✅ template | referência |

---

## Licença

MIT
