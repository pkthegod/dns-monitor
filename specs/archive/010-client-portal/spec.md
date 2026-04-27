# Feature 010: Portal do Cliente + Token Embutido no Admin

**Status**: Planejado
**Prioridade**: Alta
**Dependencias**: Nenhuma

## Problema

1. O admin panel exige que o usuario cole o AGENT_TOKEN manualmente — friction desnecessaria pra quem ja fez login
2. Clientes que usam os servidores DNS nao tem visibilidade das metricas do SEU servidor
3. Toda a visao e global (admin ve tudo) — nao existe acesso restrito por hostname

## Solucao

### Parte 1: Token embutido no admin

O admin ja esta autenticado via cookie de sessao. O backend injeta o AGENT_TOKEN direto no HTML servido, eliminando o campo manual.

**Mudancas:**
- `GET /admin` — injeta `window.__TOKEN__ = "..."` no HTML antes de servir
- `app.js` — `token()` usa `window.__TOKEN__` se disponivel, senao campo input
- `admin.html` — remove o campo de token do header (ou esconde quando __TOKEN__ existe)
- Dashboard — recebe o mesmo tratamento quando acessado via admin (link com sessao)

### Parte 2: Tabela de usuarios/clientes

Nova tabela `client_users` no banco:

```sql
CREATE TABLE IF NOT EXISTS client_users (
    id           SERIAL       PRIMARY KEY,
    username     TEXT         NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,
    hostnames    TEXT[]       NOT NULL,     -- array de hostnames que pode ver
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    active       BOOLEAN      NOT NULL DEFAULT TRUE,
    notes        TEXT
);
```

**Exemplo**: cliente `cliente1` com senha `cliente1` ve apenas `nsr-cliente1`.

### Parte 3: Portal do cliente

Nova pagina `/client` (ou `/portal`):
- Login proprio (`/client/login`) com user/senha da tabela `client_users`
- Dashboard simplificado: so mostra agentes do `hostnames[]` do user
- Read-only: sem comandos, sem edicao, sem remocao
- Graficos: CPU, RAM, DNS latencia, alertas — filtrados por hostname
- Auto-refresh a cada 60s

**Endpoints novos:**
- `POST /client/login` — valida user/senha, seta cookie `client_session`
- `GET /client` — serve portal HTML (protegido por cookie)
- `GET /api/v1/client/data` — retorna dados filtrados por hostnames do user
- `GET /client/logout`

**Admin panel — CRUD de clientes:**
- Secao nova no admin: listar/criar/editar/remover client_users
- Ao criar: define username, senha, seleciona hostnames associados

### Parte 4: Fluxo de uso

```
Admin cria cliente:
  username: cliente1
  password: cliente1
  hostnames: [nsr-cliente1]

Cliente acessa: http://servidor:8000/client
  → Login com cliente1/cliente1
  → Ve dashboard filtrado para nsr-cliente1
  → Metricas, graficos, alertas — so do servidor dele
  → Sem acesso a comandos, edicao, ou outros agentes
```

## Arquivos impactados

| Arquivo | Mudanca |
|---|---|
| `backend/schemas.sql` | Tabela `client_users` |
| `backend/db.py` | CRUD de client_users, queries filtradas |
| `backend/main.py` | Endpoints /client/*, token embutido no admin |
| `backend/static/admin.html` | CRUD clientes, remover token field |
| `backend/static/client.html` | **NOVO** — portal do cliente |
| `backend/static/client-login.html` | **NOVO** — login do cliente |
| `backend/static/app.js` | `token()` com fallback para `__TOKEN__` |
| `backend/test_backend.py` | Testes dos novos endpoints |

## Criterios de aceite

- [ ] Admin nao precisa colar token — ja esta embutido na sessao
- [ ] Admin pode criar/editar/remover usuarios clientes
- [ ] Cliente faz login e ve APENAS seus hostnames
- [ ] Cliente NAO consegue acessar /admin ou endpoints de outros hostnames
- [ ] Dashboard do cliente tem graficos de CPU, RAM, DNS, alertas
- [ ] Senhas armazenadas com hash (bcrypt ou sha256+salt)
- [ ] Testes cobrindo auth, filtragem, CRUD

---

# Feature 011: DNSTop — Monitoramento DNS em Tempo Real

**Status**: Planejado
**Prioridade**: Media
**Dependencias**: Feature 010 (portal do cliente)

## Problema

O cliente nao tem visibilidade em tempo real das queries DNS passando pelo servidor dele. As metricas atuais (quick probe, full check) testam resolucao — nao mostram o trafego real.

## Solucao

### O que e dnstop

`dnstop` e uma ferramenta que monitora trafego DNS em tempo real, mostrando:
- Queries por segundo (QPS)
- Top dominios consultados
- Top clientes (IPs de origem)
- Tipos de query (A, AAAA, MX, PTR, etc.)
- Codigos de resposta (NOERROR, NXDOMAIN, SERVFAIL)

### Arquitetura

```
[agente] → captura com dnstop/tcpdump → agrega a cada 30s
         → envia para backend via POST /api/v1/dnstop
[backend] → armazena em hypertable dnstop_snapshots
[portal]  → grafico em tempo real com polling a cada 30s
```

### Dados coletados pelo agente

Nova funcao `collect_dnstop()` no agente:
- Roda `dnstop -l 30 <interface>` ou equivalente com `tcpdump + parsing`
- Alternativa leve: `unbound-control stats_noreset` (se unbound)
- Agrega os ultimos 30s de trafego

Payload enviado no heartbeat (campo novo `dnstop`):

```json
{
  "qps": 142.5,
  "total_queries": 4275,
  "top_domains": [
    {"domain": "google.com", "count": 320},
    {"domain": "facebook.com", "count": 210}
  ],
  "top_clients": [
    {"ip": "192.168.1.10", "count": 890},
    {"ip": "192.168.1.20", "count": 650}
  ],
  "query_types": {"A": 3200, "AAAA": 800, "MX": 50, "PTR": 225},
  "response_codes": {"NOERROR": 4000, "NXDOMAIN": 250, "SERVFAIL": 25}
}
```

### Banco de dados

```sql
CREATE TABLE IF NOT EXISTS dnstop_snapshots (
    ts            TIMESTAMPTZ NOT NULL,
    hostname      TEXT        NOT NULL,
    qps           NUMERIC(10,1),
    total_queries INTEGER,
    top_domains   JSONB,
    top_clients   JSONB,
    query_types   JSONB,
    response_codes JSONB
);

SELECT create_hypertable('dnstop_snapshots', 'ts',
    chunk_time_interval => INTERVAL '1 hour', if_not_exists => TRUE);
```

### Portal do cliente — graficos DNSTop

- **QPS tempo real**: line chart atualizado a cada 30s
- **Top dominios**: bar chart horizontal (top 10)
- **Top clientes**: bar chart horizontal (top 10 IPs)
- **Query types**: donut chart (A, AAAA, MX, PTR, outros)
- **Response codes**: donut chart (NOERROR, NXDOMAIN, SERVFAIL)

### Configuracao no agente

```toml
[dnstop]
enabled = true
interval = 30           # segundos entre capturas
interface = "eth0"      # interface de rede a monitorar
method = "unbound"      # "unbound" | "tcpdump" | "auto"
top_count = 10          # quantos top domains/clients reportar
```

## Arquivos impactados

| Arquivo | Mudanca |
|---|---|
| `agent/dns_agent.py` | `collect_dnstop()`, integracao no heartbeat |
| `agent/agent.toml` | Secao `[dnstop]` |
| `backend/schemas.sql` | Tabela `dnstop_snapshots` |
| `backend/db.py` | `insert_dnstop()`, queries filtradas |
| `backend/main.py` | Processar campo `dnstop` no payload |
| `backend/static/client.html` | Graficos DNSTop em tempo real |
| `agent/test_agent.py` | Testes de collect_dnstop |
| `backend/test_backend.py` | Testes de armazenamento/query |

## Criterios de aceite

- [ ] Agente coleta stats DNS a cada 30s (QPS, top domains, top clients)
- [ ] Backend armazena snapshots em hypertable com compressao
- [ ] Portal do cliente mostra graficos DNSTop em tempo real
- [ ] Funciona com Unbound (unbound-control) e Bind9 (rndc stats)
- [ ] Configuravel: habilitar/desabilitar, intervalo, interface
- [ ] Nao impacta performance do servidor DNS (< 1% CPU overhead)
- [ ] Testes cobrindo coleta, envio, armazenamento, visualizacao
