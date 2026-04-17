# Feature 012: NATS Messaging — Comandos Push + DNSTop Stream

**Status**: Planejado
**Prioridade**: Media
**Dependencias**: Feature 010 (portal cliente) validada

## Problema

1. Comandos remotos dependem de polling HTTP a cada 60s — latencia de ate 1 minuto
2. DNSTop (feature 011) precisa de stream em tempo real — polling HTTP e ineficiente
3. Portal do cliente faz polling a cada 60s — nao e "tempo real" de verdade
4. Cada agente faz 1 HTTP request/min so pra checar "tem comando?" — desperdicio quando nao tem

## Solucao: NATS como barramento de mensagens

NATS e um message broker leve (binario unico, ~15MB RAM) que suporta:
- **Pub/Sub**: publish/subscribe para mensagens efemeras
- **JetStream**: persistencia de mensagens (garante entrega mesmo com agente offline)
- **WebSocket**: bridge nativa para browsers (portal do cliente)

### Arquitetura

```
                    ┌─────────┐
                    │  NATS   │
                    │ Server  │
                    │ +JSream │
                    └────┬────┘
         ┌───────────────┼───────────────┐
         │               │               │
    ┌────▼────┐    ┌─────▼─────┐   ┌─────▼─────┐
    │ Agente  │    │  Backend  │   │  Portal   │
    │ (pub/   │    │  (pub/    │   │  (sub via │
    │  sub)   │    │   sub)    │   │  websocket│
    └─────────┘    └───────────┘   └───────────┘
```

### Topicos NATS

```
dns.metrics.{hostname}      → agente publica metricas (JetStream)
dns.heartbeat.{hostname}    → agente publica heartbeat (efemero)
dns.commands.{hostname}     → backend publica comando (JetStream)
dns.commands.{hostname}.ack → agente publica resultado (JetStream)
dns.dnstop.{hostname}       → agente publica stats DNS (efemero, alto volume)
dns.alerts.{hostname}       → backend publica alertas (portal subscreve)
```

## Fases de implementacao

### Fase 1: Infraestrutura NATS (container + lib)

**Objetivo**: NATS rodando no docker-compose, agent e backend com lib conectada.

**Mudancas:**
- `docker-compose.yaml`: adicionar servico nats (nats:latest, porta 4222 + 8222 monitor)
- `backend/requirements.txt`: adicionar `nats-py>=2.7`
- `agent/requirements.txt`: adicionar `nats-py>=2.7`
- `backend/nats_client.py`: **NOVO** — conexao, publish, subscribe helpers
- `agent/dns_agent.py`: conexao NATS opcional (fallback HTTP se NATS indisponivel)

**Config:**
```toml
# agent.toml
[nats]
enabled = true
url = "nats://172.20.0.13:4222"
```

```yaml
# docker-compose.yaml
nats:
  image: nats:latest
  command: ["--jetstream", "--store_dir", "/data"]
  ports:
    - "4222:4222"
    - "8222:8222"
  volumes:
    - nats_data:/data
  networks:
    dns-net:
      ipv4_address: 172.20.0.13
```

### Fase 2: Comandos via NATS (push instantaneo)

**Objetivo**: Backend publica comando → agente recebe em < 1s. Elimina polling HTTP de comandos.

**Fluxo:**
```
Admin clica "restart" no painel
  → Backend grava no DB (como hoje)
  → Backend publica em dns.commands.{hostname} via JetStream
  → Agente recebe instantaneamente
  → Agente executa e publica resultado em dns.commands.{hostname}.ack
  → Backend recebe ACK, atualiza DB
  → Admin ve resultado no painel
```

**JetStream** garante entrega:
- Se agente esta offline, mensagem fica no stream
- Quando agente reconecta, recebe comandos pendentes
- Substitui completamente o poll_commands HTTP

**Mudancas:**
- `backend/main.py`: POST /commands publica no NATS alem de gravar no DB
- `backend/nats_client.py`: subscribe em `dns.commands.*.ack` para receber resultados
- `agent/dns_agent.py`: subscribe em `dns.commands.{hostname}` via NATS
- `agent/dns_agent.py`: remover `poll_commands` HTTP (manter como fallback)
- Config: `command_poll_interval` so usado quando NATS indisponivel

**Backward compat**: agentes sem NATS continuam usando HTTP polling.

### Fase 3: DNSTop via NATS stream (feature 011)

**Objetivo**: Stats DNS em tempo real no portal do cliente via WebSocket.

**Fluxo:**
```
Agente coleta dnstop a cada 10s
  → Publica em dns.dnstop.{hostname} (efemero, sem JetStream)
  → Backend subscreve, armazena snapshot a cada 30s no DB
  → Portal do cliente subscreve via NATS WebSocket bridge
  → Graficos atualizam em tempo real (< 1s delay)
```

**NATS WebSocket**: o servidor NATS suporta conexoes WebSocket nativamente.
O browser do cliente conecta direto no NATS via WS, subscribendo em `dns.dnstop.{hostname}`.

```yaml
# nats-server.conf
websocket {
  port: 9222
  no_tls: true
}
```

**Mudancas:**
- `agent/dns_agent.py`: `collect_dnstop()` publica via NATS
- `backend/nats_client.py`: subscribe `dns.dnstop.*`, armazena no DB a cada 30s
- `backend/schemas.sql`: tabela `dnstop_snapshots`
- `client.html`: conecta via WebSocket NATS, graficos real-time
- `docker-compose.yaml`: expor porta 9222 (WS)

### Fase 4: Metrics + Heartbeat via NATS (opcional)

**Objetivo**: Migrar todo o trafego agente→backend para NATS. HTTP so para admin/portal.

**So faz sentido se:**
- 20+ agentes (volume justifica)
- Rede permite TCP persistente na porta 4222
- Quer eliminar completamente HTTP no agente

**Mudancas:**
- Agente publica em `dns.metrics.{hostname}` e `dns.heartbeat.{hostname}`
- Backend subscreve e persiste no TimescaleDB
- Endpoint POST /metrics vira legacy (backward compat)

## Decisoes de design

### Por que NATS e nao Redis/RabbitMQ/Kafka?

| Criterio | NATS | Redis Pub/Sub | RabbitMQ | Kafka |
|---|---|---|---|---|
| RAM | ~15MB | ~50MB | ~200MB | ~500MB |
| Complexidade | Binario unico | Precisa de config | Erlang runtime | JVM + Zookeeper |
| WebSocket | Nativo | Nao | Plugin | Nao |
| JetStream (persistencia) | Built-in | Streams (Redis 5+) | Built-in | Built-in |
| Latencia | ~100us | ~200us | ~1ms | ~5ms |
| Go/Python libs | Excelentes | Boas | Boas | Boas |

NATS e o mais leve e tem WebSocket nativo — ideal pra esse caso.

### Fallback HTTP

Agentes SEMPRE mantem capacidade HTTP. Se NATS cair:
- Metricas/heartbeat: continuam via POST /api/v1/metrics
- Comandos: voltam pro polling HTTP (poll_commands)
- Portal: volta pro polling HTTP (apiFetch)

O agente detecta desconexao NATS e ativa fallback automaticamente.

### Seguranca

- NATS com auth: token ou NKey por agente
- Permissoes: agente so publica em `dns.*.{seu_hostname}` e subscreve em `dns.commands.{seu_hostname}`
- Portal: subscreve apenas em `dns.dnstop.{hostnames_do_cliente}`
- TLS opcional (recomendado se trafego sai da rede local)

## Arquivos impactados

| Fase | Arquivo | Mudanca |
|---|---|---|
| 1 | `docker-compose.yaml` | Servico NATS |
| 1 | `backend/nats_client.py` | **NOVO** — client NATS |
| 1 | `backend/requirements.txt` | +nats-py |
| 1 | `agent/requirements.txt` | +nats-py |
| 1 | `agent/agent.toml` | Secao [nats] |
| 2 | `backend/main.py` | Publish comando no NATS |
| 2 | `agent/dns_agent.py` | Subscribe comandos via NATS |
| 3 | `agent/dns_agent.py` | collect_dnstop + publish |
| 3 | `backend/schemas.sql` | Tabela dnstop_snapshots |
| 3 | `client.html` | WebSocket NATS real-time |
| 4 | `agent/dns_agent.py` | Metrics via NATS (opcional) |
| 4 | `backend/main.py` | Subscribe metrics (opcional) |

## Estimativas

| Fase | Testes novos | Linhas | Risco |
|---|---|---|---|
| 1 — Infra | ~5 | ~150 | Baixo |
| 2 — Comandos push | ~10 | ~200 | Medio (fallback logic) |
| 3 — DNSTop stream | ~12 | ~350 | Medio (WebSocket + coleta) |
| 4 — Metrics NATS | ~8 | ~200 | Baixo (opcional) |
| **Total** | **~35** | **~900** | |

## Criterios de aceite

### Fase 1
- [ ] Container NATS rodando no docker-compose com JetStream
- [ ] Backend conecta ao NATS no startup
- [ ] Agente conecta ao NATS se configurado
- [ ] Fallback HTTP funciona quando NATS indisponivel

### Fase 2
- [ ] Comando emitido pelo admin chega ao agente em < 1s
- [ ] Agente offline recebe comandos pendentes ao reconectar (JetStream)
- [ ] Resultado do comando volta pro backend via NATS
- [ ] Agente sem NATS continua usando HTTP polling

### Fase 3
- [ ] Portal do cliente mostra QPS, top domains, top clients em tempo real
- [ ] Graficos atualizam a cada 10s via WebSocket
- [ ] Backend armazena snapshots no TimescaleDB a cada 30s
- [ ] Funciona com Unbound e Bind9

### Fase 4
- [ ] Metricas e heartbeat via NATS (pub/sub)
- [ ] POST /metrics continua funcionando (legacy)
- [ ] Sem perda de dados se NATS reiniciar (JetStream)
