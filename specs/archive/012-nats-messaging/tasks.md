# Tasks — Feature 012: NATS Messaging

## Ordem de execucao

```
Fase 1: Infra NATS ──────── container + libs + conexao
   │
Fase 2: Comandos push ───── elimina polling, < 1s latencia
   │
Fase 3: DNSTop stream ───── stats DNS tempo real no portal
   │
Fase 4: Metrics NATS ────── (opcional) migrar heartbeat/metrics
```

---

## Fase 1: Infraestrutura NATS

- [ ] T001 — docker-compose.yaml: servico nats com JetStream + rede dns-net (172.20.0.13)
- [ ] T002 — backend/nats_client.py: NOVO — connect(), publish(), subscribe(), close()
- [ ] T003 — backend/requirements.txt: +nats-py>=2.7
- [ ] T004 — agent/requirements.txt: +nats-py>=2.7
- [ ] T005 — agent/agent.toml: secao [nats] com enabled, url
- [ ] T006 — agent/dns_agent.py: conexao NATS opcional no startup (try/except fallback)
- [ ] T007 — backend/main.py: conectar NATS no lifespan (startup/shutdown)
- [ ] T008 — Testes: conexao mock, fallback quando NATS offline

**Checkpoint**: NATS rodando, agent e backend conectados.

---

## Fase 2: Comandos via NATS (push)

- [ ] T009 — Testes RED: comando publicado no NATS ao criar via API
- [ ] T010 — backend/main.py: POST /commands publica em dns.commands.{hostname}
- [ ] T011 — backend/nats_client.py: subscribe dns.commands.*.ack para receber resultados
- [ ] T012 — agent/dns_agent.py: subscribe dns.commands.{hostname} via NATS
- [ ] T013 — agent/dns_agent.py: ao executar comando, publica resultado em dns.commands.{hostname}.ack
- [ ] T014 — agent/dns_agent.py: fallback para HTTP polling se NATS desconectado
- [ ] T015 — Testes GREEN: comando emitido → agente recebe → resultado volta
- [ ] T016 — JetStream: criar stream COMMANDS com retencao 7 dias
- [ ] T017 — Testar: agente offline → reconecta → recebe comandos pendentes

**Checkpoint**: Comandos chegam em < 1s. Fallback HTTP funciona.

---

## Fase 3: DNSTop via NATS stream

- [ ] T018 — agent/agent.toml: secao [dnstop] com enabled, interval, interface, method
- [ ] T019 — agent/dns_agent.py: collect_dnstop() via unbound-control ou rndc stats
- [ ] T020 — agent/dns_agent.py: publica dns.dnstop.{hostname} a cada 10s via NATS
- [ ] T021 — backend/schemas.sql: tabela dnstop_snapshots (hypertable)
- [ ] T022 — backend/nats_client.py: subscribe dns.dnstop.*, armazena a cada 30s
- [ ] T023 — docker-compose.yaml: habilitar WebSocket na porta 9222
- [ ] T024 — client.html: conexao WebSocket NATS, subscribe dns.dnstop.{hostnames}
- [ ] T025 — client.html: graficos real-time (QPS line, top domains bar, donut charts)
- [ ] T026 — Testes: coleta, publish, armazenamento, filtragem por hostname

**Checkpoint**: Portal do cliente mostra DNS em tempo real.

---

## Fase 4: Metrics + Heartbeat via NATS (opcional)

- [ ] T027 — agent/dns_agent.py: publish dns.metrics.{hostname} e dns.heartbeat.{hostname}
- [ ] T028 — backend/nats_client.py: subscribe dns.metrics.*, persiste no TimescaleDB
- [ ] T029 — JetStream: stream METRICS com retencao 24h (buffer)
- [ ] T030 — agent/dns_agent.py: fallback HTTP se NATS indisponivel
- [ ] T031 — Testes: publicacao, persistencia, fallback

**Checkpoint**: Todo trafego via NATS. HTTP so como fallback.

---

## Dependencias

```
Fase 1 ← nenhuma (pode comecar apos validar portal cliente)
Fase 2 ← Fase 1 (precisa NATS rodando)
Fase 3 ← Fase 2 (precisa NATS + WebSocket)
Fase 4 ← Fase 2 (opcional, so se volume justificar)
```

## Estimativas

| Fase | Tasks | Testes | Linhas |
|------|-------|--------|--------|
| 1 — Infra | 8 | ~5 | ~150 |
| 2 — Comandos | 9 | ~10 | ~200 |
| 3 — DNSTop | 9 | ~12 | ~350 |
| 4 — Metrics | 5 | ~8 | ~200 |
| **Total** | **31** | **~35** | **~900** |
