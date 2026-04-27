# Tasks — Feature 010: Client Portal + Token Embutido

## Ordem de implementacao

```
Fase 1: Token embutido no admin (independente)
Fase 2: Tabela client_users + CRUD no admin
Fase 3: Portal do cliente (login + dashboard filtrado)
Fase 4: DNSTop (feature 011 — depende do portal)
```

---

## Fase 1: Token embutido no admin

- [ ] T001 — Testes RED: admin serve HTML com __TOKEN__ injetado
- [ ] T002 — backend/main.py: GET /admin injeta `<script>window.__TOKEN__="..."</script>` no HTML
- [ ] T003 — app.js: token() usa window.__TOKEN__ se disponivel
- [ ] T004 — admin.html: esconde campo de token quando __TOKEN__ presente
- [ ] T005 — dashboard: mesma logica quando acessado com sessao admin
- [ ] T006 — Testes GREEN: verificar que admin funciona sem colar token

**Checkpoint**: Admin funcional sem campo de token manual.

---

## Fase 2: Tabela client_users + CRUD

- [ ] T007 — schemas.sql: CREATE TABLE client_users
- [ ] T008 — db.py: create_client, get_client, update_client, delete_client, list_clients, authenticate_client
- [ ] T009 — Testes RED: CRUD de client_users
- [ ] T010 — main.py: endpoints CRUD (GET/POST/PATCH/DELETE /api/v1/clients)
- [ ] T011 — admin.html: secao de gerenciamento de clientes (listar, criar, editar, remover)
- [ ] T012 — admin.html: ao criar cliente, selecionar hostnames associados
- [ ] T013 — Testes GREEN: CRUD completo + hash de senha

**Checkpoint**: Admin pode criar/editar/remover usuarios clientes.

---

## Fase 3: Portal do cliente

- [ ] T014 — client-login.html: tela de login do cliente (mesma estetica do admin login)
- [ ] T015 — main.py: POST /client/login — autentica e seta cookie client_session
- [ ] T016 — main.py: GET /client — serve portal (protegido por cookie)
- [ ] T017 — main.py: GET /api/v1/client/data — dados filtrados por hostnames do user
- [ ] T018 — client.html: dashboard do cliente (CPU, RAM, DNS, alertas — filtrado)
- [ ] T019 — client.html: graficos Chart.js (reutiliza base.css + app.js)
- [ ] T020 — Testes: auth do cliente, filtragem de dados, acesso negado a outros hosts
- [ ] T021 — main.py: GET /client/logout — limpa cookie

**Checkpoint**: Cliente faz login e ve so seus dados.

---

## Fase 4: DNSTop (feature 011)

- [ ] T022 — agent.toml: secao [dnstop] com enabled, interval, interface, method
- [ ] T023 — dns_agent.py: collect_dnstop() — unbound-control stats / tcpdump
- [ ] T024 — dns_agent.py: integrar dnstop no heartbeat payload
- [ ] T025 — schemas.sql: tabela dnstop_snapshots (hypertable)
- [ ] T026 — db.py: insert_dnstop(), get_dnstop_latest()
- [ ] T027 — main.py: processar campo dnstop no receive_metrics
- [ ] T028 — main.py: GET /api/v1/client/dnstop — dados DNSTop filtrados
- [ ] T029 — client.html: graficos DNSTop (QPS, top domains, top clients, query types)
- [ ] T030 — Testes: coleta, envio, armazenamento, visualizacao

**Checkpoint**: Cliente ve DNS em tempo real no portal.

---

## Dependencias

```
T001-T006 (token embutido) → independente, pode comecar ja
T007-T013 (CRUD clientes)  → independente, pode ser paralelo com Fase 1
T014-T021 (portal)         → depende de Fase 2 (precisa da tabela client_users)
T022-T030 (DNSTop)         → depende de Fase 3 (precisa do portal)
```

## Estimativas

| Fase | Testes novos | Linhas estimadas |
|------|-------------|-----------------|
| 1 — Token embutido | ~5 | ~30 |
| 2 — CRUD clientes | ~12 | ~200 |
| 3 — Portal cliente | ~10 | ~400 (client.html + endpoints) |
| 4 — DNSTop | ~15 | ~350 (agent + backend + portal) |
| **Total** | **~42** | **~980** |
