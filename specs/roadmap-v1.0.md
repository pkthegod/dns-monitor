# Roadmap — DNS Monitor v1.0

**Foco**: UX/UI do portal do cliente, relatorios, documentacao
**Escopo**: 50-100 agentes DNS, Docker Compose
**Meta**: produto entregavel pra clientes com self-service

---

## Sprint 1 — Portal do Cliente (UX)

**Objetivo**: cliente abre o portal e entende a saude do DNS em 5 segundos

### 1.1 Status hero — card principal

Substituir os 4 KPIs por um card hero:

```
┌─────────────────────────────────────────────────┐
│  🟢 DNS Saudavel                                │
│  Uptime: 99.98%  |  Latencia: 45ms  |  0 alertas│
│  Ultimo check: 32s atras                         │
└─────────────────────────────────────────────────┘
```

- Verde/amarelo/vermelho com base em regras
- Uptime calculado dos ultimos 30 dias
- Latencia media do periodo selecionado
- Contagem de alertas abertos

### 1.2 Botao "Testar meu DNS" (self-service)

O cliente clica e roda um teste DNS sob demanda:
- Resolve 3 dominios de teste (google.com, cloudflare.com, dominio do cliente)
- Mostra resultado em tempo real: OK/FAIL + latencia
- Nao precisa esperar o proximo check agendado
- Rate limit: 1 teste a cada 60s por cliente

### 1.3 Simplificar graficos

- **Manter**: DNS latencia (o que o cliente mais entende)
- **Simplificar**: CPU/RAM → "Carga do servidor: Baixa/Media/Alta" (gauge)
- **Adicionar**: Timeline de disponibilidade (barra verde/vermelha por hora)
- **Remover**: bar chart de dominios (confuso pro cliente)

### 1.4 Explicacoes contextuais

- Tooltip em cada metrica: "Latencia DNS: tempo que seu servidor leva pra responder consultas. Abaixo de 50ms e excelente."
- Alertas com "O que fazer": "DNS timeout detectado → Seu servidor DNS nao respondeu em 5s. Se persistir, contate o suporte."

---

## Sprint 2 — Relatorios

**Objetivo**: cliente recebe relatorio mensal automatico

### 2.1 Relatorio mensal (endpoint + PDF)

`GET /api/v1/client/report?month=2026-04`

Retorna JSON (e gera PDF):
- Uptime % do mes
- Latencia media/max/p95
- Total de queries (se dnstop ativo)
- Alertas do mes (quantos, tipos, duracao)
- Comparativo com mes anterior
- Grafico de tendencia

### 2.2 Email automatico

- Backend envia relatorio por email no dia 1 de cada mes
- Template HTML estilizado (mesma paleta Tokyo Night)
- Configuravel: ativar/desativar por cliente

### 2.3 SLA dashboard

Card no portal do cliente:

```
┌─────────────────────────────────────────┐
│  SLA — Abril 2026                       │
│  Meta: 99.9%  |  Real: 99.98%  ✓        │
│  Downtime: 8min  |  Incidentes: 1       │
│  ████████████████████████████░░  99.98%  │
└─────────────────────────────────────────┘
```

---

## Sprint 3 — UX Admin

**Objetivo**: admin gerencia 50+ agentes sem fricao

### 3.1 Busca e filtros na tabela de agentes

- Search box: filtra por hostname em tempo real
- Filtro por status: Online / Offline / Stale
- Sort por coluna: click no header
- Contagem: "Mostrando 12 de 50 agentes"

### 3.2 Linhas coloridas na tabela

- Borda esquerda verde (online), amarela (stale), vermelha (offline)
- Linha inteira levemente colorida pra agentes criticos

### 3.3 Bulk actions

- Checkbox em cada agente
- Botao "Selecionar todos offline"
- Acoes em lote: restart, update_agent, decommission

### 3.4 CRUD de clientes no admin panel

- Secao dedicada: listar/criar/editar/remover clientes
- Associar hostnames a cada cliente (multi-select)
- Ver portal como cliente (preview)

---

## Sprint 4 — Documentacao

**Objetivo**: user guide completo pra cliente e admin

### 4.1 Guia do portal do cliente

Pagina acessivel em `/client/help`:
- Como ler os graficos
- O que significam os alertas
- Como rodar teste DNS
- Como ler o relatorio mensal
- FAQ: "Meu DNS esta lento?" / "O que e latencia?" / "Quando devo ligar pro suporte?"

### 4.2 Guia do admin

Pagina em `/admin/help`:
- Como adicionar agente novo
- Como criar cliente
- Como rodar diagnostico
- Como fazer decommission
- Comandos disponiveis
- Troubleshooting

### 4.3 API docs

- OpenAPI schema customizado (ja tem FastAPI /docs)
- Exemplos curl pra cada endpoint
- Autenticacao explicada

---

## Sprint 5 — Polish e Escalabilidade (roadmap futuro)

### 5.1 Docker Swarm (quando > 100 agentes)
- Separar backend API de scheduler
- NATS cluster (3 nodes)
- TimescaleDB com replicas

### 5.2 Mobile responsive
- Dashboard adaptavel pra tablet/mobile
- Touch targets maiores
- Cards colapsaveis

### 5.3 Integracao webhook
- Alertas pra Slack/Teams/PagerDuty
- Webhook customizavel por cliente

---

## Ordem de implementacao

```
Sprint 1 (UX Cliente)  ────── agora
  │  1.1 Status hero
  │  1.2 Testar meu DNS
  │  1.3 Simplificar graficos
  │  1.4 Tooltips
  │
Sprint 2 (Relatorios)  ────── proximo
  │  2.1 Relatorio mensal JSON/PDF
  │  2.2 Email automatico
  │  2.3 SLA dashboard
  │
Sprint 3 (UX Admin)    ────── depois
  │  3.1 Busca e filtros
  │  3.2 Linhas coloridas
  │  3.3 Bulk actions
  │  3.4 CRUD clientes visual
  │
Sprint 4 (Docs)        ────── paralelo com Sprint 2-3
  │  4.1 Guia cliente
  │  4.2 Guia admin
  │  4.3 API docs
  │
Sprint 5 (Escala)      ────── roadmap futuro
     5.1 Swarm
     5.2 Mobile
     5.3 Webhooks
```

## Estimativas

| Sprint | Testes novos | Linhas | Impacto |
|--------|-------------|--------|---------|
| 1 — UX Cliente | ~15 | ~600 | Alto (diferencial) |
| 2 — Relatorios | ~10 | ~500 | Alto (retencao) |
| 3 — UX Admin | ~8 | ~300 | Medio (eficiencia) |
| 4 — Docs | ~0 | ~400 (markdown) | Alto (onboarding) |
| 5 — Escala | ~10 | ~400 | Baixo (futuro) |
