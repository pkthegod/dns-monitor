# Feature 013 — Relatorio Diario (DNS Health Report)

**Status**: planejado (pos-v1.0)
**Prioridade**: alta — diferencial para clientes e troubleshooting admin

---

## Objetivo

Gerar automaticamente um PDF diario com metricas + teste de resolucao DNS real, armazenar no banco, e disponibilizar para admin e cliente.

## Motivacao

- Cliente quer evidencia de que o DNS funciona — relatorio diario e prova concreta
- Admin precisa de historico rapido quando cliente suspeita de problema
- Elimina necessidade de investigar banco manualmente

## Arquitetura

```
Scheduler (APScheduler, 23:59)
  |
  +-- Para cada cliente ativo:
  |     +-- Coleta metricas do dia dos hostnames do cliente (do banco)
  |     +-- Dispara teste DNS real via NATS (run_script dig_test)
  |     +-- Aguarda resultado (timeout 60s)
  |     +-- Gera PDF com dados agregados + resultado do teste
  |     +-- Armazena na tabela daily_reports (id, date, client_id, pdf_bytes)
  |     +-- Opcionalmente envia por email/Telegram
  |
  +-- Gera relatorio admin consolidado (todos os hosts)
```

## Tabela

```sql
CREATE TABLE IF NOT EXISTS daily_reports (
    id          SERIAL PRIMARY KEY,
    report_date DATE NOT NULL,
    client_id   INTEGER REFERENCES client_users(id) ON DELETE CASCADE,
    hostname    TEXT,          -- NULL = relatorio consolidado do cliente
    pdf_data    BYTEA NOT NULL,
    generated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (report_date, client_id)
);
```

## Endpoints

| Metodo | Rota | Auth | Descricao |
|--------|------|------|-----------|
| GET | `/api/v1/client/reports` | cookie cliente | Lista relatorios disponiveis do cliente logado |
| GET | `/api/v1/client/reports/{date}` | cookie cliente | Download PDF do dia (YYYY-MM-DD) |
| GET | `/api/v1/reports` | Bearer token | Admin: lista todos (filtro ?client_id=&date=) |
| GET | `/api/v1/reports/{date}/{client_id}` | Bearer token | Admin: download PDF de qualquer cliente |
| POST | `/api/v1/reports/generate` | Bearer token | Admin: forca geracao manual de um relatorio |

## Conteudo do PDF

| Secao | Conteudo |
|-------|----------|
| Header | Data, cliente, hosts monitorados |
| Disponibilidade | Uptime %, downtime minutos, heartbeats recebidos/esperados |
| Latencia DNS | Media, max, p95 do dia |
| Teste de resolucao | Resultado do dig_test real: dominios, latencia, sucesso/falha |
| Alertas do dia | Lista com horario, tipo, severidade, mensagem |
| Metricas do sistema | CPU/RAM pico e media do dia |
| Comparativo | Tendencia vs dia anterior (melhor/pior/estavel) |
| Footer | Gerado em, DNS Monitor |

## UI

### Portal do cliente
- Nova secao "Relatorios" abaixo do SLA
- Tabela: Data | Status | Acao (Baixar PDF)
- Ultimos 30 dias

### Admin
- Secao "Relatorios" ou filtro na secao de clientes
- Dropdown de cliente + calendario
- Botao "Gerar agora" para relatorio sob demanda

## Dependencias

- reportlab (ja instalado)
- NATS para disparo do dig_test (fallback: usa dados do ultimo check)
- Tabela daily_reports no schemas.sql

## Estimativa

| Componente | Complexidade |
|------------|-------------|
| Tabela + db.py | Baixa |
| Job scheduler | Media |
| PDF (expandir _build_report_pdf) | Media |
| Endpoints listagem/download | Baixa |
| UI portal do cliente | Baixa |
| UI admin | Baixa |
| Total | ~2-3 sessoes |
