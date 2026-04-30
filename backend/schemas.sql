-- =============================================================================
-- dns-monitor: schemas.sql
-- Cria todas as tabelas a partir do contrato de dados definido pelo agente.
-- Execute como superusuário (postgres) ou usuário com CREATE privileges.
-- =============================================================================

-- Extensão TimescaleDB (necessária antes de qualquer hypertable)
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- =============================================================================
-- 1. HEARTBEATS
-- Sinal de vida enviado pelo agente a cada 5 min (payload type="heartbeat").
-- Usado pelo backend para detectar agentes offline.
-- Chunk pequeno (1h) pois o volume é alto e as queries são sempre recentes.
-- =============================================================================
CREATE TABLE IF NOT EXISTS agent_heartbeats (
    ts          TIMESTAMPTZ     NOT NULL,
    hostname    TEXT            NOT NULL,
    agent_version TEXT
);

SELECT create_hypertable(
    'agent_heartbeats', 'ts',
    chunk_time_interval => INTERVAL '1 hour',
    if_not_exists       => TRUE
);

CREATE INDEX IF NOT EXISTS idx_hb_hostname_ts
    ON agent_heartbeats (hostname, ts DESC);

-- Retenção: 30 dias são suficientes para calcular uptime e detectar offline
SELECT add_retention_policy('agent_heartbeats', INTERVAL '30 days', if_not_exists => TRUE);

-- =============================================================================
-- 2. MÉTRICAS DO SISTEMA
-- Enviadas em todo ciclo (check) e heartbeat.
-- Uma linha por agente por envio — normalizado por tipo de recurso.
-- =============================================================================

-- CPU (payload: system.cpu)
CREATE TABLE IF NOT EXISTS metrics_cpu (
    ts              TIMESTAMPTZ NOT NULL,
    hostname        TEXT        NOT NULL,
    cpu_percent     NUMERIC(5,1),
    cpu_count       SMALLINT,
    freq_mhz        NUMERIC(8,1),
    load_1m         NUMERIC(6,2),
    load_5m         NUMERIC(6,2),
    load_15m        NUMERIC(6,2)
);

SELECT create_hypertable(
    'metrics_cpu', 'ts',
    chunk_time_interval => INTERVAL '6 hours',
    if_not_exists       => TRUE
);

CREATE INDEX IF NOT EXISTS idx_cpu_hostname_ts
    ON metrics_cpu (hostname, ts DESC);

SELECT add_retention_policy('metrics_cpu', INTERVAL '1 year', if_not_exists => TRUE);


-- RAM (payload: system.ram)
CREATE TABLE IF NOT EXISTS metrics_ram (
    ts              TIMESTAMPTZ NOT NULL,
    hostname        TEXT        NOT NULL,
    ram_percent     NUMERIC(5,1),
    ram_used_mb     NUMERIC(10,1),
    ram_total_mb    NUMERIC(10,1),
    swap_percent    NUMERIC(5,1),
    swap_used_mb    NUMERIC(10,1),
    swap_total_mb   NUMERIC(10,1)
);

SELECT create_hypertable(
    'metrics_ram', 'ts',
    chunk_time_interval => INTERVAL '6 hours',
    if_not_exists       => TRUE
);

CREATE INDEX IF NOT EXISTS idx_ram_hostname_ts
    ON metrics_ram (hostname, ts DESC);

SELECT add_retention_policy('metrics_ram', INTERVAL '1 year', if_not_exists => TRUE);


-- Disco (payload: system.disk[] — uma linha por mountpoint por envio)
CREATE TABLE IF NOT EXISTS metrics_disk (
    ts              TIMESTAMPTZ NOT NULL,
    hostname        TEXT        NOT NULL,
    mountpoint      TEXT        NOT NULL,
    device          TEXT,
    fstype          TEXT,
    disk_percent    NUMERIC(5,1),
    used_gb         NUMERIC(10,2),
    free_gb         NUMERIC(10,2),
    total_gb        NUMERIC(10,2),
    alert_level     TEXT        -- 'ok' | 'warning' | 'critical'
);

SELECT create_hypertable(
    'metrics_disk', 'ts',
    chunk_time_interval => INTERVAL '6 hours',
    if_not_exists       => TRUE
);

CREATE INDEX IF NOT EXISTS idx_disk_hostname_ts
    ON metrics_disk (hostname, ts DESC);
CREATE INDEX IF NOT EXISTS idx_disk_hostname_mount
    ON metrics_disk (hostname, mountpoint, ts DESC);

SELECT add_retention_policy('metrics_disk', INTERVAL '1 year', if_not_exists => TRUE);


-- I/O de disco (payload: system.io — contadores acumulados desde o boot)
CREATE TABLE IF NOT EXISTS metrics_io (
    ts              TIMESTAMPTZ NOT NULL,
    hostname        TEXT        NOT NULL,
    read_bytes      BIGINT,
    write_bytes     BIGINT,
    read_count      BIGINT,
    write_count     BIGINT,
    read_time_ms    BIGINT,
    write_time_ms   BIGINT
);

SELECT create_hypertable(
    'metrics_io', 'ts',
    chunk_time_interval => INTERVAL '6 hours',
    if_not_exists       => TRUE
);

CREATE INDEX IF NOT EXISTS idx_io_hostname_ts
    ON metrics_io (hostname, ts DESC);

SELECT add_retention_policy('metrics_io', INTERVAL '1 year', if_not_exists => TRUE);


-- =============================================================================
-- 3. CHECKS DNS
-- Resultado de cada teste de resolução (payload: dns_checks[]).
-- Uma linha por domínio por ciclo por agente.
-- Chunk de 1 dia: 4 checks/dia × 50 agentes × N domínios = volume controlado.
-- =============================================================================
CREATE TABLE IF NOT EXISTS dns_checks (
    ts              TIMESTAMPTZ NOT NULL,
    hostname        TEXT        NOT NULL,
    domain          TEXT        NOT NULL,
    resolver        TEXT,           -- IP do resolver consultado ou 'system'
    success         BOOLEAN     NOT NULL,
    latency_ms      NUMERIC(8,2),   -- NULL em caso de falha
    response_ips    TEXT[],         -- IPs retornados (array)
    error_code      TEXT,           -- 'TIMEOUT' | 'NXDOMAIN' | 'NO_NAMESERVERS' | NULL
    attempts        SMALLINT
);

SELECT create_hypertable(
    'dns_checks', 'ts',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists       => TRUE
);

CREATE INDEX IF NOT EXISTS idx_dns_hostname_ts
    ON dns_checks (hostname, ts DESC);
CREATE INDEX IF NOT EXISTS idx_dns_domain_ts
    ON dns_checks (domain, ts DESC);
CREATE INDEX IF NOT EXISTS idx_dns_success
    ON dns_checks (success, ts DESC);

SELECT add_retention_policy('dns_checks', INTERVAL '1 year', if_not_exists => TRUE);


-- =============================================================================
-- 4. STATUS DO SERVIÇO DNS
-- Detectado em cada envio (payload: dns_service).
-- Registra se unbound/bind9 estava ativo no momento da coleta.
-- =============================================================================
CREATE TABLE IF NOT EXISTS dns_service_status (
    ts              TIMESTAMPTZ NOT NULL,
    hostname        TEXT        NOT NULL,
    service_name    TEXT,           -- 'unbound' | 'bind9' | 'named' | 'unknown'
    active          BOOLEAN,
    version         TEXT
);

SELECT create_hypertable(
    'dns_service_status', 'ts',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists       => TRUE
);

CREATE INDEX IF NOT EXISTS idx_dns_svc_hostname_ts
    ON dns_service_status (hostname, ts DESC);

SELECT add_retention_policy('dns_service_status', INTERVAL '1 year', if_not_exists => TRUE);


-- =============================================================================
-- 5. ALERTAS GERADOS
-- Histórico de alertas disparados pelo backend (para auditoria e dashboard).
-- Não é hypertable — volume baixo, mas precisa de timestamp para ordenação.
-- =============================================================================
CREATE TABLE IF NOT EXISTS alerts_log (
    id              BIGSERIAL   PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hostname        TEXT        NOT NULL,
    alert_type      TEXT        NOT NULL, -- 'dns_fail' | 'dns_latency' | 'cpu' | 'ram' | 'disk' | 'offline'
    severity        TEXT        NOT NULL, -- 'warning' | 'critical'
    metric_name     TEXT,
    metric_value    NUMERIC,
    threshold_value NUMERIC,
    message         TEXT,
    resolved_at     TIMESTAMPTZ,
    notified_telegram BOOLEAN   DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_alerts_hostname_ts
    ON alerts_log (hostname, ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_unresolved
    ON alerts_log (resolved_at) WHERE resolved_at IS NULL;

-- A1 (v1.5 race-fix R6): dedupe defensivo de rows abertas antes de criar o
-- UNIQUE partial index. Bancos com historico pre-migration podem ter
-- duplicatas geradas pelo race antigo (has_open_alert + insert separados);
-- sem este DELETE, o CREATE UNIQUE INDEX falharia e travaria o startup.
-- Idempotente: sem duplicatas, e no-op. Mantem o ID mais antigo de cada
-- (hostname, alert_type, severity) aberto, descartando duplicatas mais novas.
DELETE FROM alerts_log a
USING alerts_log b
WHERE a.id > b.id
  AND a.hostname = b.hostname
  AND a.alert_type = b.alert_type
  AND a.severity = b.severity
  AND a.resolved_at IS NULL
  AND b.resolved_at IS NULL;

-- Unique partial index pra suportar INSERT ... ON CONFLICT DO NOTHING.
-- Severity faz parte da chave: warning pode escalar pra critical sem o
-- warning ter sido resolvido (visto em prod: CPU 81% gera warning, sobe
-- pra 96% gera critical antes do operador resolver o warning).
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_open_unique
    ON alerts_log (hostname, alert_type, severity)
    WHERE resolved_at IS NULL;


-- =============================================================================
-- 6. REGISTRO DE AGENTES CONHECIDOS
-- Tabela de controle: cadastro de todos os hostnames esperados.
-- O backend usa isso para detectar agentes que nunca enviaram heartbeat.
-- =============================================================================
CREATE TABLE IF NOT EXISTS agents (
    hostname        TEXT        PRIMARY KEY,
    display_name    TEXT,
    location        TEXT,           -- Localização/rack/datacenter (livre)
    dns_service     TEXT,           -- Serviço DNS esperado: 'unbound' | 'bind9'
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ,
    active          BOOLEAN     NOT NULL DEFAULT TRUE,
    notes           TEXT
);


-- Colunas adicionadas após criação inicial da tabela agents
ALTER TABLE agents ADD COLUMN IF NOT EXISTS inactive_since        TIMESTAMPTZ;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS fingerprint           TEXT;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS fingerprint_first_seen TIMESTAMPTZ;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS fingerprint_last_seen  TIMESTAMPTZ;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS agent_version         TEXT;
-- Intervalo de coleta de stats DNS (rndc-stats / unbound-control). Default 600s (10min).
-- Configuravel no painel admin per-agente. Agente le no startup e a cada heartbeat.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS dns_stats_interval_seconds INTEGER NOT NULL DEFAULT 600;

CREATE INDEX IF NOT EXISTS idx_agents_fingerprint ON agents (fingerprint);

-- =============================================================================
-- 7. VIEW: STATUS ATUAL DOS AGENTES (última leitura de cada hostname)
-- Usada pelo Grafana no painel de visão geral.
-- =============================================================================
DROP VIEW IF EXISTS v_agent_current_status;
CREATE VIEW v_agent_current_status AS
SELECT
    a.hostname,
    a.display_name,
    a.location,
    a.active,
    a.inactive_since,
    a.notes,
    a.dns_service          AS expected_dns_service,
    a.last_seen,
    a.agent_version,
    CASE
        WHEN a.last_seen IS NULL                              THEN 'never_seen'
        WHEN a.last_seen < NOW() - INTERVAL '15 minutes'     THEN 'offline'
        WHEN a.last_seen < NOW() - INTERVAL '10 minutes'     THEN 'stale'
        ELSE                                                       'online'
    END                    AS agent_status,
    cpu.cpu_percent,
    ram.ram_percent,
    dns_svc.service_name   AS dns_service_name,
    dns_svc.active         AS dns_service_active
FROM agents a
LEFT JOIN LATERAL (
    SELECT cpu_percent FROM metrics_cpu
    WHERE hostname = a.hostname
    ORDER BY ts DESC LIMIT 1
) cpu ON TRUE
LEFT JOIN LATERAL (
    SELECT ram_percent FROM metrics_ram
    WHERE hostname = a.hostname
    ORDER BY ts DESC LIMIT 1
) ram ON TRUE
LEFT JOIN LATERAL (
    SELECT service_name, active FROM dns_service_status
    WHERE hostname = a.hostname
    ORDER BY ts DESC LIMIT 1
) dns_svc ON TRUE;


-- =============================================================================
-- Compressão automática (TimescaleDB) após 7 dias
-- Reduz tamanho em disco ~90% para dados históricos
-- =============================================================================
ALTER TABLE metrics_cpu           SET (timescaledb.compress, timescaledb.compress_segmentby = 'hostname');
ALTER TABLE metrics_ram           SET (timescaledb.compress, timescaledb.compress_segmentby = 'hostname');
ALTER TABLE metrics_disk          SET (timescaledb.compress, timescaledb.compress_segmentby = 'hostname');
ALTER TABLE metrics_io            SET (timescaledb.compress, timescaledb.compress_segmentby = 'hostname');
ALTER TABLE dns_checks            SET (timescaledb.compress, timescaledb.compress_segmentby = 'hostname');
ALTER TABLE dns_service_status    SET (timescaledb.compress, timescaledb.compress_segmentby = 'hostname');
ALTER TABLE agent_heartbeats      SET (timescaledb.compress, timescaledb.compress_segmentby = 'hostname');

SELECT add_compression_policy('metrics_cpu',        INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('metrics_ram',        INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('metrics_disk',       INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('metrics_io',         INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('dns_checks',         INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('dns_service_status', INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('agent_heartbeats',   INTERVAL '7 days', if_not_exists => TRUE);


-- =============================================================================
-- 8. FINGERPRINT E COMANDOS REMOTOS
-- =============================================================================


-- Tabela de comandos remotos
-- O servidor insere, o agente consulta a cada poll e executa
CREATE TABLE IF NOT EXISTS agent_commands (
    id              BIGSERIAL       PRIMARY KEY,
    hostname        TEXT            NOT NULL,
    command         TEXT            NOT NULL,   -- 'stop'|'disable'|'enable'|'purge'
    issued_by       TEXT,                       -- identificação de quem emitiu
    issued_at       TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,               -- NULL = não expira
    confirm_token   TEXT,                      -- obrigatório para 'purge'
    executed_at     TIMESTAMPTZ,
    status          TEXT            NOT NULL DEFAULT 'pending',
                                               -- 'pending'|'done'|'failed'|'expired'
    result          TEXT                       -- saída do comando ou mensagem de erro
);

ALTER TABLE agent_commands ADD COLUMN IF NOT EXISTS params TEXT;
-- Anti-dup notificacao Telegram: marca quando comando foi notificado.
-- post_command_result (HTTP) e handle_command_ack (NATS) checam essa coluna
-- via UPDATE...WHERE notified_at IS NULL RETURNING id. So o primeiro caller
-- envia telegram; segundo (redundante) e silenciado.
ALTER TABLE agent_commands ADD COLUMN IF NOT EXISTS notified_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_cmd_hostname_status
    ON agent_commands (hostname, status)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_cmd_issued_at
    ON agent_commands (issued_at DESC);

-- ===========================================================================
-- CONTINUOUS AGGREGATES — agrega dados históricos por hora
-- Reduz disco em ~90% para dados com mais de 7 dias
-- Atualiza automaticamente a cada 1h via política
-- ===========================================================================

-- CPU agregado por hora
CREATE MATERIALIZED VIEW IF NOT EXISTS metrics_cpu_1h
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', ts) AS bucket,
    hostname,
    ROUND(AVG(cpu_percent)::numeric, 1)  AS cpu_avg,
    ROUND(MAX(cpu_percent)::numeric, 1)  AS cpu_max,
    ROUND(AVG(load_1m)::numeric, 2)      AS load_avg
FROM metrics_cpu
GROUP BY bucket, hostname
WITH NO DATA;

SELECT add_continuous_aggregate_policy('metrics_cpu_1h',
    start_offset => INTERVAL '3 days',
    end_offset   => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE);

-- RAM agregado por hora
CREATE MATERIALIZED VIEW IF NOT EXISTS metrics_ram_1h
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', ts) AS bucket,
    hostname,
    ROUND(AVG(ram_percent)::numeric, 1)  AS ram_avg,
    ROUND(MAX(ram_percent)::numeric, 1)  AS ram_max,
    ROUND(AVG(swap_percent)::numeric, 1) AS swap_avg
FROM metrics_ram
GROUP BY bucket, hostname
WITH NO DATA;

SELECT add_continuous_aggregate_policy('metrics_ram_1h',
    start_offset => INTERVAL '3 days',
    end_offset   => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE);

-- DNS latência agregada por hora
CREATE MATERIALIZED VIEW IF NOT EXISTS dns_checks_1h
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', ts) AS bucket,
    hostname,
    domain,
    ROUND(AVG(latency_ms)::numeric, 1)   AS latency_avg,
    ROUND(MAX(latency_ms)::numeric, 1)   AS latency_max,
    COUNT(*)                              AS total_checks,
    SUM(CASE WHEN success THEN 0 ELSE 1 END) AS failures
FROM dns_checks
GROUP BY bucket, hostname, domain
WITH NO DATA;

SELECT add_continuous_aggregate_policy('dns_checks_1h',
    start_offset => INTERVAL '3 days',
    end_offset   => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE);


-- ===========================================================================
-- 9. USUARIOS CLIENTES (portal read-only por hostname)
-- ===========================================================================
-- ===========================================================================
-- 10. AUDIT LOG — registro de acoes administrativas
-- ===========================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id         BIGSERIAL    PRIMARY KEY,
    ts         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    actor      TEXT         NOT NULL,
    action     TEXT         NOT NULL,
    target     TEXT,
    detail     TEXT,
    ip         TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log (ts DESC);

-- C2 (v1.5 audit): hash chain immutable. prev_hash referencia row_hash da
-- linha anterior; row_hash = SHA-256 do conteudo + prev_hash. Adulteracao
-- de qualquer campo invalida a recomputacao em verify_audit_chain.
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS row_hash  TEXT;


CREATE TABLE IF NOT EXISTS client_users (
    id            SERIAL       PRIMARY KEY,
    username      TEXT         NOT NULL UNIQUE,
    password_hash TEXT         NOT NULL,
    hostnames     TEXT[]       NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    active        BOOLEAN      NOT NULL DEFAULT TRUE,
    notes         TEXT,
    email         TEXT
);

-- Migracoes (ADD COLUMN IF NOT EXISTS e idempotente)
ALTER TABLE client_users ADD COLUMN IF NOT EXISTS email TEXT;
ALTER TABLE client_users ADD COLUMN IF NOT EXISTS webhook_url TEXT;


-- =============================================================================
-- ADMIN USERS — multi-user RBAC (admin / viewer)
-- =============================================================================
CREATE TABLE IF NOT EXISTS admin_users (
    id            SERIAL       PRIMARY KEY,
    username      TEXT         NOT NULL UNIQUE,
    password_hash TEXT         NOT NULL,
    role          TEXT         NOT NULL DEFAULT 'viewer'
                               CHECK (role IN ('admin', 'viewer')),
    active        BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by    TEXT,
    notes         TEXT
);


-- =============================================================================
-- DAILY REPORTS — relatorios diarios gerados automaticamente
-- =============================================================================
CREATE TABLE IF NOT EXISTS daily_reports (
    id            SERIAL       PRIMARY KEY,
    report_date   DATE         NOT NULL,
    client_id     INTEGER      REFERENCES client_users(id) ON DELETE CASCADE,
    pdf_data      BYTEA        NOT NULL,
    generated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (report_date, client_id)
);

CREATE INDEX IF NOT EXISTS idx_daily_reports_client ON daily_reports (client_id, report_date DESC);


-- =============================================================================
-- SPEEDTEST — Domain SSL/Port checker (medidores)
-- =============================================================================

CREATE TABLE IF NOT EXISTS speedtest_scans (
    id              BIGSERIAL    PRIMARY KEY,
    ts              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    total_domains   INTEGER      NOT NULL DEFAULT 0,
    reachable       INTEGER      NOT NULL DEFAULT 0,
    unreachable     INTEGER      NOT NULL DEFAULT 0,
    ssl_valid       INTEGER      NOT NULL DEFAULT 0,
    ssl_invalid     INTEGER      NOT NULL DEFAULT 0,
    ssl_expired     INTEGER      NOT NULL DEFAULT 0,
    expiring_soon   INTEGER      NOT NULL DEFAULT 0,
    avg_response_ms NUMERIC(8,2),
    scan_duration_s NUMERIC(8,2),
    errors_count    INTEGER      NOT NULL DEFAULT 0,
    timeouts_count  INTEGER      NOT NULL DEFAULT 0,
    source          TEXT
);

CREATE INDEX IF NOT EXISTS idx_speedtest_scans_ts ON speedtest_scans (ts DESC);

CREATE TABLE IF NOT EXISTS speedtest_domains (
    ts                  TIMESTAMPTZ  NOT NULL,
    scan_id             BIGINT       NOT NULL,
    domain              TEXT         NOT NULL,
    port                INTEGER      DEFAULT 8080,
    reachable           BOOLEAN,
    ssl_enabled         BOOLEAN,
    certificate_valid   BOOLEAN,
    certificate_expired BOOLEAN,
    days_until_expiry   INTEGER,
    expiry_date         TEXT,
    issuer              TEXT,
    subject             TEXT,
    tls_version         TEXT,
    cipher_suite        TEXT,
    response_time_ms    NUMERIC(8,2),
    error_message       TEXT
);

SELECT create_hypertable(
    'speedtest_domains', 'ts',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists       => TRUE
);

CREATE INDEX IF NOT EXISTS idx_speedtest_domains_scan
    ON speedtest_domains (scan_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_speedtest_domains_domain
    ON speedtest_domains (domain, ts DESC);

SELECT add_retention_policy('speedtest_domains', INTERVAL '1 year', if_not_exists => TRUE);

ALTER TABLE speedtest_domains SET (timescaledb.compress, timescaledb.compress_segmentby = 'domain');
SELECT add_compression_policy('speedtest_domains', INTERVAL '7 days', if_not_exists => TRUE);


-- ============================================================================
-- DNS Query Stats — coleta periodica de RCODEs/tipos/QPS via rndc-stats
-- (Bind9) e unbound-control stats (Unbound). Agente computa delta sobre
-- counters cumulativos e publica via NATS subject dns.stats.<hostname>.
-- ============================================================================

CREATE TABLE IF NOT EXISTS dns_query_stats (
    ts             TIMESTAMPTZ  NOT NULL,
    hostname       TEXT         NOT NULL,
    period_seconds INTEGER      NOT NULL,
    source         TEXT         NOT NULL,            -- 'bind9' | 'unbound'

    -- RCODEs (delta sobre o periodo)
    noerror        BIGINT       NOT NULL DEFAULT 0,
    nxdomain       BIGINT       NOT NULL DEFAULT 0,
    servfail       BIGINT       NOT NULL DEFAULT 0,
    refused        BIGINT       NOT NULL DEFAULT 0,
    notimpl        BIGINT       NOT NULL DEFAULT 0,
    formerr        BIGINT       NOT NULL DEFAULT 0,
    other_rcode    BIGINT       NOT NULL DEFAULT 0,

    -- Query types (delta)
    queries_a      BIGINT       NOT NULL DEFAULT 0,
    queries_aaaa   BIGINT       NOT NULL DEFAULT 0,
    queries_mx     BIGINT       NOT NULL DEFAULT 0,
    queries_ptr    BIGINT       NOT NULL DEFAULT 0,
    queries_other  BIGINT       NOT NULL DEFAULT 0,

    queries_total  BIGINT       NOT NULL DEFAULT 0,
    qps_avg        NUMERIC(10,2),

    -- Unbound only (NULL pra Bind9)
    cache_hits     BIGINT,
    cache_misses   BIGINT,
    cache_hit_pct  NUMERIC(5,2)
);

SELECT create_hypertable('dns_query_stats', 'ts',
    chunk_time_interval => INTERVAL '7 days', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_dns_stats_host_ts ON dns_query_stats (hostname, ts DESC);

ALTER TABLE dns_query_stats SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'hostname',
    timescaledb.compress_orderby   = 'ts DESC'
);
SELECT add_compression_policy('dns_query_stats', INTERVAL '30 days', if_not_exists => TRUE);
SELECT add_retention_policy('dns_query_stats', INTERVAL '365 days', if_not_exists => TRUE);

-- Continuous aggregate por hora — usado em dashboards de periodo longo
CREATE MATERIALIZED VIEW IF NOT EXISTS dns_stats_hourly
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', ts) AS hour,
    hostname,
    SUM(noerror)  AS noerror,
    SUM(nxdomain) AS nxdomain,
    SUM(servfail) AS servfail,
    SUM(refused)  AS refused,
    SUM(notimpl)  AS notimpl,
    SUM(formerr)  AS formerr,
    SUM(queries_a)     AS queries_a,
    SUM(queries_aaaa)  AS queries_aaaa,
    SUM(queries_mx)    AS queries_mx,
    SUM(queries_ptr)   AS queries_ptr,
    SUM(queries_other) AS queries_other,
    SUM(queries_total) AS queries_total,
    AVG(qps_avg)       AS qps_avg,
    AVG(cache_hit_pct) AS cache_hit_pct
FROM dns_query_stats
GROUP BY hour, hostname
WITH NO DATA;

SELECT add_continuous_aggregate_policy('dns_stats_hourly',
    start_offset      => INTERVAL '3 days',
    end_offset        => INTERVAL '1 hour',
    schedule_interval => INTERVAL '30 minutes',
    if_not_exists     => TRUE);