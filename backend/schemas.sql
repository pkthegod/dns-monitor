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

-- Migracao: campo email (ADD COLUMN IF NOT EXISTS e idempotente)
ALTER TABLE client_users ADD COLUMN IF NOT EXISTS email TEXT;