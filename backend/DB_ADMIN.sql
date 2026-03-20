-- =============================================================================
-- DNS Monitor — Guia de Administração do Banco de Dados
--
-- Acesso:
--   docker exec -it dns_monitor_db psql -U dnsmonitor -d dns_monitor
--
-- Todas as tabelas de métricas são hypertables TimescaleDB (PostgreSQL 15).
-- Não há foreign keys entre métricas e agents — exclusões são independentes.
-- =============================================================================


-- =============================================================================
-- 1. VISÃO GERAL
-- =============================================================================

-- Listar todas as tabelas e tamanho em disco
SELECT
    hypertable_name                          AS tabela,
    pg_size_pretty(hypertable_size(hypertable_name::regclass)) AS tamanho
FROM timescaledb_information.hypertables
UNION ALL
SELECT tablename, pg_size_pretty(pg_total_relation_size(tablename::regclass))
FROM pg_tables
WHERE tablename IN ('agents', 'alerts_log')
  AND schemaname = 'public'
ORDER BY tabela;

-- Contar registros por tabela
SELECT 'agent_heartbeats'  AS tabela, COUNT(*) AS registros FROM agent_heartbeats
UNION ALL
SELECT 'metrics_cpu',                  COUNT(*) FROM metrics_cpu
UNION ALL
SELECT 'metrics_ram',                  COUNT(*) FROM metrics_ram
UNION ALL
SELECT 'metrics_disk',                 COUNT(*) FROM metrics_disk
UNION ALL
SELECT 'metrics_io',                   COUNT(*) FROM metrics_io
UNION ALL
SELECT 'dns_checks',                   COUNT(*) FROM dns_checks
UNION ALL
SELECT 'dns_service_status',           COUNT(*) FROM dns_service_status
UNION ALL
SELECT 'alerts_log',                   COUNT(*) FROM alerts_log
UNION ALL
SELECT 'agents',                       COUNT(*) FROM agents
ORDER BY tabela;

-- Período coberto pelos dados (primeiro e último registro por tabela)
SELECT 'metrics_cpu'  AS tabela, MIN(ts) AS primeiro, MAX(ts) AS ultimo FROM metrics_cpu
UNION ALL
SELECT 'dns_checks',              MIN(ts),             MAX(ts)           FROM dns_checks
UNION ALL
SELECT 'agent_heartbeats',        MIN(ts),             MAX(ts)           FROM agent_heartbeats
ORDER BY tabela;


-- =============================================================================
-- 2. AGENTES — CONSULTAS E METADADOS
-- =============================================================================

-- Status atual de todos os agentes (view consolida última leitura de cada host)
SELECT
    hostname,
    display_name,
    location,
    agent_status,
    cpu_percent,
    ram_percent,
    dns_service_name,
    dns_service_active,
    last_seen
FROM v_agent_current_status
ORDER BY hostname;

-- Todos os campos da tabela agents (incluindo dns_service esperado e notes)
SELECT
    hostname,
    display_name,
    location,
    dns_service,
    active,
    registered_at,
    last_seen,
    notes
FROM agents
ORDER BY hostname;

-- Agentes que não enviaram heartbeat nos últimos 15 minutos
SELECT hostname, last_seen,
       EXTRACT(EPOCH FROM (NOW() - last_seen)) / 60 AS minutos_sem_sinal
FROM agents
WHERE last_seen < NOW() - INTERVAL '15 minutes'
   OR last_seen IS NULL
ORDER BY last_seen ASC NULLS FIRST;


-- =============================================================================
-- 3. AGENTES — ATUALIZAR METADADOS
-- =============================================================================

-- Preencher nome de exibição, localização e serviço DNS esperado
UPDATE agents SET
    display_name = 'Nome Legível da Máquina',
    location     = 'Rack / Datacenter / Cidade',
    dns_service  = 'unbound',   -- ou 'bind9'
    notes        = 'Observações livres'
WHERE hostname = 'HOSTNAME_AQUI';

-- Desativar agente sem apagar histórico (não aparece mais no Grafana)
UPDATE agents SET active = FALSE WHERE hostname = 'HOSTNAME_AQUI';

-- Reativar
UPDATE agents SET active = TRUE WHERE hostname = 'HOSTNAME_AQUI';


-- =============================================================================
-- 4. AGENTES — RENOMEAR HOSTNAME (merge de registros)
--
-- Use quando o hostname mudou na máquina e o banco tem dois registros
-- para o mesmo host físico. Migra todo o histórico para o novo nome.
-- =============================================================================

-- Passo 1: confirmar os dois registros antes de agir
SELECT hostname, display_name, last_seen, agent_status
FROM v_agent_current_status
WHERE hostname IN ('HOSTNAME_ANTIGO', 'HOSTNAME_NOVO');

-- Passo 2: migrar todo o histórico para o novo hostname
UPDATE agent_heartbeats   SET hostname = 'HOSTNAME_NOVO' WHERE hostname = 'HOSTNAME_ANTIGO';
UPDATE metrics_cpu        SET hostname = 'HOSTNAME_NOVO' WHERE hostname = 'HOSTNAME_ANTIGO';
UPDATE metrics_ram        SET hostname = 'HOSTNAME_NOVO' WHERE hostname = 'HOSTNAME_ANTIGO';
UPDATE metrics_disk       SET hostname = 'HOSTNAME_NOVO' WHERE hostname = 'HOSTNAME_ANTIGO';
UPDATE metrics_io         SET hostname = 'HOSTNAME_NOVO' WHERE hostname = 'HOSTNAME_ANTIGO';
UPDATE dns_checks         SET hostname = 'HOSTNAME_NOVO' WHERE hostname = 'HOSTNAME_ANTIGO';
UPDATE dns_service_status SET hostname = 'HOSTNAME_NOVO' WHERE hostname = 'HOSTNAME_ANTIGO';
UPDATE alerts_log         SET hostname = 'HOSTNAME_NOVO' WHERE hostname = 'HOSTNAME_ANTIGO';

-- Passo 3: remover o registro antigo da tabela de agentes
DELETE FROM agents WHERE hostname = 'HOSTNAME_ANTIGO';

-- Passo 4: confirmar resultado
SELECT hostname, display_name, last_seen FROM agents ORDER BY hostname;


-- =============================================================================
-- 5. AGENTES — EXCLUIR HOST COMPLETAMENTE
--
-- Remove o agente e todo o histórico de métricas associado.
-- Irreversível — não há soft delete para métricas.
-- =============================================================================

DELETE FROM agent_heartbeats   WHERE hostname = 'HOSTNAME_AQUI';
DELETE FROM metrics_cpu        WHERE hostname = 'HOSTNAME_AQUI';
DELETE FROM metrics_ram        WHERE hostname = 'HOSTNAME_AQUI';
DELETE FROM metrics_disk       WHERE hostname = 'HOSTNAME_AQUI';
DELETE FROM metrics_io         WHERE hostname = 'HOSTNAME_AQUI';
DELETE FROM dns_checks         WHERE hostname = 'HOSTNAME_AQUI';
DELETE FROM dns_service_status WHERE hostname = 'HOSTNAME_AQUI';
DELETE FROM alerts_log         WHERE hostname = 'HOSTNAME_AQUI';
DELETE FROM agents             WHERE hostname = 'HOSTNAME_AQUI';

-- Confirmar
SELECT hostname FROM agents ORDER BY hostname;


-- =============================================================================
-- 6. ALERTAS — CONSULTAS
-- =============================================================================

-- Alertas abertos (não resolvidos)
SELECT
    ts AT TIME ZONE 'America/Sao_Paulo' AS horario,
    hostname,
    alert_type,
    severity,
    message,
    metric_value,
    threshold_value
FROM alerts_log
WHERE resolved_at IS NULL
ORDER BY ts DESC;

-- Histórico completo de alertas dos últimos 7 dias
SELECT
    ts AT TIME ZONE 'America/Sao_Paulo' AS horario,
    hostname,
    alert_type,
    severity,
    message,
    resolved_at
FROM alerts_log
WHERE ts > NOW() - INTERVAL '7 days'
ORDER BY ts DESC;

-- Alertas por host — contagem no último mês
SELECT
    hostname,
    alert_type,
    severity,
    COUNT(*) AS total
FROM alerts_log
WHERE ts > NOW() - INTERVAL '30 days'
GROUP BY hostname, alert_type, severity
ORDER BY total DESC;


-- =============================================================================
-- 7. ALERTAS — MANUTENÇÃO
-- =============================================================================

-- Resolver alerta manualmente (quando o problema foi corrigido fora do sistema)
UPDATE alerts_log
SET resolved_at = NOW()
WHERE hostname   = 'HOSTNAME_AQUI'
  AND alert_type = 'cpu'           -- cpu | ram | disk | dns_fail | dns_latency | offline
  AND resolved_at IS NULL;

-- Apagar alertas antigos resolvidos (limpeza manual além da retenção automática)
DELETE FROM alerts_log
WHERE resolved_at IS NOT NULL
  AND resolved_at < NOW() - INTERVAL '90 days';

-- Apagar todos os alertas de um host (ex: após excluir o agente)
DELETE FROM alerts_log WHERE hostname = 'HOSTNAME_AQUI';


-- =============================================================================
-- 8. MÉTRICAS — CONSULTAS OPERACIONAIS
-- =============================================================================

-- Últimas leituras de CPU de um host
SELECT
    ts AT TIME ZONE 'America/Sao_Paulo' AS horario,
    cpu_percent,
    load_1m,
    load_5m,
    load_15m
FROM metrics_cpu
WHERE hostname = 'HOSTNAME_AQUI'
ORDER BY ts DESC
LIMIT 20;

-- Média de CPU por hora nas últimas 24h
SELECT
    time_bucket('1 hour', ts) AT TIME ZONE 'America/Sao_Paulo' AS hora,
    hostname,
    ROUND(AVG(cpu_percent)::numeric, 1) AS cpu_media_pct
FROM metrics_cpu
WHERE hostname  = 'HOSTNAME_AQUI'
  AND ts > NOW() - INTERVAL '24 hours'
GROUP BY 1, 2
ORDER BY 1 DESC;

-- Partições de disco em alerta agora
SELECT DISTINCT ON (hostname, mountpoint)
    hostname,
    mountpoint,
    disk_percent,
    alert_level,
    ts AT TIME ZONE 'America/Sao_Paulo' AS ultima_leitura
FROM metrics_disk
WHERE alert_level IN ('warning', 'critical')
ORDER BY hostname, mountpoint, ts DESC;

-- Falhas DNS das últimas 24h
SELECT
    ts AT TIME ZONE 'America/Sao_Paulo' AS horario,
    hostname,
    domain,
    error_code,
    attempts
FROM dns_checks
WHERE success = FALSE
  AND ts > NOW() - INTERVAL '24 hours'
ORDER BY ts DESC;

-- Taxa de sucesso DNS por host na última hora
SELECT
    hostname,
    COUNT(*)                                          AS total_checks,
    SUM(CASE WHEN success THEN 1 ELSE 0 END)          AS sucessos,
    ROUND(100.0 * SUM(CASE WHEN success THEN 1 ELSE 0 END) / COUNT(*), 1) AS taxa_sucesso_pct
FROM dns_checks
WHERE ts > NOW() - INTERVAL '1 hour'
GROUP BY hostname
ORDER BY taxa_sucesso_pct ASC;

-- Latência DNS média por domínio na última hora
SELECT
    domain,
    ROUND(AVG(latency_ms)::numeric, 1) AS latencia_media_ms,
    MAX(latency_ms)                    AS latencia_maxima_ms,
    COUNT(*)                           AS amostras
FROM dns_checks
WHERE success = TRUE
  AND ts > NOW() - INTERVAL '1 hour'
GROUP BY domain
ORDER BY latencia_media_ms DESC;


-- =============================================================================
-- 9. TIMESCALEDB — ADMINISTRAÇÃO
-- =============================================================================

-- Políticas de retenção configuradas
--   agent_heartbeats  → 30 dias
--   metrics_cpu       → 1 ano
--   metrics_ram       → 1 ano
--   metrics_disk      → 1 ano
--   metrics_io        → 1 ano
--   dns_checks        → 1 ano
--   dns_service_status→ 1 ano

-- Ver políticas ativas
SELECT hypertable_name, config
FROM timescaledb_information.jobs
WHERE proc_name IN ('policy_retention', 'policy_compression')
ORDER BY hypertable_name;

-- Alterar retenção de uma tabela (ex: guardar cpu por 2 anos)
SELECT alter_job(
    (SELECT job_id FROM timescaledb_information.jobs
     WHERE proc_name = 'policy_retention'
       AND hypertable_name = 'metrics_cpu'),
    config => '{"drop_after": "2 years"}'::jsonb
);

-- Forçar compressão imediata de chunks antigos (normalmente automático após 7 dias)
SELECT compress_chunk(c.chunk_schema || '.' || c.chunk_name)
FROM timescaledb_information.chunks c
WHERE c.hypertable_name = 'metrics_cpu'
  AND c.range_end < NOW() - INTERVAL '7 days'
  AND NOT c.is_compressed;

-- Ver chunks por tabela (comprimidos vs não comprimidos)
SELECT
    hypertable_name,
    COUNT(*) FILTER (WHERE is_compressed)     AS chunks_comprimidos,
    COUNT(*) FILTER (WHERE NOT is_compressed) AS chunks_abertos,
    COUNT(*)                                  AS total_chunks
FROM timescaledb_information.chunks
GROUP BY hypertable_name
ORDER BY hypertable_name;

-- Espaço economizado pela compressão
SELECT
    hypertable_name,
    pg_size_pretty(before_compression_total_bytes) AS antes,
    pg_size_pretty(after_compression_total_bytes)  AS depois,
    ROUND(100.0 - 100.0 * after_compression_total_bytes
          / NULLIF(before_compression_total_bytes, 0), 1) AS reducao_pct
FROM chunk_compression_stats(NULL::text)
ORDER BY before_compression_total_bytes DESC NULLS LAST;


-- =============================================================================
-- 10. COMANDOS REMOTOS
-- =============================================================================

-- Listar todos os comandos pendentes (todos os hosts)
SELECT
    id,
    hostname,
    command,
    issued_by,
    issued_at AT TIME ZONE 'America/Sao_Paulo' AS emitido_em,
    expires_at AT TIME ZONE 'America/Sao_Paulo' AS expira_em,
    status
FROM agent_commands
WHERE status = 'pending'
ORDER BY issued_at ASC;

-- Histórico completo de comandos de um host
SELECT
    id,
    command,
    issued_by,
    issued_at   AT TIME ZONE 'America/Sao_Paulo' AS emitido_em,
    executed_at AT TIME ZONE 'America/Sao_Paulo' AS executado_em,
    status,
    result
FROM agent_commands
WHERE hostname = 'HOSTNAME_AQUI'
ORDER BY issued_at DESC
LIMIT 20;

-- Emitir comando stop (para o serviço DNS imediatamente)
INSERT INTO agent_commands (hostname, command, issued_by)
VALUES ('HOSTNAME_AQUI', 'stop', 'admin');

-- Emitir comando disable (para e desabilita no boot)
INSERT INTO agent_commands (hostname, command, issued_by)
VALUES ('HOSTNAME_AQUI', 'disable', 'admin');

-- Emitir comando enable (reativa e inicia — use após stop ou disable)
INSERT INTO agent_commands (hostname, command, issued_by)
VALUES ('HOSTNAME_AQUI', 'enable', 'admin');

-- Emitir comando purge (remove o pacote — IRREVERSÍVEL)
-- confirm_token é obrigatório — use qualquer string, o agente valida presença
INSERT INTO agent_commands (hostname, command, issued_by, confirm_token)
VALUES ('HOSTNAME_AQUI', 'purge', 'admin', 'token-confirmacao-aqui');

-- Emitir comando com expiração (expira se não executado em N horas)
INSERT INTO agent_commands (hostname, command, issued_by, expires_at)
VALUES ('HOSTNAME_AQUI', 'stop', 'admin', NOW() + INTERVAL '24 hours');

-- Cancelar comando pendente (antes do agente executar)
UPDATE agent_commands
SET status = 'expired'
WHERE id = 999
  AND status = 'pending';

-- Ver fingerprint registrado de cada agente
-- fingerprint_first_seen: primeiro registro — hardware original
-- fingerprint_last_seen:  última vez que o fingerprint foi enviado
-- Se fingerprint mudou, o backend gera WARNING nos logs
SELECT
    hostname,
    fingerprint,
    fingerprint_first_seen AT TIME ZONE 'America/Sao_Paulo' AS registrado_em,
    fingerprint_last_seen  AT TIME ZONE 'America/Sao_Paulo' AS visto_por_ultimo
FROM agents
ORDER BY hostname;

-- Redefinir fingerprint (após troca de hardware legítima)
UPDATE agents
SET fingerprint            = NULL,
    fingerprint_first_seen = NULL,
    fingerprint_last_seen  = NULL
WHERE hostname = 'HOSTNAME_AQUI';
-- O próximo heartbeat do agente registrará o novo fingerprint automaticamente

-- Estatísticas de comandos por status
SELECT
    hostname,
    command,
    status,
    COUNT(*) AS total
FROM agent_commands
GROUP BY hostname, command, status
ORDER BY hostname, command, status;
