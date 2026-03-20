"""
db.py — Camada de acesso ao TimescaleDB via asyncpg.
Fornece: pool de conexão, inicialização do schema e funções de inserção
para cada tabela definida em schemas.sql.
"""

import logging
import os
import re
from contextlib import asynccontextmanager
from typing import Optional

import asyncpg

logger = logging.getLogger("dns-monitor.db")

# Pool global — inicializado em startup, fechado em shutdown
_pool: Optional[asyncpg.Pool] = None


# ---------------------------------------------------------------------------
# Pool
# ---------------------------------------------------------------------------

async def init_pool() -> None:
    """Cria o pool de conexões. Chamado no startup do FastAPI."""
    global _pool
    dsn = os.environ["DATABASE_URL"]  # Obrigatório — falha rápido se ausente
    _pool = await asyncpg.create_pool(
        dsn,
        ssl=False,
        min_size=2,
        max_size=10,
        command_timeout=60,
        server_settings={"application_name": "dns-monitor-backend"},
    )
    logger.info("Pool de conexões criado (min=2 max=10)")


async def close_pool() -> None:
    """Fecha o pool de conexões. Chamado no shutdown do FastAPI."""
    global _pool
    if _pool:
        await _pool.close()
        logger.info("Pool de conexões fechado")


@asynccontextmanager
async def get_conn():
    """Context manager para obter uma conexão do pool."""
    async with _pool.acquire() as conn:
        yield conn


# ---------------------------------------------------------------------------
# Inicialização do schema
# ---------------------------------------------------------------------------

def _split_sql(sql: str) -> list[str]:
    """
    Divide o SQL em statements individuais.
    asyncpg não aceita múltiplos statements em uma única chamada execute().
    Remove comentários de linha e statements vazios.
    """
    # Remove comentários de linha (-- ...)
    sql_no_comments = re.sub(r'--[^\n]*', '', sql)
    # Divide por ';' e limpa
    statements = [s.strip() for s in sql_no_comments.split(';')]
    return [s for s in statements if s]


async def apply_schema() -> None:
    """
    Executa schemas.sql no banco statement a statement.
    Seguro para rodar a cada startup (usa IF NOT EXISTS / OR REPLACE).
    """
    schema_path = os.path.join(os.path.dirname(__file__), "schemas.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        sql = f.read()

    statements = _split_sql(sql)
    async with get_conn() as conn:
        for stmt in statements:
            try:
                await conn.execute(stmt)
            except Exception as exc:
                logger.error("Erro ao executar statement SQL: %s\n%s", exc, stmt[:200])
                raise
    logger.info("Schema aplicado com sucesso (%d statements)", len(statements))


# ---------------------------------------------------------------------------
# Registro de agentes
# ---------------------------------------------------------------------------

async def upsert_agent(hostname: str, last_seen_ts: str) -> None:
    """
    Garante que o agente está na tabela 'agents'.
    Atualiza last_seen a cada heartbeat/check recebido.
    """
    async with get_conn() as conn:
        await conn.execute(
            """
            INSERT INTO agents (hostname, registered_at, last_seen)
            VALUES ($1, $2::timestamptz, $2::timestamptz)
            ON CONFLICT (hostname) DO UPDATE
                SET last_seen = EXCLUDED.last_seen
            """,
            hostname, last_seen_ts,
        )


# ---------------------------------------------------------------------------
# Inserção de heartbeat
# ---------------------------------------------------------------------------

async def insert_heartbeat(hostname: str, ts: str, agent_version: Optional[str]) -> None:
    async with get_conn() as conn:
        await conn.execute(
            "INSERT INTO agent_heartbeats (ts, hostname, agent_version) VALUES ($1::timestamptz, $2, $3)",
            ts, hostname, agent_version,
        )


# ---------------------------------------------------------------------------
# Inserção de métricas do sistema
# ---------------------------------------------------------------------------

async def insert_metrics_cpu(hostname: str, ts: str, cpu: dict, load: dict) -> None:
    async with get_conn() as conn:
        await conn.execute(
            """
            INSERT INTO metrics_cpu
                (ts, hostname, cpu_percent, cpu_count, freq_mhz, load_1m, load_5m, load_15m)
            VALUES ($1::timestamptz, $2, $3, $4, $5, $6, $7, $8)
            """,
            ts, hostname,
            cpu.get("percent"),
            cpu.get("count"),
            cpu.get("freq_mhz"),
            load.get("load_1m"),
            load.get("load_5m"),
            load.get("load_15m"),
        )


async def insert_metrics_ram(hostname: str, ts: str, ram: dict) -> None:
    async with get_conn() as conn:
        await conn.execute(
            """
            INSERT INTO metrics_ram
                (ts, hostname, ram_percent, ram_used_mb, ram_total_mb,
                 swap_percent, swap_used_mb, swap_total_mb)
            VALUES ($1::timestamptz, $2, $3, $4, $5, $6, $7, $8)
            """,
            ts, hostname,
            ram.get("percent"),
            ram.get("used_mb"),
            ram.get("total_mb"),
            ram.get("swap_percent"),
            ram.get("swap_used_mb"),
            ram.get("swap_total_mb"),
        )


async def insert_metrics_disk(hostname: str, ts: str, disks: list) -> None:
    """Insere uma linha por partição. Campo 'alert' do payload → 'alert_level' na tabela."""
    if not disks:
        return
    async with get_conn() as conn:
        await conn.executemany(
            """
            INSERT INTO metrics_disk
                (ts, hostname, mountpoint, device, fstype,
                 disk_percent, used_gb, free_gb, total_gb, alert_level)
            VALUES ($1::timestamptz, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            """,
            [
                (
                    ts, hostname,
                    d.get("mountpoint"), d.get("device"), d.get("fstype"),
                    d.get("percent"), d.get("used_gb"), d.get("free_gb"),
                    d.get("total_gb"),
                    d.get("alert"),   # payload usa 'alert' → coluna 'alert_level'
                )
                for d in disks
            ],
        )


async def insert_metrics_io(hostname: str, ts: str, io: dict) -> None:
    if not io:
        return
    async with get_conn() as conn:
        await conn.execute(
            """
            INSERT INTO metrics_io
                (ts, hostname, read_bytes, write_bytes, read_count,
                 write_count, read_time_ms, write_time_ms)
            VALUES ($1::timestamptz, $2, $3, $4, $5, $6, $7, $8)
            """,
            ts, hostname,
            io.get("read_bytes"),   io.get("write_bytes"),
            io.get("read_count"),   io.get("write_count"),
            io.get("read_time_ms"), io.get("write_time_ms"),
        )


# ---------------------------------------------------------------------------
# Inserção de checks DNS
# ---------------------------------------------------------------------------

async def insert_dns_checks(hostname: str, ts: str, checks: list) -> None:
    """
    Insere uma linha por domínio testado.
    Campo 'error' do payload → coluna 'error_code' na tabela dns_checks.
    """
    if not checks:
        return
    async with get_conn() as conn:
        await conn.executemany(
            """
            INSERT INTO dns_checks
                (ts, hostname, domain, resolver, success,
                 latency_ms, response_ips, error_code, attempts)
            VALUES ($1::timestamptz, $2, $3, $4, $5, $6, $7, $8, $9)
            """,
            [
                (
                    ts, hostname,
                    c.get("domain"),
                    c.get("resolver"),
                    c.get("success", False),
                    c.get("latency_ms"),
                    c.get("response_ips") or [],
                    c.get("error"),        # payload usa 'error' → coluna 'error_code'
                    c.get("attempts"),
                )
                for c in checks
            ],
        )


async def insert_dns_service_status(hostname: str, ts: str, svc: dict) -> None:
    async with get_conn() as conn:
        await conn.execute(
            """
            INSERT INTO dns_service_status (ts, hostname, service_name, active, version)
            VALUES ($1::timestamptz, $2, $3, $4, $5)
            """,
            ts, hostname,
            svc.get("name"),
            svc.get("active"),
            svc.get("version"),
        )


# ---------------------------------------------------------------------------
# Alertas
# ---------------------------------------------------------------------------

async def insert_alert(
    hostname: str,
    alert_type: str,
    severity: str,
    message: str,
    metric_name: Optional[str] = None,
    metric_value: Optional[float] = None,
    threshold_value: Optional[float] = None,
) -> int:
    """Registra um alerta e retorna seu ID."""
    async with get_conn() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO alerts_log
                (hostname, alert_type, severity, message,
                 metric_name, metric_value, threshold_value)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
            """,
            hostname, alert_type, severity, message,
            metric_name, metric_value, threshold_value,
        )
        return row["id"]


async def mark_alert_notified(alert_id: int) -> None:
    async with get_conn() as conn:
        await conn.execute(
            "UPDATE alerts_log SET notified_telegram = TRUE WHERE id = $1",
            alert_id,
        )


async def resolve_alert(hostname: str, alert_type: str) -> None:
    """Marca alertas abertos desse tipo como resolvidos."""
    async with get_conn() as conn:
        await conn.execute(
            """
            UPDATE alerts_log
            SET resolved_at = NOW()
            WHERE hostname = $1
              AND alert_type = $2
              AND resolved_at IS NULL
            """,
            hostname, alert_type,
        )


# ---------------------------------------------------------------------------
# Queries para o scheduler de alertas
# ---------------------------------------------------------------------------

async def get_agents_offline(threshold_minutes: int = 10) -> list[dict]:
    """Retorna agentes que não mandaram heartbeat nos últimos N minutos."""
    async with get_conn() as conn:
        rows = await conn.fetch(
            """
            SELECT hostname, last_seen
            FROM agents
            WHERE active = TRUE
              AND (last_seen IS NULL OR last_seen < NOW() - ($1 * INTERVAL '1 minute'))
            ORDER BY hostname
            """,
            threshold_minutes,
        )
        return [dict(r) for r in rows]


async def get_latest_disk_alerts(hostname: str) -> list[dict]:
    """Retorna partições com alert_level != 'ok' na última leitura."""
    async with get_conn() as conn:
        rows = await conn.fetch(
            """
            SELECT DISTINCT ON (mountpoint)
                hostname, mountpoint, disk_percent, alert_level, ts
            FROM metrics_disk
            WHERE hostname = $1
            ORDER BY mountpoint, ts DESC
            """,
            hostname,
        )
        return [dict(r) for r in rows if r["alert_level"] != "ok"]


async def get_open_alerts(hostname: Optional[str] = None) -> list[dict]:
    """Retorna alertas ainda não resolvidos."""
    async with get_conn() as conn:
        if hostname:
            rows = await conn.fetch(
                "SELECT * FROM alerts_log WHERE hostname = $1 AND resolved_at IS NULL ORDER BY ts DESC",
                hostname,
            )
        else:
            rows = await conn.fetch(
                "SELECT * FROM alerts_log WHERE resolved_at IS NULL ORDER BY ts DESC LIMIT 200"
            )
        return [dict(r) for r in rows]


async def get_all_disk_alerts() -> list[dict]:
    """
    Retorna partições em alerta (warning ou critical) de TODOS os agentes
    em uma única query — substitui o loop N+1 em job_send_report.
    Usa DISTINCT ON para pegar apenas a leitura mais recente por (hostname, mountpoint).
    """
    async with get_conn() as conn:
        rows = await conn.fetch(
            """
            SELECT DISTINCT ON (hostname, mountpoint)
                hostname, mountpoint, disk_percent, alert_level, ts
            FROM metrics_disk
            WHERE alert_level IN ('warning', 'critical')
            ORDER BY hostname, mountpoint, ts DESC
            """
        )
        return [dict(r) for r in rows]


async def has_open_alert(hostname: str, alert_type: str) -> bool:
    """
    Verifica se já existe um alerta aberto do mesmo tipo para o host.
    Usado para deduplicação de warnings — evita inserções a cada heartbeat.
    """
    async with get_conn() as conn:
        row = await conn.fetchrow(
            """
            SELECT 1 FROM alerts_log
            WHERE hostname = $1
              AND alert_type = $2
              AND resolved_at IS NULL
            LIMIT 1
            """,
            hostname, alert_type,
        )
        return row is not None