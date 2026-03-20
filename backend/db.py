"""
db.py — Camada de acesso ao TimescaleDB via asyncpg.
"""

import logging
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import asyncpg

logger = logging.getLogger("dns-monitor.db")

_pool: Optional[asyncpg.Pool] = None


def _parse_ts(ts: str) -> datetime:
    """Converte ISO 8601 string para datetime. asyncpg exige datetime, não str."""
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


async def init_pool() -> None:
    global _pool
    dsn = os.environ["DATABASE_URL"]
    _pool = await asyncpg.create_pool(
        dsn, ssl=False, min_size=2, max_size=10, command_timeout=60,
        server_settings={"application_name": "dns-monitor-backend"},
    )
    logger.info("Pool de conexões criado (min=2 max=10)")


async def close_pool() -> None:
    global _pool
    if _pool:
        await _pool.close()
        logger.info("Pool de conexões fechado")


@asynccontextmanager
async def get_conn():
    async with _pool.acquire() as conn:
        yield conn


def _split_sql(sql: str) -> list[str]:
    sql_no_comments = re.sub(r'--[^\n]*', '', sql)
    statements = [s.strip() for s in sql_no_comments.split(';')]
    return [s for s in statements if s]


async def apply_schema() -> None:
    schema_path = os.path.join(os.path.dirname(__file__), "schemas.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        sql = f.read()
    statements = _split_sql(sql)
    async with get_conn() as conn:
        for stmt in statements:
            try:
                await conn.execute(stmt)
            except Exception as exc:
                logger.error("Erro SQL: %s\n%s", exc, stmt[:200])
                raise
    logger.info("Schema aplicado (%d statements)", len(statements))


async def upsert_agent(
    hostname: str,
    last_seen_ts: str,
    display_name: Optional[str] = None,
    location: Optional[str] = None,
    agent_version: Optional[str] = None,
) -> dict:
    """
    Registra ou atualiza o agente.
    Retorna {"is_new": True} se for o primeiro heartbeat deste hostname.
    Usado pelo backend para disparar alerta de novo agente detectado.
    """
    ts = _parse_ts(last_seen_ts)
    async with get_conn() as conn:
        # Verifica se já existe antes do upsert
        existing = await conn.fetchrow(
            "SELECT hostname, registered_at FROM agents WHERE hostname = $1",
            hostname,
        )
        is_new = existing is None

        await conn.execute(
            """
            INSERT INTO agents (hostname, registered_at, last_seen, display_name, location)
            VALUES ($1, $2, $2, $3, $4)
            ON CONFLICT (hostname) DO UPDATE SET
                last_seen    = EXCLUDED.last_seen,
                display_name = COALESCE(EXCLUDED.display_name, agents.display_name),
                location     = COALESCE(EXCLUDED.location,     agents.location)
            """,
            hostname, ts,
            display_name or None,
            location or None,
        )
    return {"is_new": is_new}


async def insert_heartbeat(hostname: str, ts: str, agent_version: Optional[str]) -> None:
    async with get_conn() as conn:
        await conn.execute(
            "INSERT INTO agent_heartbeats (ts, hostname, agent_version) VALUES ($1, $2, $3)",
            _parse_ts(ts), hostname, agent_version,
        )


async def insert_metrics_cpu(hostname: str, ts: str, cpu: dict, load: dict) -> None:
    async with get_conn() as conn:
        await conn.execute(
            """
            INSERT INTO metrics_cpu
                (ts, hostname, cpu_percent, cpu_count, freq_mhz, load_1m, load_5m, load_15m)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """,
            _parse_ts(ts), hostname,
            cpu.get("percent"), cpu.get("count"), cpu.get("freq_mhz"),
            load.get("load_1m"), load.get("load_5m"), load.get("load_15m"),
        )


async def insert_metrics_ram(hostname: str, ts: str, ram: dict) -> None:
    async with get_conn() as conn:
        await conn.execute(
            """
            INSERT INTO metrics_ram
                (ts, hostname, ram_percent, ram_used_mb, ram_total_mb,
                 swap_percent, swap_used_mb, swap_total_mb)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """,
            _parse_ts(ts), hostname,
            ram.get("percent"), ram.get("used_mb"), ram.get("total_mb"),
            ram.get("swap_percent"), ram.get("swap_used_mb"), ram.get("swap_total_mb"),
        )


async def insert_metrics_disk(hostname: str, ts: str, disks: list) -> None:
    if not disks:
        return
    ts_dt = _parse_ts(ts)
    async with get_conn() as conn:
        await conn.executemany(
            """
            INSERT INTO metrics_disk
                (ts, hostname, mountpoint, device, fstype,
                 disk_percent, used_gb, free_gb, total_gb, alert_level)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            """,
            [
                (
                    ts_dt, hostname,
                    d.get("mountpoint"), d.get("device"), d.get("fstype"),
                    d.get("percent"), d.get("used_gb"), d.get("free_gb"),
                    d.get("total_gb"), d.get("alert"),
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
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """,
            _parse_ts(ts), hostname,
            io.get("read_bytes"),   io.get("write_bytes"),
            io.get("read_count"),   io.get("write_count"),
            io.get("read_time_ms"), io.get("write_time_ms"),
        )


async def insert_dns_checks(hostname: str, ts: str, checks: list) -> None:
    if not checks:
        return
    ts_dt = _parse_ts(ts)
    async with get_conn() as conn:
        await conn.executemany(
            """
            INSERT INTO dns_checks
                (ts, hostname, domain, resolver, success,
                 latency_ms, response_ips, error_code, attempts)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """,
            [
                (
                    ts_dt, hostname,
                    c.get("domain"), c.get("resolver"),
                    c.get("success", False), c.get("latency_ms"),
                    c.get("response_ips") or [], c.get("error"), c.get("attempts"),
                )
                for c in checks
            ],
        )


async def insert_dns_service_status(hostname: str, ts: str, svc: dict) -> None:
    async with get_conn() as conn:
        await conn.execute(
            """
            INSERT INTO dns_service_status (ts, hostname, service_name, active, version)
            VALUES ($1, $2, $3, $4, $5)
            """,
            _parse_ts(ts), hostname,
            svc.get("name"), svc.get("active"), svc.get("version"),
        )


async def insert_alert(
    hostname: str, alert_type: str, severity: str, message: str,
    metric_name: Optional[str] = None, metric_value: Optional[float] = None,
    threshold_value: Optional[float] = None,
) -> int:
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
            "UPDATE alerts_log SET notified_telegram = TRUE WHERE id = $1", alert_id,
        )


async def resolve_alert(hostname: str, alert_type: str) -> None:
    async with get_conn() as conn:
        await conn.execute(
            """
            UPDATE alerts_log SET resolved_at = NOW()
            WHERE hostname = $1 AND alert_type = $2 AND resolved_at IS NULL
            """,
            hostname, alert_type,
        )


async def get_agents_offline(threshold_minutes: int = 10) -> list[dict]:
    async with get_conn() as conn:
        rows = await conn.fetch(
            """
            SELECT hostname, last_seen FROM agents
            WHERE active = TRUE
              AND (last_seen IS NULL OR last_seen < NOW() - ($1 * INTERVAL '1 minute'))
            ORDER BY hostname
            """,
            threshold_minutes,
        )
        return [dict(r) for r in rows]


async def get_all_disk_alerts() -> list[dict]:
    """1 query para todos os agentes — sem N+1."""
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


async def get_latest_disk_alerts(hostname: str) -> list[dict]:
    async with get_conn() as conn:
        rows = await conn.fetch(
            """
            SELECT DISTINCT ON (mountpoint)
                hostname, mountpoint, disk_percent, alert_level, ts
            FROM metrics_disk WHERE hostname = $1
            ORDER BY mountpoint, ts DESC
            """,
            hostname,
        )
        return [dict(r) for r in rows if r["alert_level"] != "ok"]


async def has_open_alert(hostname: str, alert_type: str) -> bool:
    async with get_conn() as conn:
        row = await conn.fetchrow(
            """
            SELECT 1 FROM alerts_log
            WHERE hostname = $1 AND alert_type = $2 AND resolved_at IS NULL
            LIMIT 1
            """,
            hostname, alert_type,
        )
        return row is not None


async def get_open_alerts(hostname: Optional[str] = None) -> list[dict]:
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


# ---------------------------------------------------------------------------
# Fingerprint — identificação de hardware do agente
# ---------------------------------------------------------------------------

async def upsert_fingerprint(hostname: str, fingerprint: str) -> dict:
    """
    Registra ou atualiza o fingerprint do agente.
    Retorna dict com 'is_new' e 'changed' para o backend decidir se alerta.
    """
    async with get_conn() as conn:
        row = await conn.fetchrow(
            "SELECT fingerprint, fingerprint_first_seen FROM agents WHERE hostname = $1",
            hostname,
        )
        if row is None:
            return {"is_new": True, "changed": False}

        existing = row["fingerprint"]
        first_seen = row["fingerprint_first_seen"]

        if existing is None:
            # Primeiro registro do fingerprint
            await conn.execute(
                """
                UPDATE agents
                SET fingerprint            = $1,
                    fingerprint_first_seen = NOW(),
                    fingerprint_last_seen  = NOW()
                WHERE hostname = $2
                """,
                fingerprint, hostname,
            )
            return {"is_new": False, "changed": False}

        if existing != fingerprint:
            # Fingerprint mudou — possível cópia ou migração de hardware
            await conn.execute(
                "UPDATE agents SET fingerprint_last_seen = NOW() WHERE hostname = $1",
                hostname,
            )
            return {"is_new": False, "changed": True, "previous": existing}

        # Fingerprint igual — só atualiza last_seen
        await conn.execute(
            "UPDATE agents SET fingerprint_last_seen = NOW() WHERE hostname = $1",
            hostname,
        )
        return {"is_new": False, "changed": False}


# ---------------------------------------------------------------------------
# Comandos remotos
# ---------------------------------------------------------------------------

VALID_COMMANDS = {"stop", "disable", "enable", "purge"}


async def get_pending_commands(hostname: str) -> list[dict]:
    """
    Retorna comandos pendentes para o hostname.
    Marca como 'expired' os que passaram do expires_at.
    """
    async with get_conn() as conn:
        # Expirar comandos vencidos antes de retornar
        await conn.execute(
            """
            UPDATE agent_commands
            SET status = 'expired'
            WHERE hostname  = $1
              AND status    = 'pending'
              AND expires_at IS NOT NULL
              AND expires_at < NOW()
            """,
            hostname,
        )
        rows = await conn.fetch(
            """
            SELECT id, command, confirm_token, issued_at
            FROM agent_commands
            WHERE hostname = $1
              AND status   = 'pending'
            ORDER BY issued_at ASC
            """,
            hostname,
        )
        return [dict(r) for r in rows]


async def mark_command_done(
    command_id: int,
    status: str,
    result: str,
) -> None:
    """Atualiza o status do comando após execução pelo agente."""
    async with get_conn() as conn:
        await conn.execute(
            """
            UPDATE agent_commands
            SET status      = $1,
                result      = $2,
                executed_at = NOW()
            WHERE id = $3
            """,
            status, result, command_id,
        )


async def insert_command(
    hostname: str,
    command: str,
    issued_by: str = "admin",
    confirm_token: str = None,
    expires_hours: int = None,
) -> int:
    """Insere um novo comando para o agente executar. Retorna o ID."""
    if command not in VALID_COMMANDS:
        raise ValueError(f"Comando inválido: {command}. Válidos: {VALID_COMMANDS}")
    if command == "purge" and not confirm_token:
        raise ValueError("purge exige confirm_token")

    async with get_conn() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO agent_commands
                (hostname, command, issued_by, confirm_token, expires_at)
            VALUES ($1, $2, $3, $4,
                    CASE WHEN $5::int IS NULL THEN NULL
                         ELSE NOW() + ($5 * INTERVAL '1 hour')
                    END)
            RETURNING id
            """,
            hostname, command, issued_by, confirm_token, expires_hours,
        )
        return row["id"]


async def get_command_by_id(command_id: int):
    """Retorna dados de um comando pelo ID — hostname, command, issued_by."""
    async with get_conn() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, hostname, command, issued_by, status, result, executed_at
            FROM agent_commands
            WHERE id = $1
            """,
            command_id,
        )
        return dict(row) if row else None


async def get_commands_history(hostname: str, limit: int = 50) -> list[dict]:
    """Retorna histórico de comandos de um host."""
    async with get_conn() as conn:
        rows = await conn.fetch(
            """
            SELECT id, command, issued_by, issued_at, executed_at, status, result
            FROM agent_commands
            WHERE hostname = $1
            ORDER BY issued_at DESC
            LIMIT $2
            """,
            hostname, limit,
        )
        return [dict(r) for r in rows]