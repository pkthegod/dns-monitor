"""
db.py — Camada de acesso ao TimescaleDB via asyncpg.

Secoes (cada uma marcada por bloco `# === Nome ===` no corpo;
use grep '^# ===' para navegar):

    Pool / schema
    Agents — registro e heartbeat
    Metrics — cpu / ram / disk / io
    DNS checks
    DNS Query Stats — RCODEs/QPS via rndc/unbound
    Alerts
    Agent admin & alert queries
    Fingerprint — identificacao de hardware
    Comandos remotos
    Client users — portal read-only
    Admin users — multi-user RBAC
    Audit log
    Daily Reports
    Dashboard / Client — queries agregadas
    Speedtest — Domain SSL/Port checker
"""

import hashlib
import logging
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import asyncpg

import db_observability as _obs

logger = logging.getLogger("infra-vision.db")


class _TrackedConn:
    """Proxy de asyncpg.Connection que registra cada query no _query_tracker
    do request atual. Fora de request scope (ex: scheduler_jobs, init) o
    tracker e None — record_query e no-op, custo zero.

    Cobre os 5 metodos usados em db.py + routes_*.py + scheduler_jobs.py:
    execute, executemany, fetch, fetchrow, fetchval. Tudo o mais (transaction,
    cursor, etc) e delegado via __getattr__.
    """

    __slots__ = ("_conn",)

    def __init__(self, conn):
        self._conn = conn

    async def execute(self, query, *args, **kwargs):
        _obs.record_query(query)
        return await self._conn.execute(query, *args, **kwargs)

    async def executemany(self, query, *args, **kwargs):
        _obs.record_query(query)
        return await self._conn.executemany(query, *args, **kwargs)

    async def fetch(self, query, *args, **kwargs):
        _obs.record_query(query)
        return await self._conn.fetch(query, *args, **kwargs)

    async def fetchrow(self, query, *args, **kwargs):
        _obs.record_query(query)
        return await self._conn.fetchrow(query, *args, **kwargs)

    async def fetchval(self, query, *args, **kwargs):
        _obs.record_query(query)
        return await self._conn.fetchval(query, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._conn, name)

_pool: Optional[asyncpg.Pool] = None


# ===========================================================================
# Pool / schema
# ===========================================================================

def _parse_ts(ts: str) -> datetime:
    """Converte ISO 8601 string para datetime. asyncpg exige datetime, não str."""
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


async def init_pool() -> None:
    global _pool
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL environment variable is required")
    # SSL: 'require' em prod, 'disable' para dev/docker local
    ssl_mode = os.environ.get("DB_SSL", "disable")
    ssl_param = ssl_mode if ssl_mode in ("require", "prefer", "verify-full") else False
    _pool = await asyncpg.create_pool(
        dsn, ssl=ssl_param, min_size=2, max_size=10, command_timeout=60,
        server_settings={"application_name": "infra-vision-backend"},
    )
    logger.info("Pool de conexoes criado (min=2 max=10 ssl=%s)", ssl_mode)


async def close_pool() -> None:
    global _pool
    if _pool:
        await _pool.close()
        logger.info("Pool de conexões fechado")


@asynccontextmanager
async def get_conn():
    async with _pool.acquire() as conn:
        yield _TrackedConn(conn)


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


# ===========================================================================
# Agents — registro e heartbeat
# ===========================================================================

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

    A3 (R7 race-fix): is_new vinha de SELECT separado do INSERT — duas
    transacoes, race entre 2 heartbeats simultaneos do mesmo hostname
    perdia detecao de novo agente. Agora usamos `xmax = 0` no RETURNING:
    em Postgres, xmax=0 significa "linha foi inserida agora" (vs xmax!=0
    que indica UPDATE). Atomic em uma unica statement.
    """
    ts = _parse_ts(last_seen_ts)
    async with get_conn() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO agents (hostname, registered_at, last_seen, display_name, location, agent_version)
            VALUES ($1, $2, $2, $3, $4, $5)
            ON CONFLICT (hostname) DO UPDATE SET
                last_seen     = EXCLUDED.last_seen,
                display_name  = COALESCE(EXCLUDED.display_name,  agents.display_name),
                location      = COALESCE(EXCLUDED.location,      agents.location),
                agent_version = COALESCE(EXCLUDED.agent_version, agents.agent_version)
            RETURNING (xmax = 0) AS is_new
            """,
            hostname, ts,
            display_name or None,
            location or None,
            agent_version or None,
        )
    return {"is_new": bool(row["is_new"])}


async def insert_heartbeat(hostname: str, ts: str, agent_version: Optional[str]) -> None:
    async with get_conn() as conn:
        await conn.execute(
            "INSERT INTO agent_heartbeats (ts, hostname, agent_version) VALUES ($1, $2, $3)",
            _parse_ts(ts), hostname, agent_version,
        )


# ===========================================================================
# Metrics — cpu / ram / disk / io
# ===========================================================================

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


# ===========================================================================
# DNS checks
# ===========================================================================

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


# ===========================================================================
# DNS Query Stats — RCODEs/tipos/QPS/cache via rndc-stats e unbound-control
# ===========================================================================

async def insert_dns_query_stats(hostname: str, data: dict) -> None:
    """Persiste 1 amostra de stats DNS. data vem do agente via NATS.

    Chaves esperadas (todos os contadores sao deltas sobre period_seconds):
      ts, period_seconds, source ('bind9'|'unbound'),
      noerror, nxdomain, servfail, refused, notimpl, formerr, other_rcode,
      queries_a, queries_aaaa, queries_mx, queries_ptr, queries_other,
      queries_total, qps_avg,
      cache_hits, cache_misses, cache_hit_pct  (NULL pra Bind)
    """
    ts = data.get("ts")
    ts_dt = _parse_ts(ts) if ts else datetime.now(timezone.utc)
    async with get_conn() as conn:
        await conn.execute(
            """
            INSERT INTO dns_query_stats (
                ts, hostname, period_seconds, source,
                noerror, nxdomain, servfail, refused, notimpl, formerr, other_rcode,
                queries_a, queries_aaaa, queries_mx, queries_ptr, queries_other,
                queries_total, qps_avg,
                cache_hits, cache_misses, cache_hit_pct
            ) VALUES (
                $1, $2, $3, $4,
                $5, $6, $7, $8, $9, $10, $11,
                $12, $13, $14, $15, $16,
                $17, $18,
                $19, $20, $21
            )
            """,
            ts_dt, hostname,
            int(data.get("period_seconds", 600)),
            str(data.get("source", "unknown")),
            int(data.get("noerror", 0)),
            int(data.get("nxdomain", 0)),
            int(data.get("servfail", 0)),
            int(data.get("refused", 0)),
            int(data.get("notimpl", 0)),
            int(data.get("formerr", 0)),
            int(data.get("other_rcode", 0)),
            int(data.get("queries_a", 0)),
            int(data.get("queries_aaaa", 0)),
            int(data.get("queries_mx", 0)),
            int(data.get("queries_ptr", 0)),
            int(data.get("queries_other", 0)),
            int(data.get("queries_total", 0)),
            data.get("qps_avg"),
            data.get("cache_hits"),
            data.get("cache_misses"),
            data.get("cache_hit_pct"),
        )


async def get_dns_query_stats(
    hostname: Optional[str] = None,
    hostnames: Optional[list[str]] = None,
    period: str = "24h",
) -> list[dict]:
    """Retorna serie temporal de stats DNS.

    Decide entre tabela raw (periodos curtos) e continuous aggregate
    dns_stats_hourly (periodos longos) automaticamente. hostnames filtra
    multi-tenant; hostname filtra um so. Sem nenhum dos dois = todos.
    """
    period_intervals = {
        "1h": ("1 hour", "raw"),
        "6h": ("6 hours", "raw"),
        "24h": ("24 hours", "raw"),
        "7d": ("7 days", "hourly"),
        "30d": ("30 days", "hourly"),
        "90d": ("90 days", "hourly"),
    }
    interval, source_tbl = period_intervals.get(period, ("24 hours", "raw"))

    where_clauses = []
    params: list = []
    if hostname:
        params.append(hostname)
        where_clauses.append(f"hostname = ${len(params)}")
    elif hostnames:
        params.append(hostnames)
        where_clauses.append(f"hostname = ANY(${len(params)})")
    where_sql = (" AND " + " AND ".join(where_clauses)) if where_clauses else ""

    if source_tbl == "raw":
        sql = f"""
            SELECT ts, hostname, source,
                   noerror, nxdomain, servfail, refused, notimpl, formerr,
                   queries_a, queries_aaaa, queries_mx, queries_ptr, queries_other,
                   queries_total, qps_avg, cache_hit_pct
            FROM dns_query_stats
            WHERE ts > NOW() - INTERVAL '{interval}' {where_sql}
            ORDER BY ts ASC
        """
    else:
        sql = f"""
            SELECT hour AS ts, hostname,
                   noerror, nxdomain, servfail, refused, notimpl, formerr,
                   queries_a, queries_aaaa, queries_mx, queries_ptr, queries_other,
                   queries_total, qps_avg, cache_hit_pct
            FROM dns_stats_hourly
            WHERE hour > NOW() - INTERVAL '{interval}' {where_sql}
            ORDER BY hour ASC
        """
    async with get_conn() as conn:
        rows = await conn.fetch(sql, *params)
    return [dict(r) for r in rows]


async def get_dns_query_stats_summary(
    hostnames: list[str], start, end,
) -> dict:
    """Agregados pro relatorio mensal: totais e percentuais por RCODE no periodo."""
    placeholders = ", ".join(f"${i+1}" for i in range(len(hostnames)))
    p_start = f"${len(hostnames)+1}"
    p_end = f"${len(hostnames)+2}"
    sql = f"""
        SELECT
            COALESCE(SUM(queries_total), 0) AS queries_total,
            COALESCE(SUM(noerror), 0)  AS noerror,
            COALESCE(SUM(nxdomain), 0) AS nxdomain,
            COALESCE(SUM(servfail), 0) AS servfail,
            COALESCE(SUM(refused), 0)  AS refused,
            COALESCE(SUM(notimpl), 0)  AS notimpl,
            COALESCE(SUM(formerr), 0)  AS formerr,
            COALESCE(SUM(queries_a), 0)     AS queries_a,
            COALESCE(SUM(queries_aaaa), 0)  AS queries_aaaa,
            COALESCE(SUM(queries_mx), 0)    AS queries_mx,
            COALESCE(SUM(queries_ptr), 0)   AS queries_ptr,
            COALESCE(SUM(queries_other), 0) AS queries_other,
            ROUND(AVG(qps_avg)::numeric, 1)       AS qps_avg,
            ROUND(AVG(cache_hit_pct)::numeric, 1) AS cache_hit_pct,
            COUNT(*) AS samples
        FROM dns_query_stats
        WHERE hostname IN ({placeholders})
          AND ts BETWEEN {p_start} AND {p_end}
    """
    async with get_conn() as conn:
        row = await conn.fetchrow(sql, *hostnames, start, end)
    return dict(row) if row else {}


async def update_agent_stats_interval(hostname: str, interval_seconds: int) -> bool:
    """Atualiza intervalo de coleta de stats DNS pra um agente. Retorna False se inexistente."""
    if interval_seconds < 60 or interval_seconds > 3600:
        raise ValueError("dns_stats_interval_seconds deve estar entre 60 e 3600")
    async with get_conn() as conn:
        result = await conn.execute(
            "UPDATE agents SET dns_stats_interval_seconds = $1 WHERE hostname = $2",
            interval_seconds, hostname,
        )
        return result != "UPDATE 0"


async def get_agent_stats_interval(hostname: str) -> int:
    """Retorna intervalo configurado pra agente. Default 600 se nao existe."""
    async with get_conn() as conn:
        row = await conn.fetchval(
            "SELECT dns_stats_interval_seconds FROM agents WHERE hostname = $1",
            hostname,
        )
    return int(row) if row else 600


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


# ===========================================================================
# Alerts
# ===========================================================================

async def insert_alert(
    hostname: str, alert_type: str, severity: str, message: str,
    metric_name: Optional[str] = None, metric_value: Optional[float] = None,
    threshold_value: Optional[float] = None,
) -> Optional[int]:
    """Insere alerta. Retorna id se foi inserido, None se ja existia um aberto
    do mesmo (hostname, alert_type, severity).

    A1 (v1.5 race-fix R6): troca check-then-act (has_open_alert + insert)
    por upsert atomico. ON CONFLICT exige idx_alerts_open_unique em
    (hostname, alert_type, severity) WHERE resolved_at IS NULL — definido
    em schemas.sql. Sob race, apenas uma coroutine consegue o INSERT;
    as outras recebem None e pulam o notify.

    Chamadores devem checar None pra decidir se notificam Telegram/webhook.
    """
    async with get_conn() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO alerts_log
                (hostname, alert_type, severity, message,
                 metric_name, metric_value, threshold_value)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (hostname, alert_type, severity)
                WHERE resolved_at IS NULL
                DO NOTHING
            RETURNING id
            """,
            hostname, alert_type, severity, message,
            metric_name, metric_value, threshold_value,
        )
        return row["id"] if row else None


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


# ===========================================================================
# Agent admin & alert queries
# ===========================================================================

async def update_agent_meta(
    hostname: str,
    display_name: Optional[str],
    location: Optional[str],
    notes: Optional[str],
    active: Optional[bool] = None,
) -> bool:
    """Atualiza metadados editáveis do agente. Retorna False se não existir."""
    async with get_conn() as conn:
        # Se active está sendo alterado, ajusta inactive_since
        if active is True:
            inactive_since_expr = "NULL"
        elif active is False:
            inactive_since_expr = "COALESCE(inactive_since, NOW())"
        else:
            inactive_since_expr = "inactive_since"  # mantém

        result = await conn.execute(
            f"""
            UPDATE agents
            SET display_name   = $2,
                location       = $3,
                notes          = $4,
                active         = COALESCE($5, active),
                inactive_since = {inactive_since_expr}
            WHERE hostname = $1
            """,
            hostname,
            display_name or None,
            location or None,
            notes or None,
            active,
        )
        return result != "UPDATE 0"


async def delete_inactive_agents() -> list[str]:
    """
    Remove agentes marcados como inativos há mais de 3 dias.
    Retorna lista de hostnames deletados.
    """
    async with get_conn() as conn:
        rows = await conn.fetch(
            """
            SELECT hostname FROM agents
            WHERE active = FALSE
              AND inactive_since IS NOT NULL
              AND inactive_since < NOW() - INTERVAL '3 days'
            """
        )
    deleted = []
    for row in rows:
        await delete_agent(row["hostname"])
        deleted.append(row["hostname"])
    return deleted


async def delete_agent(hostname: str) -> bool:
    """
    Remove o agente e todos os seus dados históricos.
    Retorna False se o hostname não existir.
    """
    async with get_conn() as conn:
        result = await conn.execute(
            "DELETE FROM agents WHERE hostname = $1", hostname
        )
        if result == "DELETE 0":
            return False
        # Remove dados históricos (hypertables não têm FK cascade)
        for table in (
            "agent_heartbeats", "metrics_cpu", "metrics_ram",
            "metrics_disk", "metrics_io", "dns_checks",
            "dns_service_status", "agent_commands", "alerts_log",
        ):
            await conn.execute(
                f"DELETE FROM {table} WHERE hostname = $1", hostname  # noqa: S608
            )
        return True


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


# ===========================================================================
# Fingerprint — identificacao de hardware do agente
# ===========================================================================

async def upsert_fingerprint(hostname: str, fingerprint: str) -> dict:
    """
    Registra ou atualiza o fingerprint do agente.
    Retorna dict com 'is_new' e 'changed' para o backend decidir se alerta.

    A3 (R8 race-fix): SELECT + multi-UPDATE foi consolidado em UMA transacao
    com SELECT ... FOR UPDATE. O row-level lock garante que dois heartbeats
    simultaneos do mesmo hostname serializam — sem isso, perdia-se deteccao
    de mudanca de fingerprint (2 reboots simultaneos podiam reportar changed=False).
    """
    async with get_conn() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT fingerprint
                FROM agents
                WHERE hostname = $1
                FOR UPDATE
                """,
                hostname,
            )
            if row is None:
                return {"is_new": True, "changed": False}

            existing = row["fingerprint"]

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
                # Fingerprint mudou — possivel copia ou migracao de hardware
                await conn.execute(
                    "UPDATE agents SET fingerprint_last_seen = NOW() WHERE hostname = $1",
                    hostname,
                )
                return {"is_new": False, "changed": True, "previous": existing}

            # Fingerprint igual — so atualiza last_seen
            await conn.execute(
                "UPDATE agents SET fingerprint_last_seen = NOW() WHERE hostname = $1",
                hostname,
            )
            return {"is_new": False, "changed": False}


# ===========================================================================
# Comandos remotos
# ===========================================================================

VALID_COMMANDS = {"stop", "disable", "enable", "restart", "purge", "decommission", "run_script", "update_agent", "dnstop"}

# SEC (SEC-2.4): comandos irreversiveis que exigem confirm_token no INSERT.
# Defesa em profundidade — controller ja barra no two-step, mas o DB tambem
# valida pra impedir codigo legado/scripts inserindo direto sem o gate.
_TOKEN_REQUIRED_COMMANDS = {"purge", "decommission"}


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
            SELECT id, command, confirm_token, params, issued_at
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


async def mark_command_notified(command_id: int) -> bool:
    """Marca command como notificado (idempotente, atomico).

    Retorna True se foi a primeira marcacao (caller deve enviar Telegram).
    Retorna False se ja estava notificado (caller deve silenciar — duplicata).

    Usado pra dedupe quando agente publica ack em 2 caminhos (NATS + HTTP
    fallback). Ambos endpoints chamam isso antes de tg.send_command_result;
    so o primeiro a vencer a UPDATE atomica envia.
    """
    async with get_conn() as conn:
        row = await conn.fetchval(
            """
            UPDATE agent_commands
            SET notified_at = NOW()
            WHERE id = $1 AND notified_at IS NULL
            RETURNING id
            """,
            command_id,
        )
    return row is not None


async def insert_command(
    hostname: str,
    command: str,
    issued_by: str = "admin",
    confirm_token: str = None,
    expires_hours: int = None,
    params: str = None,
) -> int:
    """Insere um novo comando para o agente executar. Retorna o ID."""
    if command not in VALID_COMMANDS:
        raise ValueError(f"Comando inválido: {command}. Válidos: {VALID_COMMANDS}")
    if command in _TOKEN_REQUIRED_COMMANDS and not confirm_token:
        raise ValueError(f"{command} exige confirm_token")
    if command == "run_script" and not params:
        raise ValueError("run_script exige params com o nome do script")

    async with get_conn() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO agent_commands
                (hostname, command, issued_by, confirm_token, params, expires_at)
            VALUES ($1, $2, $3, $4, $5,
                    CASE WHEN $6::int IS NULL THEN NULL
                         ELSE NOW() + ($6 * INTERVAL '1 hour')
                    END)
            RETURNING id
            """,
            hostname, command, issued_by, confirm_token, params, expires_hours,
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


async def get_all_commands_history(limit: int = 50) -> list[dict]:
    """Retorna histórico recente de comandos de todos os hosts."""
    async with get_conn() as conn:
        rows = await conn.fetch(
            """
            SELECT id, hostname, command, params, issued_by, issued_at, executed_at, status, result
            FROM agent_commands
            ORDER BY issued_at DESC
            LIMIT $1
            """,
            limit,
        )
        return [dict(r) for r in rows]


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


# ===========================================================================
# Client users — portal read-only
# ===========================================================================

async def create_client(username: str, password_hash: str, hostnames: list[str],
                        notes: str = None, email: str = None,
                        domains: list[str] = None) -> int:
    async with get_conn() as conn:
        row = await conn.fetchrow(
            """INSERT INTO client_users (username, password_hash, hostnames, notes, email, domains)
               VALUES ($1, $2, $3, $4, $5, $6) RETURNING id""",
            username, password_hash, hostnames, notes, email, domains or [],
        )
        return row["id"]


async def get_client(username: str) -> Optional[dict]:
    async with get_conn() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM client_users WHERE username = $1", username)
        return dict(row) if row else None


async def list_clients() -> list[dict]:
    async with get_conn() as conn:
        rows = await conn.fetch(
            "SELECT id, username, hostnames, active, created_at, notes, email, webhook_url, domains "
            "FROM client_users ORDER BY username")
        return [dict(r) for r in rows]


_CLIENT_ALLOWED_FIELDS = {"hostnames", "active", "password_hash", "notes", "email", "webhook_url", "domains"}


async def update_client(client_id: int, **fields) -> bool:
    # Whitelist — rejeita campos nao permitidos
    invalid = set(fields.keys()) - _CLIENT_ALLOWED_FIELDS
    if invalid:
        raise ValueError(f"Campos nao permitidos: {invalid}")
    sets, vals, i = [], [], 1
    for k, v in fields.items():
        if v is not None:
            sets.append(f"{k} = ${i}")
            vals.append(v)
            i += 1
    if not sets:
        return False
    vals.append(client_id)
    async with get_conn() as conn:
        result = await conn.execute(
            f"UPDATE client_users SET {', '.join(sets)} WHERE id = ${i}",
            *vals,
        )
        return "UPDATE 1" in result


async def delete_client(client_id: int) -> bool:
    async with get_conn() as conn:
        result = await conn.execute(
            "DELETE FROM client_users WHERE id = $1", client_id)
        return "DELETE 1" in result


async def authenticate_client(username: str) -> Optional[dict]:
    """Retorna user com password_hash para verificação. None se não existe ou inativo."""
    async with get_conn() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM client_users WHERE username = $1 AND active = TRUE",
            username,
        )
        return dict(row) if row else None


# ===========================================================================
# Admin users — multi-user RBAC
# ===========================================================================

async def create_admin_user(username: str, password_hash: str, role: str = "viewer",
                            created_by: str = None, notes: str = None) -> int:
    async with get_conn() as conn:
        row = await conn.fetchrow(
            """INSERT INTO admin_users (username, password_hash, role, created_by, notes)
               VALUES ($1, $2, $3, $4, $5) RETURNING id""",
            username, password_hash, role, created_by, notes,
        )
        return row["id"]


async def get_admin_user(username: str) -> Optional[dict]:
    async with get_conn() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM admin_users WHERE username = $1", username)
        return dict(row) if row else None


async def get_admin_user_by_id(user_id: int) -> Optional[dict]:
    async with get_conn() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM admin_users WHERE id = $1", user_id)
        return dict(row) if row else None


async def authenticate_admin_user(username: str) -> Optional[dict]:
    """Retorna admin user ativo com password_hash para verificacao. None se nao existe ou inativo."""
    async with get_conn() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM admin_users WHERE username = $1 AND active = TRUE",
            username,
        )
        return dict(row) if row else None


async def list_admin_users() -> list[dict]:
    async with get_conn() as conn:
        rows = await conn.fetch(
            "SELECT id, username, role, active, created_at, created_by, notes "
            "FROM admin_users ORDER BY username")
        return [dict(r) for r in rows]


_ADMIN_USER_ALLOWED_FIELDS = {"role", "active", "password_hash", "notes"}


async def update_admin_user(user_id: int, **fields) -> bool:
    invalid = set(fields.keys()) - _ADMIN_USER_ALLOWED_FIELDS
    if invalid:
        raise ValueError(f"Campos nao permitidos: {invalid}")
    sets, vals, i = [], [], 1
    for k, v in fields.items():
        if v is not None:
            sets.append(f"{k} = ${i}")
            vals.append(v)
            i += 1
    if not sets:
        return False
    vals.append(user_id)
    async with get_conn() as conn:
        result = await conn.execute(
            f"UPDATE admin_users SET {', '.join(sets)} WHERE id = ${i}",
            *vals,
        )
        return "UPDATE 1" in result


async def delete_admin_user(user_id: int) -> bool:
    async with get_conn() as conn:
        result = await conn.execute(
            "DELETE FROM admin_users WHERE id = $1", user_id)
        return "DELETE 1" in result


# ===========================================================================
# Audit log
# ===========================================================================

# SEC (M10/LL2): campos de audit aceitam strings controladas por atacante
# (username em login_failed, hostname em commands, detail em comandos remotos).
# Sanitizamos antes do INSERT para mitigar prompt-injection caso um LLM seja
# usado para resumir/analisar audit log no futuro, e para impedir que controle
# de fluxo (\r\n) crie linhas falsas em logs textuais derivados.
import re as _re_audit
_AUDIT_CTRL = _re_audit.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
_AUDIT_MAX_LEN = 256

def _sanitize_audit_field(value, max_len: int = _AUDIT_MAX_LEN):
    if value is None:
        return None
    s = str(value)
    # Remove control chars (NUL, BEL, etc.); preserva \n e \t para depois neutralizar
    s = _AUDIT_CTRL.sub('', s)
    # Normaliza quebras e tabs (impede injecao de "novas linhas" em logs derivados)
    s = s.replace('\r\n', ' | ').replace('\n', ' | ').replace('\r', ' | ').replace('\t', ' ')
    if len(s) > max_len:
        s = s[: max_len - 1] + '…'
    return s


# C2 (v1.5): hash chain immutable. Constante 64-bit pra advisory lock —
# serializa appends concorrentes (varios await audit() em flight) e evita
# race em prev_hash. Liberado no commit/rollback da transaction.
_AUDIT_LOCK_KEY = 8329472100  # const arbitraria; isolada em sua keyspace


def _compute_audit_hash(prev_hash: Optional[str], ts: datetime,
                        actor: Optional[str], action: Optional[str],
                        target: Optional[str], detail: Optional[str],
                        ip: Optional[str]) -> str:
    """SHA-256 canonico do conteudo + prev_hash. Mudanca em qualquer campo
    apos o INSERT invalida a verificacao. Separator US (\\x1f) impede
    colisao por concatenacao ambigua."""
    parts = [
        prev_hash or '',
        ts.isoformat(),
        actor or '',
        action or '',
        target or '',
        detail or '',
        ip or '',
    ]
    canonical = '\x1f'.join(parts).encode('utf-8')
    return hashlib.sha256(canonical).hexdigest()


async def audit(actor: str, action: str, target: str = None,
                detail: str = None, ip: str = None) -> None:
    """Registra acao no audit log com hash chain (append-only imutavel).
    Sanitiza campos user-controlled. Em caso de falha, loga e nao bloqueia
    a acao chamadora — audit e best-effort no path atual.
    """
    actor  = _sanitize_audit_field(actor,  max_len=128)
    action = _sanitize_audit_field(action, max_len=64)
    target = _sanitize_audit_field(target, max_len=256)
    detail = _sanitize_audit_field(detail, max_len=512)
    ip     = _sanitize_audit_field(ip,     max_len=64)
    ts = datetime.now(timezone.utc)
    try:
        async with get_conn() as conn:
            async with conn.transaction():
                # Advisory lock — serializa todas as chamadas concorrentes
                # de audit() pra evitar 2 transactions pegarem o mesmo
                # prev_hash (chain quebraria).
                await conn.execute("SELECT pg_advisory_xact_lock($1)", _AUDIT_LOCK_KEY)
                row = await conn.fetchrow(
                    "SELECT row_hash FROM audit_log WHERE row_hash IS NOT NULL "
                    "ORDER BY id DESC LIMIT 1"
                )
                prev_hash = row['row_hash'] if row else None
                row_hash = _compute_audit_hash(prev_hash, ts, actor, action, target, detail, ip)
                await conn.execute(
                    """INSERT INTO audit_log
                         (ts, actor, action, target, detail, ip, prev_hash, row_hash)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)""",
                    ts, actor, action, target, detail, ip, prev_hash, row_hash,
                )
    except Exception as exc:
        logger.warning("Audit log falhou: %s", exc)


async def verify_audit_chain(limit: Optional[int] = None) -> dict:
    """Verifica integridade do hash chain do audit_log.

    Tolera rows legacy (criadas antes da migration C2 — row_hash IS NULL)
    SE estiverem todas no inicio (continuas, antes de qualquer row assinada).
    A partir da primeira row com row_hash != NULL, exige cadeia integra.

    Retorna dict com keys: valid (bool), total (int), legacy_count (int),
    signed_count (int), broken_at_id (int|None), message (str).
    """
    sql = ("SELECT id, ts, actor, action, target, detail, ip, prev_hash, row_hash "
           "FROM audit_log ORDER BY id ASC")
    if limit:
        sql += f" LIMIT {int(limit)}"
    async with get_conn() as conn:
        rows = await conn.fetch(sql)

    total = len(rows)
    legacy_count = 0
    signed_count = 0
    chain_started = False
    expected_prev: Optional[str] = None  # row_hash esperado como prev_hash da proxima

    for r in rows:
        if r['row_hash'] is None:
            if chain_started:
                return {
                    "valid": False, "total": total,
                    "legacy_count": legacy_count, "signed_count": signed_count,
                    "broken_at_id": r['id'],
                    "message": (f"Row id={r['id']} sem row_hash apos chain iniciar — "
                                f"insercao manual sem hash ou rollback parcial."),
                }
            legacy_count += 1
            continue

        if not chain_started:
            chain_started = True
            # Primeira row do chain pode ter qualquer prev_hash (incluindo None
            # se for genesis OU o row_hash da ultima legacy se aplicado pos-fato).
            # Nao validamos prev_hash aqui — apenas o conteudo.
        else:
            if r['prev_hash'] != expected_prev:
                return {
                    "valid": False, "total": total,
                    "legacy_count": legacy_count, "signed_count": signed_count,
                    "broken_at_id": r['id'],
                    "message": (f"Row id={r['id']} prev_hash={r['prev_hash'][:16]+'...' if r['prev_hash'] else 'NULL'} "
                                f"nao bate com row_hash anterior."),
                }

        computed = _compute_audit_hash(r['prev_hash'], r['ts'], r['actor'],
                                       r['action'], r['target'], r['detail'], r['ip'])
        if computed != r['row_hash']:
            return {
                "valid": False, "total": total,
                "legacy_count": legacy_count, "signed_count": signed_count,
                "broken_at_id": r['id'],
                "message": (f"Row id={r['id']} row_hash recomputado nao bate — "
                            f"conteudo modificado apos o INSERT."),
            }
        signed_count += 1
        expected_prev = r['row_hash']

    return {
        "valid": True, "total": total,
        "legacy_count": legacy_count, "signed_count": signed_count,
        "broken_at_id": None,
        "message": (f"Chain integro: {signed_count} rows assinadas + "
                    f"{legacy_count} legacy."),
    }


# ===========================================================================
# Daily Reports
# ===========================================================================

async def save_daily_report(report_date, client_id: int, pdf_data: bytes) -> int:
    async with get_conn() as conn:
        row = await conn.fetchrow(
            """INSERT INTO daily_reports (report_date, client_id, pdf_data)
               VALUES ($1, $2, $3)
               ON CONFLICT (report_date, client_id) DO UPDATE SET pdf_data = $3, generated_at = NOW()
               RETURNING id""",
            report_date, client_id, pdf_data,
        )
        return row["id"]


async def list_daily_reports(client_id: int, limit: int = 30) -> list[dict]:
    async with get_conn() as conn:
        rows = await conn.fetch(
            """SELECT id, report_date, generated_at, LENGTH(pdf_data) AS size_bytes
               FROM daily_reports WHERE client_id = $1
               ORDER BY report_date DESC LIMIT $2""",
            client_id, limit,
        )
        return [dict(r) for r in rows]


async def get_daily_report_pdf(report_date, client_id: int) -> bytes | None:
    async with get_conn() as conn:
        row = await conn.fetchrow(
            "SELECT pdf_data FROM daily_reports WHERE report_date = $1 AND client_id = $2",
            report_date, client_id,
        )
        return row["pdf_data"] if row else None


async def list_all_daily_reports(limit: int = 50) -> list[dict]:
    """Admin: lista todos os relatorios de todos os clientes."""
    async with get_conn() as conn:
        rows = await conn.fetch(
            """SELECT dr.id, dr.report_date, dr.client_id, dr.generated_at,
                      LENGTH(dr.pdf_data) AS size_bytes, cu.username
               FROM daily_reports dr
               JOIN client_users cu ON cu.id = dr.client_id
               ORDER BY dr.report_date DESC LIMIT $1""",
            limit,
        )
        return [dict(r) for r in rows]


# ===========================================================================
# Dashboard / Client — queries de metricas agregadas
# ===========================================================================

_VALID_PERIODS = {"1h": "1 hour", "6h": "6 hours", "24h": "24 hours", "7d": "7 days"}
_BUCKET_MAP    = {"1h": "5 minutes", "6h": "30 minutes", "24h": "1 hour", "7d": "6 hours"}


async def validate_client_hostnames(client_username: str, requested_hostnames: list[str]) -> bool:
    """Valida que os hostnames pertencem ao cliente. Previne acesso cross-client."""
    async with get_conn() as conn:
        row = await conn.fetchrow(
            "SELECT hostnames FROM client_users WHERE username = $1 AND active = TRUE",
            client_username,
        )
    if not row:
        return False
    allowed = set(row["hostnames"] or [])
    return all(h in allowed for h in requested_hostnames)


async def get_aggregated_metrics(
    period: str = "24h",
    hostnames: list[str] | None = None,
) -> dict:
    """
    Retorna metricas agregadas para dashboard admin ou portal do cliente.
    Se hostnames fornecido, filtra por esses hosts (portal do cliente).
    Se None, retorna todos (dashboard admin), com suporte a filtro por host unico.
    """
    interval = _VALID_PERIODS.get(period, "24 hours")
    bucket   = _BUCKET_MAP.get(period, "1 hour")

    # Seguranca: interval e bucket SEMPRE vem de dicts internos (nunca de input do usuario)
    assert interval in _VALID_PERIODS.values(), f"interval invalido: {interval}"
    assert bucket in _BUCKET_MAP.values(), f"bucket invalido: {bucket}"

    # Monta filtro de hostnames (parameterized — sem f-string SQL)
    if hostnames:
        placeholders = ", ".join(f"${i+1}" for i in range(len(hostnames)))
        host_filter = f" AND hostname IN ({placeholders})"
        host_params = list(hostnames)
    else:
        host_filter = ""
        host_params = []

    async with get_conn() as conn:
        # Agentes — lista completa ou filtrada
        if hostnames:
            agents = [dict(r) for r in await conn.fetch(
                f"SELECT * FROM v_agent_current_status WHERE hostname IN ({placeholders}) ORDER BY hostname",
                *host_params)]
        else:
            agents = [dict(r) for r in await conn.fetch(
                "SELECT * FROM v_agent_current_status ORDER BY hostname")]

        dns_latency = [dict(r) for r in await conn.fetch(f"""
            SELECT domain,
                   ROUND(AVG(latency_ms)::numeric, 1) AS avg_ms,
                   ROUND(MAX(latency_ms)::numeric, 1) AS max_ms,
                   COUNT(*) AS checks,
                   SUM(CASE WHEN NOT success THEN 1 ELSE 0 END) AS failures
            FROM dns_checks
            WHERE ts > NOW() - INTERVAL '{interval}' AND latency_ms IS NOT NULL{host_filter}
            GROUP BY domain ORDER BY avg_ms DESC LIMIT 10
        """, *host_params)]

        cpu_history = [dict(r) for r in await conn.fetch(f"""
            SELECT hostname,
                   time_bucket('{bucket}', ts) AS bucket,
                   ROUND(AVG(cpu_percent)::numeric, 1) AS cpu_avg
            FROM metrics_cpu
            WHERE ts > NOW() - INTERVAL '{interval}'{host_filter}
            GROUP BY hostname, bucket ORDER BY bucket
        """, *host_params)]

        ram_history = [dict(r) for r in await conn.fetch(f"""
            SELECT hostname,
                   time_bucket('{bucket}', ts) AS bucket,
                   ROUND(AVG(ram_percent)::numeric, 1) AS ram_avg
            FROM metrics_ram
            WHERE ts > NOW() - INTERVAL '{interval}'{host_filter}
            GROUP BY hostname, bucket ORDER BY bucket
        """, *host_params)]

        dns_history = [dict(r) for r in await conn.fetch(f"""
            SELECT hostname,
                   time_bucket('{bucket}', ts) AS bucket,
                   ROUND(AVG(latency_ms)::numeric, 1) AS latency_avg,
                   COUNT(*) AS total,
                   SUM(CASE WHEN NOT success THEN 1 ELSE 0 END) AS failures
            FROM dns_checks
            WHERE ts > NOW() - INTERVAL '{interval}'{host_filter}
            GROUP BY hostname, bucket ORDER BY bucket
        """, *host_params)]

        alert_limit = 20 if hostnames else 30
        recent_alerts = [dict(r) for r in await conn.fetch(f"""
            SELECT hostname, alert_type, severity, message, ts
            FROM alerts_log
            WHERE ts > NOW() - INTERVAL '{interval}'{host_filter}
            ORDER BY ts DESC LIMIT {alert_limit}
        """, *host_params)]

    return {
        "agents": agents,
        "dns_latency": dns_latency,
        "cpu_history": cpu_history,
        "ram_history": ram_history,
        "dns_history": dns_history,
        "recent_alerts": recent_alerts,
    }


# ===========================================================================
# Speedtest — Domain SSL/Port checker (medidores)
# ===========================================================================

def _aggregate_speedtest_metrics(domains: list, metadata: dict, summary: dict) -> dict:
    """Computa metricas agregadas de speedtest_scans a partir da lista
    individual de dominios. Robusto contra divergencias de schema do
    payload do domain_checker.py (mismatch de chaves em metadata).

    Bug 2026-05-07: o checker enviava 'reachable_count' mas backend
    esperava 'reachable_domains' (etc). Resultado: agregados zerados em
    speedtest_scans, embora speedtest_domains tivesse dados certos.
    Grafico de historico (que le dos agregados) ficava todo em zero.

    Estrategia:
      - Conta a partir de domains[] (fonte primaria)
      - Cai pra metadata.<x> apenas se domains[] vazio (cenario edge)
      - 'expiring_soon' definido como SSL valido com <30 dias pra expirar
        (alinhado com filtro do frontend)
    """
    if not domains:
        return {
            "total_domains":  metadata.get("total_domains", 0),
            "reachable":      metadata.get("reachable_domains", 0),
            "unreachable":    metadata.get("total_domains", 0) - metadata.get("reachable_domains", 0),
            "ssl_valid":      metadata.get("valid_certificates", 0),
            "ssl_invalid":    metadata.get("ssl_enabled_domains", 0) - metadata.get("valid_certificates", 0),
            "ssl_expired":    metadata.get("expired_certificates", 0),
            "expiring_soon":  metadata.get("expiring_soon_count", 0),
            "avg_response_ms": (summary.get("performance_metrics") or {}).get("avg_response_time_ms"),
        }

    total       = len(domains)
    reachable   = sum(1 for d in domains if d.get("reachable"))
    ssl_valid   = sum(1 for d in domains if d.get("certificate_valid"))
    ssl_expired = sum(1 for d in domains if d.get("certificate_expired"))
    ssl_invalid = sum(
        1 for d in domains
        if d.get("ssl_enabled")
        and not d.get("certificate_valid")
        and not d.get("certificate_expired")
    )
    expiring_soon = sum(
        1 for d in domains
        if (d.get("days_until_expiry") is not None)
        and 0 < d["days_until_expiry"] < 30
        and not d.get("certificate_expired")
    )
    rt_values = [
        float(d["response_time_ms"]) for d in domains
        if d.get("response_time_ms") is not None and d.get("reachable")
    ]
    avg_rt = round(sum(rt_values) / len(rt_values), 2) if rt_values else None

    return {
        "total_domains":   total,
        "reachable":       reachable,
        "unreachable":     total - reachable,
        "ssl_valid":       ssl_valid,
        "ssl_invalid":     ssl_invalid,
        "ssl_expired":     ssl_expired,
        "expiring_soon":   expiring_soon,
        "avg_response_ms": avg_rt,
    }


async def insert_speedtest_scan(metadata: dict, summary: dict, domains: list) -> int:
    """Insere scan completo do speedtest. Retorna scan_id."""
    from datetime import datetime as _dt, timezone as _tz
    ts = _parse_ts(metadata.get("scan_timestamp", _dt.now(_tz.utc).isoformat()))

    # 2026-05-07: agregados computados em Python a partir de domains[].
    # Antes lia direto de metadata.<x> e ficava zerado quando o checker
    # enviava chaves diferentes. Agora robusto a mismatch.
    agg = _aggregate_speedtest_metrics(domains, metadata, summary)

    async with get_conn() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO speedtest_scans
                (ts, total_domains, reachable, unreachable, ssl_valid, ssl_invalid,
                 ssl_expired, expiring_soon, avg_response_ms, scan_duration_s,
                 errors_count, timeouts_count, source)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
            RETURNING id
            """,
            ts,
            agg["total_domains"],
            agg["reachable"],
            agg["unreachable"],
            agg["ssl_valid"],
            agg["ssl_invalid"],
            agg["ssl_expired"],
            agg["expiring_soon"],
            agg["avg_response_ms"],
            metadata.get("scan_duration_seconds"),
            metadata.get("errors_count", 0),
            metadata.get("timeouts_count", 0),
            metadata.get("source"),
        )
        scan_id = row["id"]

        if domains:
            await conn.executemany(
                """
                INSERT INTO speedtest_domains
                    (ts, scan_id, domain, port, reachable, ssl_enabled,
                     certificate_valid, certificate_expired, days_until_expiry,
                     expiry_date, issuer, subject, tls_version, cipher_suite,
                     response_time_ms, error_message)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
                """,
                [
                    (
                        ts, scan_id,
                        d.get("domain"), d.get("port", 8080),
                        d.get("reachable"), d.get("ssl_enabled"),
                        d.get("certificate_valid"), d.get("certificate_expired"),
                        d.get("days_until_expiry"), d.get("expiry_date"),
                        d.get("issuer"), d.get("subject"),
                        d.get("tls_version"), d.get("cipher_suite"),
                        d.get("response_time_ms"), d.get("error_message"),
                    )
                    for d in domains
                ],
            )

    return scan_id


async def get_latest_speedtest() -> Optional[dict]:
    """Retorna o scan mais recente com todos os domínios."""
    async with get_conn() as conn:
        scan = await conn.fetchrow(
            "SELECT * FROM speedtest_scans ORDER BY ts DESC LIMIT 1"
        )
        if not scan:
            return None
        scan_dict = dict(scan)
        domains = await conn.fetch(
            "SELECT * FROM speedtest_domains WHERE scan_id = $1 ORDER BY domain",
            scan_dict["id"],
        )
        scan_dict["domains"] = [dict(d) for d in domains]
        return scan_dict


async def get_speedtest_history(limit: int = 30) -> list[dict]:
    """Historico de scans (sem dominios individuais)."""
    async with get_conn() as conn:
        rows = await conn.fetch(
            "SELECT * FROM speedtest_scans ORDER BY ts DESC LIMIT $1", limit
        )
        return [dict(r) for r in rows]


# ===========================================================================
# Speedtest — visao do cliente (filtrada pelos seus dominios)
# ===========================================================================

async def get_client_speedtest_latest(domains: list[str]) -> list[dict]:
    """Retorna o ultimo registro de cada dominio em speedtest_domains que
    bate com a lista do cliente. SEC: lista vazia = nada (nao retorna tudo).

    Sobreposicao entre clientes e suportada — mesmo dominio pode aparecer
    em multiplos client.domains[]; cada cliente recebe o snapshot atual
    independente.
    """
    if not domains:
        return []
    async with get_conn() as conn:
        rows = await conn.fetch(
            """
            SELECT DISTINCT ON (domain)
                domain, port, ts, reachable, ssl_enabled,
                certificate_valid, certificate_expired, days_until_expiry,
                expiry_date, issuer, tls_version,
                response_time_ms, error_message
            FROM speedtest_domains
            WHERE domain = ANY($1)
            ORDER BY domain, ts DESC
            """,
            domains,
        )
        return [dict(r) for r in rows]


async def get_client_speedtest_summary(domains: list[str]) -> dict:
    """KPIs agregados pra card resumo no portal do cliente.
    Calcula em cima do ultimo registro de cada dominio (ou seja, mesmo
    set que get_client_speedtest_latest).

    Retorna:
      total_domains
      reachable / unreachable
      ssl_valid / ssl_invalid / ssl_expired
      expiring_soon (< 30 dias pra vencer)
      avg_response_ms (so dos reachable)
      last_check_ts (timestamp do scan mais recente que envolveu algum dominio)
    """
    if not domains:
        return {
            "total_domains": 0, "reachable": 0, "unreachable": 0,
            "ssl_valid": 0, "ssl_invalid": 0, "ssl_expired": 0,
            "expiring_soon": 0, "avg_response_ms": None,
            "last_check_ts": None,
        }
    latest = await get_client_speedtest_latest(domains)
    if not latest:
        return {
            "total_domains": len(domains), "reachable": 0, "unreachable": 0,
            "ssl_valid": 0, "ssl_invalid": 0, "ssl_expired": 0,
            "expiring_soon": 0, "avg_response_ms": None,
            "last_check_ts": None,
        }

    total = len(latest)
    reachable = sum(1 for r in latest if r.get("reachable"))
    ssl_valid = sum(1 for r in latest if r.get("certificate_valid"))
    ssl_invalid = sum(
        1 for r in latest
        if r.get("ssl_enabled") and not r.get("certificate_valid")
        and not r.get("certificate_expired")
    )
    ssl_expired = sum(1 for r in latest if r.get("certificate_expired"))
    # Expiring soon: < 30 dias E nao expirado ainda (= valido mas perto do fim)
    expiring_soon = sum(
        1 for r in latest
        if r.get("days_until_expiry") is not None
        and 0 < r["days_until_expiry"] < 30
        and not r.get("certificate_expired")
    )
    rt_values = [
        float(r["response_time_ms"]) for r in latest
        if r.get("response_time_ms") is not None and r.get("reachable")
    ]
    avg_rt = round(sum(rt_values) / len(rt_values), 1) if rt_values else None
    last_ts = max((r["ts"] for r in latest if r.get("ts")), default=None)

    return {
        "total_domains": total,
        "configured_domains": len(domains),  # quantos o cliente cadastrou
        "reachable": reachable,
        "unreachable": total - reachable,
        "ssl_valid": ssl_valid,
        "ssl_invalid": ssl_invalid,
        "ssl_expired": ssl_expired,
        "expiring_soon": expiring_soon,
        "avg_response_ms": avg_rt,
        "last_check_ts": last_ts,
    }