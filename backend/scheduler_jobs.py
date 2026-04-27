"""
scheduler_jobs.py — Jobs do APScheduler.

Cinco jobs:
    job_check_offline  (interval 5min)  — detecta agentes offline e dispara alerta
    job_send_report    (cron 4x/dia)    — relatorio consolidado para Telegram
    job_purge_inactive (interval 1h)    — auto-purge de agentes inativos > 3 dias
    job_monthly_email  (cron dia 1)     — relatorio PDF por email para clientes
    job_daily_report   (cron 23:59)     — gera PDF do dia para cada cliente

THRESHOLDS e REPORT_TIMES sao importados lazy de main para evitar circular
import. setup_scheduler(scheduler) registra todos os jobs no scheduler dado.
"""

import logging

import db
import telegram_bot as tg

logger = logging.getLogger("infra-vision.api")

# Janelas que disparam o relatorio Telegram consolidado.
REPORT_TIMES = ["00:00", "06:00", "12:00", "18:00"]


async def job_check_offline() -> None:
    """Roda a cada 5 min: detecta agentes offline e dispara alerta.

    Usa main.db / main.tg em vez de imports locais para que os testes
    possam monkey-patchar `main.db`/`main.tg` e o job ver o mock.
    """
    import main as _m
    THRESHOLDS = _m.THRESHOLDS
    offline = await _m.db.get_agents_offline(THRESHOLDS["offline_minutes"])
    for agent in offline:
        hostname = agent["hostname"]
        open_alerts = await _m.db.get_open_alerts(hostname)
        already_open = any(a["alert_type"] == "offline" for a in open_alerts)
        if not already_open:
            alert_id = await _m.db.insert_alert(
                hostname=hostname,
                alert_type="offline",
                severity="critical",
                message=f"Agente {hostname} sem heartbeat por mais de {THRESHOLDS['offline_minutes']} minutos",
            )
            sent = await _m.tg.alert_agent_offline(hostname, agent.get("last_seen"))
            if sent:
                await _m.db.mark_alert_notified(alert_id)
            logger.warning("Agente offline detectado: %s", hostname)


async def job_send_report() -> None:
    """Envia relatorio consolidado ao Telegram.

    Estrategia de imports para preservar monkey-patching nos testes:
    - main.db / main.tg para funcoes de alto nivel (testes patcham main.db).
    - get_conn import lazy de db pra honrar patch.object(db, 'get_conn').
    """
    import main as _m
    from db import get_conn
    async with get_conn() as conn:
        rows = await conn.fetch("SELECT hostname, agent_status FROM v_agent_current_status")

    total   = len(rows)
    online  = sum(1 for r in rows if r["agent_status"] == "online")
    offline_list = [r["hostname"] for r in rows if r["agent_status"] in ("offline", "never_seen")]

    async with get_conn() as conn:
        dns_fail_rows = await conn.fetch(
            """
            SELECT hostname, domain, error_code AS error
            FROM dns_checks
            WHERE success = FALSE AND ts > NOW() - INTERVAL '7 hours'
            ORDER BY ts DESC LIMIT 20
            """
        )
    dns_failures = [dict(r) for r in dns_fail_rows]

    disk_warn = await _m.db.get_all_disk_alerts()
    open_alerts = await _m.db.get_open_alerts()

    await _m.tg.send_report(
        total_agents=total,
        online_agents=online,
        offline_agents=offline_list,
        dns_failures=dns_failures,
        disk_warnings=disk_warn,
        open_alerts=len(open_alerts),
    )
    logger.info("Relatorio enviado ao Telegram")


async def job_purge_inactive() -> None:
    """Roda a cada hora: deleta agentes inativos ha mais de 3 dias."""
    deleted = await db.delete_inactive_agents()
    for hostname in deleted:
        logger.info("Auto-purge: agente inativo removido apos 3 dias: %s", hostname)
        await tg.send_new_agent_detected(
            hostname, "removido automaticamente (inativo > 3 dias)"
        )


async def job_monthly_email() -> None:
    """Roda no dia 1 de cada mes: envia relatorio PDF por email para clientes com email."""
    import email_report
    if not email_report.is_configured():
        logger.info("SMTP nao configurado — emails mensais desabilitados")
        return

    from datetime import datetime as _dt, timedelta as _td
    from routes_client import _build_report_pdf

    # Mes anterior
    today = _dt.now()
    first_of_month = _dt(today.year, today.month, 1)
    last_month_end = first_of_month - _td(days=1)
    last_month_start = _dt(last_month_end.year, last_month_end.month, 1)
    month_label = last_month_start.strftime("%Y-%m")

    clients = await db.list_clients()
    sent = 0
    for client in clients:
        if not client.get("active") or not client.get("email"):
            continue
        hostnames = client.get("hostnames", [])
        if not hostnames:
            continue

        # Gera dados do relatorio
        placeholders = ", ".join(f"${i+1}" for i in range(len(hostnames)))
        p_start = f"${len(hostnames)+1}"
        p_end = f"${len(hostnames)+2}"
        params = [*hostnames, last_month_start, first_of_month]

        async with db.get_conn() as conn:
            hb_count = await conn.fetchval(f"""
                SELECT COUNT(*) FROM agent_heartbeats
                WHERE hostname IN ({placeholders}) AND ts BETWEEN {p_start} AND {p_end}
            """, *params)
            total_minutes = (first_of_month - last_month_start).total_seconds() / 60
            expected_hb = int(total_minutes / 5) * len(hostnames)
            uptime_pct = round((hb_count / max(expected_hb, 1)) * 100, 2)

            lat_stats = await conn.fetchrow(f"""
                SELECT ROUND(AVG(latency_ms)::numeric, 1) AS avg_ms,
                       ROUND(MAX(latency_ms)::numeric, 1) AS max_ms,
                       ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms)::numeric, 1) AS p95_ms,
                       COUNT(*) AS total_checks,
                       SUM(CASE WHEN NOT success THEN 1 ELSE 0 END) AS failures
                FROM dns_checks
                WHERE hostname IN ({placeholders}) AND ts BETWEEN {p_start} AND {p_end}
                      AND latency_ms IS NOT NULL
            """, *params) or {}

            alerts = await conn.fetchval(f"""
                SELECT COUNT(*) FROM alerts_log
                WHERE hostname IN ({placeholders}) AND ts BETWEEN {p_start} AND {p_end}
            """, *params)
            critical = await conn.fetchval(f"""
                SELECT COUNT(*) FROM alerts_log
                WHERE hostname IN ({placeholders}) AND ts BETWEEN {p_start} AND {p_end}
                      AND severity = 'critical'
            """, *params)

        downtime_min = round(total_minutes * (1 - uptime_pct / 100))
        report_data = {
            "period": {"start": last_month_start.isoformat(), "end": first_of_month.isoformat()},
            "hostnames": hostnames,
            "uptime_pct": uptime_pct,
            "downtime_minutes": downtime_min,
            "latency": dict(lat_stats) if lat_stats else {},
            "alerts_total": alerts,
            "alerts_critical": critical,
            "heartbeats": hb_count,
            "expected_heartbeats": expected_hb,
        }

        pdf_bytes = _build_report_pdf(report_data, client["username"])
        ok = email_report.send_report_email(
            to_email=client["email"],
            client_name=client["username"],
            month_label=month_label,
            pdf_bytes=pdf_bytes,
            uptime_pct=uptime_pct,
        )
        if ok:
            sent += 1

    logger.info("Emails mensais: %d enviados de %d clientes com email", sent, len(clients))


async def job_daily_report() -> None:
    """Roda as 23:59: gera relatorio PDF do dia para cada cliente ativo."""
    from datetime import datetime as _dt, timedelta as _td, date as _date
    from routes_client import _build_report_pdf

    today = _date.today()
    start = _dt(today.year, today.month, today.day)
    end = start + _td(days=1)

    clients = await db.list_clients()
    generated = 0
    for client in clients:
        if not client.get("active"):
            continue
        hostnames = client.get("hostnames", [])
        if not hostnames:
            continue

        placeholders = ", ".join(f"${i+1}" for i in range(len(hostnames)))
        p_start = f"${len(hostnames)+1}"
        p_end = f"${len(hostnames)+2}"
        params = [*hostnames, start, end]

        async with db.get_conn() as conn:
            hb_count = await conn.fetchval(f"""
                SELECT COUNT(*) FROM agent_heartbeats
                WHERE hostname IN ({placeholders}) AND ts BETWEEN {p_start} AND {p_end}
            """, *params)

            total_minutes = (end - start).total_seconds() / 60
            expected_hb = int(total_minutes / 5) * len(hostnames)
            uptime_pct = round((hb_count / max(expected_hb, 1)) * 100, 2)

            lat_stats = await conn.fetchrow(f"""
                SELECT ROUND(AVG(latency_ms)::numeric, 1) AS avg_ms,
                       ROUND(MAX(latency_ms)::numeric, 1) AS max_ms,
                       ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms)::numeric, 1) AS p95_ms,
                       COUNT(*) AS total_checks,
                       SUM(CASE WHEN NOT success THEN 1 ELSE 0 END) AS failures
                FROM dns_checks
                WHERE hostname IN ({placeholders}) AND ts BETWEEN {p_start} AND {p_end}
                      AND latency_ms IS NOT NULL
            """, *params) or {}

            alerts = await conn.fetchval(f"""
                SELECT COUNT(*) FROM alerts_log
                WHERE hostname IN ({placeholders}) AND ts BETWEEN {p_start} AND {p_end}
            """, *params)
            critical = await conn.fetchval(f"""
                SELECT COUNT(*) FROM alerts_log
                WHERE hostname IN ({placeholders}) AND ts BETWEEN {p_start} AND {p_end}
                      AND severity = 'critical'
            """, *params)

        report_data = {
            "period": {"start": start.isoformat(), "end": end.isoformat()},
            "hostnames": hostnames,
            "uptime_pct": uptime_pct,
            "downtime_minutes": round(total_minutes * (1 - uptime_pct / 100)),
            "latency": dict(lat_stats) if lat_stats else {},
            "alerts_total": alerts,
            "alerts_critical": critical,
            "heartbeats": hb_count,
            "expected_heartbeats": expected_hb,
        }

        pdf_bytes = _build_report_pdf(report_data, client["username"])
        await db.save_daily_report(today, client["id"], pdf_bytes)
        generated += 1

    logger.info("Daily reports: %d gerados para %s", generated, today)


def setup_scheduler(scheduler) -> None:
    """Registra todos os jobs no scheduler e inicia."""
    scheduler.add_job(job_check_offline,   "interval", minutes=5,  id="check_offline")
    scheduler.add_job(job_purge_inactive,  "interval", hours=1,    id="purge_inactive")
    scheduler.add_job(job_monthly_email,   "cron", day=1, hour=8, minute=0, id="monthly_email")
    scheduler.add_job(job_daily_report,    "cron", hour=23, minute=59, id="daily_report")
    for t in REPORT_TIMES:
        h, m = t.split(":")
        scheduler.add_job(
            job_send_report, "cron",
            hour=int(h), minute=int(m),
            id=f"report_{t.replace(':', '')}",
        )
    scheduler.start()
    logger.info("Scheduler: offline 5min, relatorios %s, daily 23:59, email mensal dia 1", REPORT_TIMES)
