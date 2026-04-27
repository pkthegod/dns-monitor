"""
main.py — Backend central do Infra-Vision.
Recebe metricas dos agentes, persiste no TimescaleDB,
e executa o scheduler de alertas via APScheduler.
"""

import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
import pathlib
import json
import secrets
import hashlib
from datetime import date, datetime
from decimal import Decimal

import db
import telegram_bot as tg

# -- Modulos extraidos -------------------------------------------------------
# Reload cascata: importlib.reload(main) nos testes precisa re-ler env vars
import importlib as _il
import auth as _auth_mod
_il.reload(_auth_mod)
import models as _models_mod
_il.reload(_models_mod)
import routes_client as _rc_mod
_il.reload(_rc_mod)

# Re-exporta para compatibilidade com testes (import main as m; m.AgentPayload)
from models import (  # noqa: F401
    DnsServiceModel, DnsCheckModel, CpuModel, RamModel, DiskModel,
    IoModel, LoadModel, SystemModel, AgentPayload, AgentMetaUpdate,
    SpeedtestDomainModel, SpeedtestPayload,
)
from auth import (  # noqa: F401
    AGENT_TOKEN, require_token, require_admin, require_admin_role, require_client,
    ADMIN_USER, ADMIN_PASSWORD,
    _check_rate_limit, _record_failed_login, _clear_login_attempts,
    _check_cooldown, _record_action,
    _sign_admin_cookie, _verify_admin_cookie,
    _sign_client_cookie, _verify_client_cookie,
    _hash_password, _verify_password,
    _ADMIN_SESSION_TTL, _CLIENT_SESSION_TTL,
)
from routes_client import (  # noqa: F401
    client_v1,
    client_login_page, client_login_post, client_logout, client_portal,
    client_data, client_dns_test, client_dns_trace, client_report,
    list_clients_endpoint, create_client_endpoint,
    update_client_endpoint, delete_client_endpoint,
    list_client_reports, download_client_report,
    list_all_reports, download_report_admin,
)

try:
    import nats_client as nc
except ImportError:
    nc = None  # nats-py nao instalado — NATS desabilitado

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("infra-vision.api")

# ---------------------------------------------------------------------------
# Serializacao JSON — converte tipos do asyncpg nao suportados pelo json nativo
# ---------------------------------------------------------------------------

def _jsonify(obj) -> str:
    """Serializa datetime, Decimal e outros tipos do asyncpg para JSON."""
    def default(o):
        if isinstance(o, (datetime, date)):
            return o.isoformat()
        if isinstance(o, Decimal):
            return float(o)
        return str(o)
    return json.dumps(obj, default=default)


class _SafeJSONResponse(JSONResponse):
    """JSONResponse que usa _jsonify para lidar com datetime e Decimal."""
    def render(self, content) -> bytes:
        return _jsonify(content).encode("utf-8")


# ---------------------------------------------------------------------------
# Thresholds (lidos de env, com defaults sensatos)
# ---------------------------------------------------------------------------

THRESHOLDS = {
    "cpu_warning":          int(os.environ.get("THRESH_CPU_WARNING",          "80")),
    "cpu_critical":         int(os.environ.get("THRESH_CPU_CRITICAL",         "95")),
    "ram_warning":          int(os.environ.get("THRESH_RAM_WARNING",          "85")),
    "ram_critical":         int(os.environ.get("THRESH_RAM_CRITICAL",         "95")),
    "disk_warning":         int(os.environ.get("THRESH_DISK_WARNING",         "80")),
    "disk_critical":        int(os.environ.get("THRESH_DISK_CRITICAL",        "90")),
    "dns_latency_warning":  int(os.environ.get("THRESH_DNS_LATENCY_WARNING",  "200")),
    "dns_latency_critical": int(os.environ.get("THRESH_DNS_LATENCY_CRITICAL", "1000")),
    "offline_minutes":      int(os.environ.get("THRESH_OFFLINE_MINUTES",      "10")),
}

# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

scheduler = AsyncIOScheduler(timezone="America/Sao_Paulo")

REPORT_TIMES = ["00:00", "06:00", "12:00", "18:00"]


async def job_check_offline() -> None:
    """Roda a cada 5 min: detecta agentes offline e dispara alerta."""
    offline = await db.get_agents_offline(THRESHOLDS["offline_minutes"])
    for agent in offline:
        hostname = agent["hostname"]
        open_alerts = await db.get_open_alerts(hostname)
        already_open = any(a["alert_type"] == "offline" for a in open_alerts)
        if not already_open:
            alert_id = await db.insert_alert(
                hostname=hostname,
                alert_type="offline",
                severity="critical",
                message=f"Agente {hostname} sem heartbeat por mais de {THRESHOLDS['offline_minutes']} minutos",
            )
            sent = await tg.alert_agent_offline(hostname, agent.get("last_seen"))
            if sent:
                await db.mark_alert_notified(alert_id)
            logger.warning("Agente offline detectado: %s", hostname)


async def job_send_report() -> None:
    """Envia relatorio consolidado ao Telegram."""
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

    disk_warn = await db.get_all_disk_alerts()
    open_alerts = await db.get_open_alerts()

    await tg.send_report(
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


def setup_scheduler() -> None:
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


# ---------------------------------------------------------------------------
# Lifecycle FastAPI
# ---------------------------------------------------------------------------

async def _handle_command_ack(msg):
    """Recebe resultado de comando via NATS (dns.commands.{hostname}.ack)."""
    try:
        data = json.loads(msg.data.decode())
        cmd_id = data.get("command_id")
        cmd_status = data.get("status", "done")
        result = data.get("result", "")
        if cmd_id:
            await db.mark_command_done(cmd_id, cmd_status, result)
            cmd = await db.get_command_by_id(cmd_id)
            if cmd:
                await tg.send_command_result(
                    hostname=cmd["hostname"], command=cmd["command"],
                    status=cmd_status, result=result,
                    issued_by=cmd["issued_by"] or "admin",
                )
            logger.info("NATS ACK: comando #%s -> %s", cmd_id, cmd_status)
        await msg.ack()
    except Exception as exc:
        logger.error("NATS ACK handler erro: %s", exc)


async def _setup_nats_subscriptions():
    """Registra subscriptions NATS no backend."""
    if nc:
        await nc.js_subscribe("dns.commands.*.ack", _handle_command_ack, durable="backend-cmd-ack")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_pool()
    await db.apply_schema()
    if nc:
        await nc.connect()
        if nc.is_connected():
            await _setup_nats_subscriptions()
    setup_scheduler()
    logger.info("Backend Infra-Vision iniciado (NATS=%s)", "OK" if nc and nc.is_connected() else "offline")
    yield
    scheduler.shutdown(wait=False)
    if nc:
        await nc.close()
    await db.close_pool()
    logger.info("Backend encerrado")


from fastapi.staticfiles import StaticFiles

app = FastAPI(
    title="Infra-Vision — Backend",
    version="1.0.0",
    description="""
API do Infra-Vision — sistema distribuido de monitoramento DNS.

## Autenticacao

Todos os endpoints `/api/v1/*` exigem autenticacao via **Bearer token**:

```
Authorization: Bearer <AGENT_TOKEN>
```

Endpoints do portal do cliente usam autenticacao via **cookie de sessao** (login em `/client/login`).

## Exemplos rapidos

```bash
# Health check
curl http://localhost:8000/health

# Listar agentes
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/agents

# Enviar comando
curl -X POST -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"hostname":"dns01","command":"restart"}' \\
  http://localhost:8000/api/v1/commands
```
""",
    lifespan=lifespan,
    openapi_tags=[
        {"name": "agents", "description": "Gerenciamento de agentes DNS"},
        {"name": "commands", "description": "Comandos remotos para agentes"},
        {"name": "alerts", "description": "Alertas e notificacoes"},
        {"name": "metrics", "description": "Ingestao de metricas dos agentes"},
        {"name": "dashboard", "description": "Dados agregados para dashboards"},
        {"name": "clients", "description": "CRUD de clientes do portal"},
        {"name": "tools", "description": "Ferramentas auxiliares (geolocalizacao, etc.)"},
    ],
)

from middlewares import (  # noqa: F401
    APIRateLimitMiddleware, CSRFMiddleware, SecurityMonitorMiddleware,
    RequestLoggingMiddleware, SecurityHeadersMiddleware, RequestSizeLimitMiddleware,
    _security_alert,
)


def _html_with_nonce(html: str, nonce: str) -> str:
    """Injeta nonce CSP em todas as tags <script> de um HTML."""
    import re as _re_nonce
    html = _re_nonce.sub(r'<script(?!\s+nonce)', f'<script nonce="{nonce}"', html)
    return html


from ws import ws_manager, register_websocket  # noqa: F401

register_websocket(app)


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CSRFMiddleware)
app.add_middleware(APIRateLimitMiddleware)
app.add_middleware(RequestSizeLimitMiddleware)
app.add_middleware(SecurityMonitorMiddleware)
app.add_middleware(RequestLoggingMiddleware)

app.mount("/static", StaticFiles(directory=str(pathlib.Path(__file__).parent / "static")), name="static")

# ---------------------------------------------------------------------------
# API Router versionado — todas as rotas de API ficam sob /api/v1
# ---------------------------------------------------------------------------
v1 = APIRouter(prefix="/api/v1")

import re as _re
AGENT_FILE_PATH = pathlib.Path(
    os.environ.get(
        "AGENT_FILE_PATH",
        str(pathlib.Path(__file__).parent.parent / "agent" / "dns_agent.py"),
    )
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@v1.post("/metrics", dependencies=[Depends(require_token)], tags=["metrics"])
async def receive_metrics(payload: AgentPayload) -> JSONResponse:
    """
    Recebe o payload do agente (check ou heartbeat),
    persiste todas as metricas e dispara alertas se necessario.
    """
    hostname = payload.hostname
    ts       = payload.timestamp

    import re as _re_val
    if not _re_val.match(r'^[a-zA-Z0-9._-]{1,128}$', hostname):
        return JSONResponse({"error": "hostname invalido"}, status_code=422)

    agent_meta = await db.upsert_agent(
        hostname,
        ts,
        display_name  = getattr(payload, "display_name", None),
        location      = getattr(payload, "location", None),
        agent_version = payload.agent_version or None,
    )
    if agent_meta.get("is_new"):
        logger.info("Novo agente detectado: %s", hostname)
        await tg.send_new_agent_detected(hostname, payload.agent_version or "")

    if payload.fingerprint:
        fp_result = await db.upsert_fingerprint(hostname, payload.fingerprint)
        if fp_result.get("changed"):
            logger.warning(
                "ALERTA: fingerprint mudou para '%s'. Anterior: %s | Atual: %s",
                hostname, fp_result.get("previous"), payload.fingerprint
            )

    await db.insert_heartbeat(hostname, ts, payload.agent_version)

    if payload.system:
        sys = payload.system
        if sys.cpu:
            await db.insert_metrics_cpu(hostname, ts, sys.cpu.model_dump(), (sys.load or LoadModel()).model_dump())
        if sys.ram:
            await db.insert_metrics_ram(hostname, ts, sys.ram.model_dump())
        if sys.disk:
            await db.insert_metrics_disk(hostname, ts, [d.model_dump() for d in sys.disk])
        if sys.io:
            await db.insert_metrics_io(hostname, ts, sys.io.model_dump())

    if payload.dns_service:
        await db.insert_dns_service_status(hostname, ts, payload.dns_service.model_dump())
    if payload.dns_checks:
        await db.insert_dns_checks(hostname, ts, [c.model_dump() for c in payload.dns_checks])

    await _evaluate_alerts(payload)
    await db.resolve_alert(hostname, "offline")

    # Push real-time via WebSocket
    if ws_manager.count > 0:
        ws_data = {"event": "metrics", "hostname": hostname, "type": payload.type}
        if payload.system and payload.system.cpu:
            ws_data["cpu"] = payload.system.cpu.percent
        if payload.system and payload.system.ram:
            ws_data["ram"] = payload.system.ram.percent
        if payload.dns_checks:
            ws_data["dns_ok"] = all(c.success for c in payload.dns_checks)
        await ws_manager.broadcast(ws_data)

    return JSONResponse({"status": "ok", "hostname": hostname, "type": payload.type})


async def _evaluate_alerts(payload: AgentPayload) -> None:
    """Avalia thresholds e dispara alertas via Telegram quando necessario."""
    hostname = payload.hostname
    sys = payload.system

    if sys:
        if sys.cpu and sys.cpu.percent is not None:
            pct = sys.cpu.percent
            if pct >= THRESHOLDS["cpu_critical"]:
                aid = await db.insert_alert(hostname, "cpu", "critical", f"CPU {pct:.1f}%", "cpu_percent", pct, THRESHOLDS["cpu_critical"])
                if await tg.alert_cpu(hostname, pct, THRESHOLDS["cpu_critical"], "critical"):
                    await db.mark_alert_notified(aid)
            elif pct >= THRESHOLDS["cpu_warning"]:
                if not await db.has_open_alert(hostname, "cpu"):
                    await db.insert_alert(hostname, "cpu", "warning", f"CPU {pct:.1f}%", "cpu_percent", pct, THRESHOLDS["cpu_warning"])

        if sys.ram and sys.ram.percent is not None:
            pct = sys.ram.percent
            if pct >= THRESHOLDS["ram_critical"]:
                aid = await db.insert_alert(hostname, "ram", "critical", f"RAM {pct:.1f}%", "ram_percent", pct, THRESHOLDS["ram_critical"])
                if await tg.alert_ram(hostname, pct, THRESHOLDS["ram_critical"], "critical"):
                    await db.mark_alert_notified(aid)
            elif pct >= THRESHOLDS["ram_warning"]:
                if not await db.has_open_alert(hostname, "ram"):
                    await db.insert_alert(hostname, "ram", "warning", f"RAM {pct:.1f}%", "ram_percent", pct, THRESHOLDS["ram_warning"])

        for disk in (sys.disk or []):
            if disk.alert in ("warning", "critical") and disk.percent is not None:
                threshold = THRESHOLDS[f"disk_{disk.alert}"]
                aid = await db.insert_alert(hostname, "disk", disk.alert, f"Disco {disk.mountpoint} {disk.percent:.1f}%", "disk_percent", disk.percent, threshold)
                if disk.alert == "critical":
                    if await tg.alert_disk(hostname, disk.mountpoint or "?", disk.percent, threshold, "critical"):
                        await db.mark_alert_notified(aid)

    for check in (payload.dns_checks or []):
        if not check.success:
            aid = await db.insert_alert(hostname, "dns_fail", "critical", f"DNS falhou: {check.domain} ({check.error})", "dns_success", 0, 1)
            if await tg.alert_dns_failure(hostname, check.domain, check.error or "unknown", check.attempts or 0):
                await db.mark_alert_notified(aid)
        elif check.latency_ms is not None:
            if check.latency_ms >= THRESHOLDS["dns_latency_critical"]:
                aid = await db.insert_alert(hostname, "dns_latency", "critical", f"DNS latencia {check.latency_ms:.0f}ms para {check.domain}", "latency_ms", check.latency_ms, THRESHOLDS["dns_latency_critical"])
                if await tg.alert_dns_latency(hostname, check.domain, check.latency_ms, THRESHOLDS["dns_latency_critical"], "critical"):
                    await db.mark_alert_notified(aid)
            elif check.latency_ms >= THRESHOLDS["dns_latency_warning"]:
                if not await db.has_open_alert(hostname, "dns_latency"):
                    await db.insert_alert(hostname, "dns_latency", "warning", f"DNS latencia {check.latency_ms:.0f}ms para {check.domain}", "latency_ms", check.latency_ms, THRESHOLDS["dns_latency_warning"])

    if payload.dns_service and payload.dns_service.active is False:
        svc = payload.dns_service.name or "unknown"
        aid = await db.insert_alert(hostname, "dns_service", "critical", f"Servico DNS '{svc}' inativo")
        if await tg.alert_dns_service_down(hostname, svc):
            await db.mark_alert_notified(aid)

    # Dispatch webhooks para clientes que monitoram este hostname
    await _dispatch_webhooks_for_host(hostname, payload)


async def _dispatch_webhooks_for_host(hostname: str, payload: AgentPayload) -> None:
    """Envia alertas critical via webhook para clientes que monitoram este host."""
    import webhooks
    try:
        clients = await db.list_clients()
    except Exception:
        return  # DB indisponivel — nao bloqueia o fluxo de metricas
    for client in clients:
        if not client.get("webhook_url") or not client.get("active"):
            continue
        if hostname not in (client.get("hostnames") or []):
            continue
        # So dispara webhook para alertas critical reais
        alerts = []
        if payload.dns_service and payload.dns_service.active is False:
            alerts.append(("dns_service", "critical", f"Servico DNS inativo em {hostname}"))
        for check in (payload.dns_checks or []):
            if not check.success:
                alerts.append(("dns_fail", "critical", f"DNS falhou: {check.domain}"))
        sys = payload.system
        if sys and sys.cpu and sys.cpu.percent and sys.cpu.percent >= THRESHOLDS["cpu_critical"]:
            alerts.append(("cpu", "critical", f"CPU {sys.cpu.percent:.1f}%"))
        if sys and sys.ram and sys.ram.percent and sys.ram.percent >= THRESHOLDS["ram_critical"]:
            alerts.append(("ram", "critical", f"RAM {sys.ram.percent:.1f}%"))

        for alert_type, severity, message in alerts:
            webhooks.send_webhook(client["webhook_url"], alert_type, severity, hostname, message)


@v1.patch("/agents/{hostname}", dependencies=[Depends(require_admin_role)], tags=["agents"])
async def update_agent(hostname: str, body: AgentMetaUpdate) -> JSONResponse:
    """Atualiza display_name, location e notes de um agente."""
    found = await db.update_agent_meta(
        hostname, body.display_name, body.location, body.notes, body.active
    )
    if not found:
        raise HTTPException(status_code=404, detail="Agente nao encontrado")
    return JSONResponse({"status": "ok", "hostname": hostname})


@v1.delete("/agents/{hostname}", dependencies=[Depends(require_admin_role)], tags=["agents"])
async def delete_agent(hostname: str) -> JSONResponse:
    """Remove o agente e todo o historico de dados do banco."""
    found = await db.delete_agent(hostname)
    if not found:
        raise HTTPException(status_code=404, detail="Agente nao encontrado")
    logger.info("Agente removido: %s", hostname)
    return JSONResponse({"status": "ok", "hostname": hostname})


@v1.get("/agents", dependencies=[Depends(require_admin)], tags=["agents"])
async def list_agents(request: Request) -> _SafeJSONResponse:
    """Lista status atual de todos os agentes registrados."""
    async with db.get_conn() as conn:
        rows = await conn.fetch("SELECT * FROM v_agent_current_status ORDER BY hostname")
    return _SafeJSONResponse([dict(r) for r in rows])


@v1.get("/alerts", dependencies=[Depends(require_admin)], tags=["alerts"])
async def list_alerts(hostname: Optional[str] = None) -> _SafeJSONResponse:
    """Lista alertas abertos."""
    alerts = await db.get_open_alerts(hostname)
    return _SafeJSONResponse(alerts)


@v1.get("/commands/{hostname}", tags=["commands"])
async def get_commands(hostname: str, request: Request) -> _SafeJSONResponse:
    """Retorna comandos pendentes para o agente. Chamado pelo agente no poll."""
    await require_token(request)
    commands = await db.get_pending_commands(hostname)
    return _SafeJSONResponse(commands)


@v1.post("/commands/{command_id}/result", tags=["commands"])
async def post_command_result(command_id: int, request: Request) -> JSONResponse:
    """Agente reporta o resultado de um comando executado."""
    await require_token(request)
    body = await request.json()
    cmd_status = body.get("status", "done")   # 'done' | 'failed'
    result = body.get("result", "")
    if cmd_status not in ("done", "failed"):
        return JSONResponse({"error": "status deve ser 'done' ou 'failed'"}, status_code=422)

    await db.mark_command_done(command_id, cmd_status, result)

    cmd = await db.get_command_by_id(command_id)
    if cmd:
        await tg.send_command_result(
            hostname  = cmd["hostname"],
            command   = cmd["command"],
            status    = cmd_status,
            result    = result,
            issued_by = cmd["issued_by"] or "admin",
        )

    return JSONResponse({"status": "ok"})


@v1.post("/commands", tags=["commands"])
async def create_command(request: Request) -> JSONResponse:
    """
    Cria um comando para um agente executar no proximo poll.
    """
    info = await require_admin_role(request)
    body = await request.json()
    hostname = body.get("hostname", "").strip()
    command  = body.get("command",  "").strip()
    issued_by = body.get("issued_by", info["username"])
    expires_hours = body.get("expires_hours")
    params = body.get("params")

    if not hostname or not command:
        return JSONResponse({"error": "hostname e command sao obrigatorios"}, status_code=422)

    confirm_token = None
    if command == "purge":
        confirm_token = secrets.token_hex(8)

    try:
        cmd_id = await db.insert_command(
            hostname, command, issued_by, confirm_token, expires_hours, params
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=422)

    response = {"id": cmd_id, "hostname": hostname, "command": command, "status": "pending"}
    if confirm_token:
        response["confirm_token"] = confirm_token
        response["warning"] = "purge e irreversivel. Anote o confirm_token."

    await db.audit(issued_by, "command", hostname, detail=command)
    nats_sent = False
    if nc and nc.is_connected():
        nats_sent = await nc.js_publish(f"dns.commands.{hostname}", {
            "id": cmd_id, "command": command,
            "confirm_token": confirm_token, "params": params,
        })
    response["nats"] = "sent" if nats_sent else "fallback_http"

    return JSONResponse(response, status_code=201)


@v1.get("/commands/{hostname}/history", tags=["commands"])
async def get_command_history(hostname: str, request: Request) -> _SafeJSONResponse:
    """Historico de comandos executados em um host."""
    await require_admin(request)
    history = await db.get_commands_history(hostname)
    return _SafeJSONResponse(history)


# ---------------------------------------------------------------------------
# Admin pages
# ---------------------------------------------------------------------------

@app.get("/admin/login", response_class=HTMLResponse, include_in_schema=False)
async def admin_login_page(request: Request) -> HTMLResponse:
    """Formulario de login do painel admin."""
    html_path = pathlib.Path(__file__).parent / "static" / "login.html"
    html = html_path.read_text(encoding="utf-8")
    nonce = getattr(request.state, "csp_nonce", "")
    return HTMLResponse(_html_with_nonce(html, nonce))


@app.post("/admin/login", include_in_schema=False)
async def admin_login_post(request: Request):
    """Valida credenciais contra DB primeiro, depois fallback para env vars."""
    ip = request.client.host if request.client else "unknown"
    if _check_rate_limit(ip):
        return RedirectResponse("/admin/login?error=locked", status_code=303)

    form = await request.form()
    username = form.get("username", "")
    password = form.get("password", "")

    role = None
    _dummy_hash = "$2b$12$000000000000000000000uGPOaHLkG6VgbGG7ZtBCRqGz4eXxWfS"

    # 1. Tenta DB admin_users primeiro
    db_user = await db.authenticate_admin_user(username)
    if db_user and _verify_password(password, db_user["password_hash"]):
        role = db_user["role"]
    # 2. Fallback env var superadmin
    elif ADMIN_USER and ADMIN_PASSWORD:
        if secrets.compare_digest(username, ADMIN_USER) and \
           secrets.compare_digest(password, ADMIN_PASSWORD):
            role = "admin"
        else:
            _verify_password(password, _dummy_hash)  # equaliza timing
    else:
        _verify_password(password, _dummy_hash)  # equaliza timing

    if role is None:
        _record_failed_login(ip)
        logger.warning("Login admin falhado de %s (user=%s)", ip, username)
        await db.audit("admin", "login_failed", username, ip=ip)
        return RedirectResponse("/admin/login?error=1", status_code=303)

    _clear_login_attempts(ip)
    await db.audit("admin", "login_ok", username, ip=ip, detail=f"role={role}")
    resp = RedirectResponse("/admin", status_code=303)
    cookie_val = _sign_admin_cookie(username, role)
    _secure = os.environ.get("COOKIE_SECURE", "true").lower() in ("true", "1", "yes")
    resp.set_cookie("admin_session", cookie_val, httponly=True, secure=_secure, samesite="strict", max_age=_ADMIN_SESSION_TTL)
    return resp


@app.get("/admin/logout", include_in_schema=False)
async def admin_logout():
    """Limpa cookie de sessao e redireciona para login."""
    resp = RedirectResponse("/admin/login", status_code=303)
    resp.delete_cookie("admin_session")
    return resp


@app.get("/api/v1/session/whoami", include_in_schema=False)
async def session_whoami(request: Request) -> JSONResponse:
    """Retorna identidade da sessão SEM expor o AGENT_TOKEN.

    SEC: substitui o antigo /session/token. Antes, este endpoint entregava
    o AGENT_TOKEN para qualquer sessão (admin OU cliente), permitindo que
    um cliente do portal chamasse rotas administrativas como /commands.
    Agora frontend (admin/cliente) usa cookies via credentials=same-origin.
    """
    info = _verify_admin_cookie(request.cookies.get("admin_session", ""))
    if info:
        return JSONResponse({"kind": "admin", "username": info["username"], "role": info["role"]})
    client_user = _verify_client_cookie(request.cookies.get("client_session", ""))
    if client_user:
        user = await db.get_client(client_user)
        if user and user.get("active"):
            return JSONResponse({
                "kind": "client",
                "username": client_user,
                "hostnames": user.get("hostnames", []),
            })
    raise HTTPException(status_code=401, detail="Sessao invalida")


# Rota legada: mantida APENAS para detectar uso indevido e quebrar com erro claro.
# Frontends antigos que ainda chamem /session/token recebem 410 e log de warning.
@app.get("/api/v1/session/token", include_in_schema=False)
async def session_token_deprecated(request: Request) -> JSONResponse:
    ip = request.client.host if request.client else "?"
    logger.warning("DEPRECATED: /session/token chamado de %s — atualizar frontend para /session/whoami", ip)
    raise HTTPException(
        status_code=410,  # Gone
        detail="Endpoint removido por motivos de seguranca. Use /api/v1/session/whoami.",
    )


@app.get("/admin", response_class=HTMLResponse, include_in_schema=False)
async def admin_panel(request: Request) -> HTMLResponse:
    """Painel de administracao — protegido por cookie de sessao."""
    cookie = request.cookies.get("admin_session", "")
    if not _verify_admin_cookie(cookie):
        return RedirectResponse("/admin/login", status_code=303)
    html_path = pathlib.Path(__file__).parent / "static" / "admin.html"
    nonce = getattr(request.state, "csp_nonce", "")
    return HTMLResponse(_html_with_nonce(html_path.read_text(encoding="utf-8"), nonce))


@v1.get("/security/blocked", tags=["tools"], dependencies=[Depends(require_admin)])
async def list_blocked_ips() -> JSONResponse:
    """Lista IPs bloqueados pelo security monitor."""
    import security
    return JSONResponse(security.get_blocked_ips())


@v1.delete("/security/blocked", tags=["tools"], dependencies=[Depends(require_admin)])
async def unblock_all_ips() -> JSONResponse:
    """Desbloqueia todos os IPs."""
    import security
    count = security.unblock_all()
    return JSONResponse({"unblocked": count})


@v1.delete("/security/blocked/{ip}", tags=["tools"], dependencies=[Depends(require_admin)])
async def unblock_ip(ip: str) -> JSONResponse:
    """Desbloqueia um IP especifico."""
    import security
    found = security.unblock_ip(ip)
    return JSONResponse({"ip": ip, "was_blocked": found})


@v1.get("/commands/history", tags=["commands"])
async def get_all_commands_history(request: Request, limit: int = 50) -> _SafeJSONResponse:
    """Historico recente de todos os comandos (para o painel admin)."""
    await require_admin(request)
    history = await db.get_all_commands_history(limit)
    return _SafeJSONResponse(history)


@v1.get("/agent/version", tags=["agents"])
async def agent_version_info(request: Request) -> JSONResponse:
    await require_token(request)
    if not AGENT_FILE_PATH.exists():
        raise HTTPException(status_code=404, detail="Arquivo do agente nao encontrado no servidor")
    content = AGENT_FILE_PATH.read_text(encoding="utf-8")
    m = _re.search(r'^AGENT_VERSION\s*=\s*["\']([^"\']+)["\']', content, _re.MULTILINE)
    version  = m.group(1) if m else "unknown"
    checksum = hashlib.sha256(content.encode()).hexdigest()
    return JSONResponse({
        "version":  version,
        "checksum": checksum,
        "size":     len(content.encode()),
    })


@v1.get("/agent/latest", tags=["agents"])
async def agent_latest_download(request: Request):
    await require_token(request)
    if not AGENT_FILE_PATH.exists():
        raise HTTPException(status_code=404, detail="Arquivo do agente nao encontrado no servidor")
    from fastapi.responses import PlainTextResponse
    content = AGENT_FILE_PATH.read_text(encoding="utf-8")
    checksum = hashlib.sha256(content.encode()).hexdigest()
    return PlainTextResponse(
        content,
        media_type="text/x-python",
        headers={"X-Agent-Checksum": checksum},
    )


@v1.post("/tools/geolocate", dependencies=[Depends(require_admin_role)], tags=["tools"])
async def geolocate_ips(request: Request) -> JSONResponse:
    import asyncio
    import urllib.request as _urllib
    import json as _json

    body = await request.json()
    ips  = list(dict.fromkeys(str(ip) for ip in body.get("ips", []) if ip))[:100]
    if not ips:
        return JSONResponse([])

    payload = _json.dumps([{"query": ip} for ip in ips]).encode()

    def _fetch():
        try:
            req = _urllib.Request(
                "http://ip-api.com/batch"
                "?fields=query,status,country,countryCode,regionName,city,isp,org,lat,lon",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with _urllib.urlopen(req, timeout=10) as resp:
                return _json.loads(resp.read().decode())
        except Exception as exc:
            logger.warning("geolocate: ip-api.com falhou: %s", exc)
            return [{"query": ip, "status": "fail"} for ip in ips]

    loop = asyncio.get_running_loop()
    data = await loop.run_in_executor(None, _fetch)
    return JSONResponse(data)


@v1.get("/commands/{command_id}/status", tags=["commands"])
async def get_command_status(command_id: int, request: Request) -> _SafeJSONResponse:
    """Retorna o status atual de um comando.

    SEC: admin vê tudo; cliente só vê comandos de hostnames associados a ele.
    Antes, ambos usavam require_token com AGENT_TOKEN compartilhado, permitindo
    que um cliente lesse comandos de hosts de outros clientes.
    """
    cmd = await db.get_command_by_id(command_id)
    if not cmd:
        raise HTTPException(status_code=404, detail="Comando nao encontrado")

    # Admin: acesso irrestrito
    admin_info = _verify_admin_cookie(request.cookies.get("admin_session", ""))
    auth = request.headers.get("Authorization", "")
    if admin_info or (auth.startswith("Bearer ") and AGENT_TOKEN and
                 secrets.compare_digest(auth[7:], AGENT_TOKEN)):
        return _SafeJSONResponse(cmd)

    # Cliente: só comandos de seus hostnames
    client_username = _verify_client_cookie(request.cookies.get("client_session", ""))
    if client_username:
        user = await db.get_client(client_username)
        if user and user.get("active") and cmd.get("hostname") in (user.get("hostnames") or []):
            return _SafeJSONResponse(cmd)

    raise HTTPException(status_code=403, detail="Acesso negado")


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard_page(request: Request) -> HTMLResponse:
    """Dashboard de metricas."""
    html_path = pathlib.Path(__file__).parent / "static" / "dashboard.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="Dashboard nao encontrado")
    nonce = getattr(request.state, "csp_nonce", "")
    return HTMLResponse(_html_with_nonce(html_path.read_text(encoding="utf-8"), nonce))


@v1.get("/dashboard/data", dependencies=[Depends(require_admin)], tags=["dashboard"])
async def dashboard_data(period: str = "24h", host: str = "") -> _SafeJSONResponse:
    """Dados agregados para o dashboard. Aceita ?period=1h|6h|24h|7d&host=hostname."""
    hostnames = None
    if host and _re.match(r'^[a-zA-Z0-9._-]+$', host):
        hostnames = [host]
    data = await db.get_aggregated_metrics(period, hostnames)
    return _SafeJSONResponse(data)


# ---------------------------------------------------------------------------
# Speedtest — Domain SSL/Port checker (medidores)
# ---------------------------------------------------------------------------

@v1.post("/speedtest", dependencies=[Depends(require_token)], tags=["speedtest"])
async def ingest_speedtest(payload: SpeedtestPayload) -> JSONResponse:
    """Recebe JSON validado do script domain checker (speedtest)."""
    metadata = payload.metadata
    summary = payload.summary
    domains = [d.model_dump() for d in payload.domains]
    scan_id = await db.insert_speedtest_scan(metadata, summary, domains)
    logger.info("Speedtest ingerido: scan_id=%d, domains=%d", scan_id, len(domains))
    return JSONResponse({"status": "ok", "scan_id": scan_id, "domains": len(domains)}, status_code=201)


@v1.get("/speedtest/data", dependencies=[Depends(require_admin)], tags=["speedtest"])
async def speedtest_data_endpoint() -> _SafeJSONResponse:
    """Dados do ultimo scan + historico para o frontend."""
    latest = await db.get_latest_speedtest()
    history = await db.get_speedtest_history(30)
    return _SafeJSONResponse({"latest": latest, "history": history})


@app.get("/speedtest", response_class=HTMLResponse, include_in_schema=False)
async def speedtest_page(request: Request) -> HTMLResponse:
    """Pagina Speedtest — verificacao de dominios/SSL."""
    cookie = request.cookies.get("admin_session", "")
    if not _verify_admin_cookie(cookie):
        return RedirectResponse("/admin/login", status_code=303)
    html_path = pathlib.Path(__file__).parent / "static" / "speedtest.html"
    nonce = getattr(request.state, "csp_nonce", "")
    return HTMLResponse(_html_with_nonce(html_path.read_text(encoding="utf-8"), nonce))


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Serve favicon.svg como .ico fallback."""
    fav = pathlib.Path(__file__).parent / "static" / "favicon.svg"
    from fastapi.responses import FileResponse
    return FileResponse(fav, media_type="image/svg+xml")


@app.get("/health")
async def health() -> JSONResponse:
    """Healthcheck para Docker e load balancer."""
    try:
        async with db.get_conn() as conn:
            await conn.fetchval("SELECT 1")
        return JSONResponse({"status": "ok", "db": "connected"})
    except Exception as exc:
        logger.error("Health check falhou: %s", exc)
        return JSONResponse({"status": "error", "db": "unavailable"}, status_code=503)


# ---------------------------------------------------------------------------
# Admin user management (RBAC)
# ---------------------------------------------------------------------------

@v1.get("/admin-users", tags=["admin-users"])
async def list_admin_users_endpoint(request: Request) -> _SafeJSONResponse:
    """Lista todos os admin users (requer role=admin)."""
    await require_admin_role(request)
    users = await db.list_admin_users()
    return _SafeJSONResponse(users)


@v1.post("/admin-users", tags=["admin-users"])
async def create_admin_user_endpoint(request: Request) -> JSONResponse:
    """Cria um admin user (requer role=admin)."""
    caller = await require_admin_role(request)
    body = await request.json()
    username = body.get("username", "").strip()
    password = body.get("password", "").strip()
    role = body.get("role", "viewer").strip()
    notes = body.get("notes", "").strip() or None

    if not username or not password:
        return JSONResponse({"error": "username e password obrigatorios"}, status_code=422)
    if role not in ("admin", "viewer"):
        return JSONResponse({"error": "role deve ser 'admin' ou 'viewer'"}, status_code=422)
    if len(password) < 8:
        return JSONResponse({"error": "senha deve ter no minimo 8 caracteres"}, status_code=422)
    if ADMIN_USER and secrets.compare_digest(username, ADMIN_USER):
        return JSONResponse({"error": "username reservado (superadmin env var)"}, status_code=409)

    existing = await db.get_admin_user(username)
    if existing:
        return JSONResponse({"error": "username ja existe"}, status_code=409)

    pw_hash = _hash_password(password)
    user_id = await db.create_admin_user(username, pw_hash, role, caller["username"], notes)
    await db.audit(caller["username"], "admin_user_created", username, detail=f"role={role}")
    return JSONResponse({"id": user_id, "username": username, "role": role}, status_code=201)


@v1.patch("/admin-users/{user_id}", tags=["admin-users"])
async def update_admin_user_endpoint(user_id: int, request: Request) -> JSONResponse:
    """Atualiza um admin user (requer role=admin)."""
    caller = await require_admin_role(request)
    body = await request.json()
    fields = {}

    if "role" in body:
        if body["role"] not in ("admin", "viewer"):
            return JSONResponse({"error": "role deve ser 'admin' ou 'viewer'"}, status_code=422)
        fields["role"] = body["role"]
    if "active" in body:
        fields["active"] = body["active"]
    if "password" in body and body["password"]:
        if len(body["password"]) < 8:
            return JSONResponse({"error": "senha deve ter no minimo 8 caracteres"}, status_code=422)
        fields["password_hash"] = _hash_password(body["password"])
    if "notes" in body:
        fields["notes"] = body["notes"]

    if not fields:
        return JSONResponse({"error": "nenhum campo para atualizar"}, status_code=422)

    ok = await db.update_admin_user(user_id, **fields)
    if not ok:
        raise HTTPException(status_code=404, detail="Admin user nao encontrado")
    await db.audit(caller["username"], "admin_user_updated", str(user_id),
                   detail=str(list(fields.keys())))
    return JSONResponse({"status": "ok"})


@v1.delete("/admin-users/{user_id}", tags=["admin-users"])
async def delete_admin_user_endpoint(user_id: int, request: Request) -> JSONResponse:
    """Remove um admin user (requer role=admin). Nao pode deletar a si mesmo."""
    caller = await require_admin_role(request)

    target = await db.get_admin_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Admin user nao encontrado")
    if target["username"] == caller["username"]:
        return JSONResponse({"error": "Nao e possivel deletar o proprio usuario"}, status_code=422)

    ok = await db.delete_admin_user(user_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Admin user nao encontrado")
    await db.audit(caller["username"], "admin_user_deleted", target["username"])
    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------------------
# Compatibilidade com agentes antigos (v1.0.0) — rotas sem /api/v1 prefix
# ---------------------------------------------------------------------------
_legacy = APIRouter(tags=["legacy"], deprecated=True, include_in_schema=False)

_legacy.post("/metrics", dependencies=[Depends(require_token)])(receive_metrics)
_legacy.get("/agents", dependencies=[Depends(require_token)])(list_agents)
_legacy.patch("/agents/{hostname}", dependencies=[Depends(require_token)])(update_agent)
_legacy.delete("/agents/{hostname}", dependencies=[Depends(require_token)])(delete_agent)
_legacy.get("/alerts", dependencies=[Depends(require_token)])(list_alerts)
_legacy.get("/commands/{hostname}")(get_commands)
_legacy.post("/commands/{command_id}/result")(post_command_result)
_legacy.post("/commands")(create_command)
_legacy.get("/commands/{hostname}/history")(get_command_history)
_legacy.get("/commands/history")(get_all_commands_history)
_legacy.get("/commands/{command_id}/status")(get_command_status)
_legacy.get("/agent/version")(agent_version_info)
_legacy.get("/agent/latest")(agent_latest_download)
_legacy.post("/tools/geolocate", dependencies=[Depends(require_token)])(geolocate_ips)

app.include_router(_legacy)


# ---------------------------------------------------------------------------
# Rotas do portal do cliente (montadas no app)
# ---------------------------------------------------------------------------
app.get("/client/login", response_class=HTMLResponse, include_in_schema=False)(client_login_page)
app.post("/client/login", include_in_schema=False)(client_login_post)
app.get("/client/logout", include_in_schema=False)(client_logout)
app.get("/client", response_class=HTMLResponse, include_in_schema=False)(client_portal)


# ---------------------------------------------------------------------------
# Paginas de ajuda (docs in-app)
# ---------------------------------------------------------------------------

@app.get("/client/help", response_class=HTMLResponse, include_in_schema=False)
async def client_help_page(request: Request) -> HTMLResponse:
    html_path = pathlib.Path(__file__).parent / "static" / "client-help.html"
    nonce = getattr(request.state, "csp_nonce", "")
    return HTMLResponse(_html_with_nonce(html_path.read_text(encoding="utf-8"), nonce))


@app.get("/admin/help", response_class=HTMLResponse, include_in_schema=False)
async def admin_help_page(request: Request) -> HTMLResponse:
    cookie = request.cookies.get("admin_session", "")
    if not _verify_admin_cookie(cookie):
        return RedirectResponse("/admin/login", status_code=303)
    html_path = pathlib.Path(__file__).parent / "static" / "admin-help.html"
    nonce = getattr(request.state, "csp_nonce", "")
    return HTMLResponse(_html_with_nonce(html_path.read_text(encoding="utf-8"), nonce))

# ---------------------------------------------------------------------------
# Registra routers versionados (DEVE ficar depois de todos os endpoints)
# ---------------------------------------------------------------------------
v1.include_router(client_v1)
app.include_router(v1)
