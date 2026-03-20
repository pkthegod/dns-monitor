"""
main.py — Backend central do DNS Monitor.
Recebe métricas dos agentes, persiste no TimescaleDB,
e executa o scheduler de alertas via APScheduler.
"""

import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import db
import telegram_bot as tg

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("dns-monitor.api")

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
# Autenticação por token Bearer
# ---------------------------------------------------------------------------

AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")

async def require_token(request: Request) -> None:
    if not AGENT_TOKEN:
        logger.warning("AGENT_TOKEN não configurado — autenticação desativada!")
        return
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or auth[7:] != AGENT_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou ausente",
        )

# ---------------------------------------------------------------------------
# Modelos Pydantic (validação do payload do agente)
# ---------------------------------------------------------------------------

class DnsServiceModel(BaseModel):
    name:    Optional[str] = None
    active:  Optional[bool] = None
    version: Optional[str] = None

class DnsCheckModel(BaseModel):
    domain:       str
    resolver:     Optional[str] = None
    success:      bool
    latency_ms:   Optional[float] = None
    response_ips: Optional[list[str]] = Field(default_factory=list)
    error:        Optional[str] = None
    attempts:     Optional[int] = None

class CpuModel(BaseModel):
    percent:  Optional[float] = None
    count:    Optional[int]   = None
    freq_mhz: Optional[float] = None

class RamModel(BaseModel):
    percent:       Optional[float] = None
    used_mb:       Optional[float] = None
    total_mb:      Optional[float] = None
    swap_percent:  Optional[float] = None
    swap_used_mb:  Optional[float] = None
    swap_total_mb: Optional[float] = None

class DiskModel(BaseModel):
    mountpoint: Optional[str]   = None
    device:     Optional[str]   = None
    fstype:     Optional[str]   = None
    percent:    Optional[float] = None
    used_gb:    Optional[float] = None
    free_gb:    Optional[float] = None
    total_gb:   Optional[float] = None
    alert:      Optional[str]   = None

class IoModel(BaseModel):
    read_bytes:    Optional[int] = None
    write_bytes:   Optional[int] = None
    read_count:    Optional[int] = None
    write_count:   Optional[int] = None
    read_time_ms:  Optional[int] = None
    write_time_ms: Optional[int] = None

class LoadModel(BaseModel):
    load_1m:  Optional[float] = None
    load_5m:  Optional[float] = None
    load_15m: Optional[float] = None

class SystemModel(BaseModel):
    cpu:  Optional[CpuModel]        = None
    ram:  Optional[RamModel]        = None
    disk: Optional[list[DiskModel]] = Field(default_factory=list)
    io:   Optional[IoModel]         = None
    load: Optional[LoadModel]       = None

class AgentPayload(BaseModel):
    type:          str                       # "check" | "heartbeat"
    hostname:      str
    timestamp:     str
    agent_version: Optional[str]  = None
    dns_service:   Optional[DnsServiceModel] = None
    dns_checks:    Optional[list[DnsCheckModel]] = Field(default_factory=list)
    system:        Optional[SystemModel]     = None


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
        # Evita spam: só alerta se não há alerta aberto do mesmo tipo
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
    """Envia relatório consolidado ao Telegram."""
    from db import get_conn
    async with get_conn() as conn:
        rows = await conn.fetch("SELECT hostname, agent_status FROM v_agent_current_status")

    total   = len(rows)
    online  = sum(1 for r in rows if r["agent_status"] == "online")
    offline_list = [r["hostname"] for r in rows if r["agent_status"] in ("offline", "never_seen")]

    # Falhas DNS recentes (última hora)
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

    # Discos em alerta — query única para todos os agentes (sem N+1)
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
    logger.info("Relatório enviado ao Telegram")


def setup_scheduler() -> None:
    scheduler.add_job(job_check_offline, "interval", minutes=5, id="check_offline")
    for t in REPORT_TIMES:
        h, m = t.split(":")
        scheduler.add_job(
            job_send_report, "cron",
            hour=int(h), minute=int(m),
            id=f"report_{t.replace(':', '')}",
        )
    scheduler.start()
    logger.info("Scheduler iniciado: check_offline a cada 5min, relatórios em %s", REPORT_TIMES)


# ---------------------------------------------------------------------------
# Lifecycle FastAPI
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_pool()
    await db.apply_schema()
    setup_scheduler()
    logger.info("Backend DNS Monitor iniciado")
    yield
    scheduler.shutdown(wait=False)
    await db.close_pool()
    logger.info("Backend encerrado")


app = FastAPI(
    title="DNS Monitor — Backend",
    version="1.0.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/metrics", dependencies=[Depends(require_token)])
async def receive_metrics(payload: AgentPayload) -> JSONResponse:
    """
    Recebe o payload do agente (check ou heartbeat),
    persiste todas as métricas e dispara alertas se necessário.
    """
    hostname = payload.hostname
    ts       = payload.timestamp

    # Garante registro do agente
    await db.upsert_agent(hostname, ts)

    # Heartbeat sempre gravado
    await db.insert_heartbeat(hostname, ts, payload.agent_version)

    # Métricas do sistema (presentes em check e heartbeat)
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

    # Checks DNS e status do serviço (somente em "check")
    if payload.type == "check":
        if payload.dns_service:
            await db.insert_dns_service_status(hostname, ts, payload.dns_service.model_dump())
        if payload.dns_checks:
            await db.insert_dns_checks(hostname, ts, [c.model_dump() for c in payload.dns_checks])

    # Avalia e dispara alertas assincronamente
    await _evaluate_alerts(payload)

    # Agente que voltou online — resolve alerta offline aberto
    await db.resolve_alert(hostname, "offline")

    return JSONResponse({"status": "ok", "hostname": hostname, "type": payload.type})


async def _evaluate_alerts(payload: AgentPayload) -> None:
    """Avalia thresholds e dispara alertas via Telegram quando necessário."""
    hostname = payload.hostname
    sys = payload.system

    if sys:
        # CPU
        if sys.cpu and sys.cpu.percent is not None:
            pct = sys.cpu.percent
            if pct >= THRESHOLDS["cpu_critical"]:
                aid = await db.insert_alert(hostname, "cpu", "critical", f"CPU {pct:.1f}%", "cpu_percent", pct, THRESHOLDS["cpu_critical"])
                if await tg.alert_cpu(hostname, pct, THRESHOLDS["cpu_critical"], "critical"):
                    await db.mark_alert_notified(aid)
            elif pct >= THRESHOLDS["cpu_warning"]:
                if not await db.has_open_alert(hostname, "cpu"):
                    await db.insert_alert(hostname, "cpu", "warning", f"CPU {pct:.1f}%", "cpu_percent", pct, THRESHOLDS["cpu_warning"])

        # RAM
        if sys.ram and sys.ram.percent is not None:
            pct = sys.ram.percent
            if pct >= THRESHOLDS["ram_critical"]:
                aid = await db.insert_alert(hostname, "ram", "critical", f"RAM {pct:.1f}%", "ram_percent", pct, THRESHOLDS["ram_critical"])
                if await tg.alert_ram(hostname, pct, THRESHOLDS["ram_critical"], "critical"):
                    await db.mark_alert_notified(aid)
            elif pct >= THRESHOLDS["ram_warning"]:
                if not await db.has_open_alert(hostname, "ram"):
                    await db.insert_alert(hostname, "ram", "warning", f"RAM {pct:.1f}%", "ram_percent", pct, THRESHOLDS["ram_warning"])

        # Disco
        for disk in (sys.disk or []):
            if disk.alert in ("warning", "critical") and disk.percent is not None:
                threshold = THRESHOLDS[f"disk_{disk.alert}"]
                aid = await db.insert_alert(hostname, "disk", disk.alert, f"Disco {disk.mountpoint} {disk.percent:.1f}%", "disk_percent", disk.percent, threshold)
                if disk.alert == "critical":
                    if await tg.alert_disk(hostname, disk.mountpoint or "?", disk.percent, threshold, "critical"):
                        await db.mark_alert_notified(aid)

    # DNS checks
    for check in (payload.dns_checks or []):
        if not check.success:
            aid = await db.insert_alert(hostname, "dns_fail", "critical", f"DNS falhou: {check.domain} ({check.error})", "dns_success", 0, 1)
            if await tg.alert_dns_failure(hostname, check.domain, check.error or "unknown", check.attempts or 0):
                await db.mark_alert_notified(aid)
        elif check.latency_ms is not None:
            if check.latency_ms >= THRESHOLDS["dns_latency_critical"]:
                aid = await db.insert_alert(hostname, "dns_latency", "critical", f"DNS latência {check.latency_ms:.0f}ms para {check.domain}", "latency_ms", check.latency_ms, THRESHOLDS["dns_latency_critical"])
                if await tg.alert_dns_latency(hostname, check.domain, check.latency_ms, THRESHOLDS["dns_latency_critical"], "critical"):
                    await db.mark_alert_notified(aid)
            elif check.latency_ms >= THRESHOLDS["dns_latency_warning"]:
                if not await db.has_open_alert(hostname, "dns_latency"):
                    await db.insert_alert(hostname, "dns_latency", "warning", f"DNS latência {check.latency_ms:.0f}ms para {check.domain}", "latency_ms", check.latency_ms, THRESHOLDS["dns_latency_warning"])

    # Serviço DNS inativo
    if payload.dns_service and payload.dns_service.active is False:
        svc = payload.dns_service.name or "unknown"
        aid = await db.insert_alert(hostname, "dns_service", "critical", f"Serviço DNS '{svc}' inativo")
        if await tg.alert_dns_service_down(hostname, svc):
            await db.mark_alert_notified(aid)


@app.get("/agents")
async def list_agents(request: Request) -> JSONResponse:
    """Lista status atual de todos os agentes registrados."""
    async with db.get_conn() as conn:
        rows = await conn.fetch("SELECT * FROM v_agent_current_status ORDER BY hostname")
    return JSONResponse([dict(r) for r in rows])


@app.get("/alerts")
async def list_alerts(hostname: Optional[str] = None) -> JSONResponse:
    """Lista alertas abertos."""
    alerts = await db.get_open_alerts(hostname)
    return JSONResponse(alerts)


@app.get("/health")
async def health() -> JSONResponse:
    """Healthcheck para Docker e load balancer."""
    try:
        async with db.get_conn() as conn:
            await conn.fetchval("SELECT 1")
        return JSONResponse({"status": "ok", "db": "connected"})
    except Exception as exc:
        return JSONResponse({"status": "error", "db": str(exc)}, status_code=503)