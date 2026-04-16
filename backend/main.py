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
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
import pathlib
import json
import secrets
import hashlib
import hmac
from datetime import date, datetime
from decimal import Decimal
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
# Serialização JSON — converte tipos do asyncpg não suportados pelo json nativo
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
# Autenticação por token Bearer
# ---------------------------------------------------------------------------

AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")

async def require_token(request: Request) -> None:
    if not AGENT_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AGENT_TOKEN não configurado — backend recusa requests sem autenticação",
        )
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or auth[7:] != AGENT_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou ausente",
        )

# ---------------------------------------------------------------------------
# Autenticação do painel admin (cookie HMAC)
# ---------------------------------------------------------------------------

ADMIN_USER = os.environ.get("ADMIN_USER", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
_COOKIE_SECRET = (AGENT_TOKEN or "dns-monitor-fallback-key").encode()


def _sign_admin_cookie(username: str) -> str:
    """Gera cookie assinado: username.hex(hmac)"""
    sig = hmac.new(_COOKIE_SECRET, username.encode(), hashlib.sha256).hexdigest()
    return f"{username}.{sig}"


def _verify_admin_cookie(cookie: str) -> Optional[str]:
    """Verifica cookie assinado. Retorna username ou None."""
    if not cookie or "." not in cookie:
        return None
    username, sig = cookie.rsplit(".", 1)
    expected = hmac.new(_COOKIE_SECRET, username.encode(), hashlib.sha256).hexdigest()
    if hmac.compare_digest(sig, expected):
        return username
    return None


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
    fingerprint:   Optional[str]  = None     # SHA256 do hardware — detecta cópias
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


async def job_purge_inactive() -> None:
    """Roda a cada hora: deleta agentes inativos há mais de 3 dias."""
    deleted = await db.delete_inactive_agents()
    for hostname in deleted:
        logger.info("Auto-purge: agente inativo removido após 3 dias: %s", hostname)
        await tg.send_new_agent_detected(  # reutiliza notificação genérica
            hostname, "removido automaticamente (inativo > 3 dias)"
        )


def setup_scheduler() -> None:
    scheduler.add_job(job_check_offline,   "interval", minutes=5,  id="check_offline")
    scheduler.add_job(job_purge_inactive,  "interval", hours=1,    id="purge_inactive")
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


from fastapi.staticfiles import StaticFiles

app = FastAPI(
    title="DNS Monitor — Backend",
    version="1.0.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=str(pathlib.Path(__file__).parent / "static")), name="static")

# ---------------------------------------------------------------------------
# API Router versionado — todas as rotas de API ficam sob /api/v1
# ---------------------------------------------------------------------------
v1 = APIRouter(prefix="/api/v1")

# Caminho do arquivo do agente servido para auto-update.
# Pode ser sobrescrito pela variável de ambiente AGENT_FILE_PATH.
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

@v1.post("/metrics", dependencies=[Depends(require_token)])
async def receive_metrics(payload: AgentPayload) -> JSONResponse:
    """
    Recebe o payload do agente (check ou heartbeat),
    persiste todas as métricas e dispara alertas se necessário.
    """
    hostname = payload.hostname
    ts       = payload.timestamp

    # Garante registro do agente — detecta novos automaticamente
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

    # Fingerprint — valida identidade do hardware
    if payload.fingerprint:
        fp_result = await db.upsert_fingerprint(hostname, payload.fingerprint)
        if fp_result.get("changed"):
            logger.warning(
                "ALERTA: fingerprint mudou para '%s'. Anterior: %s | Atual: %s",
                hostname, fp_result.get("previous"), payload.fingerprint
            )

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

    # Checks DNS e status do serviço (check e heartbeat com quick probe)
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


class AgentMetaUpdate(BaseModel):
    display_name: Optional[str]  = None
    location:     Optional[str]  = None
    notes:        Optional[str]  = None
    active:       Optional[bool] = None


@v1.patch("/agents/{hostname}", dependencies=[Depends(require_token)])
async def update_agent(hostname: str, body: AgentMetaUpdate) -> JSONResponse:
    """Atualiza display_name, location e notes de um agente."""
    found = await db.update_agent_meta(
        hostname, body.display_name, body.location, body.notes, body.active
    )
    if not found:
        raise HTTPException(status_code=404, detail="Agente não encontrado")
    return JSONResponse({"status": "ok", "hostname": hostname})


@v1.delete("/agents/{hostname}", dependencies=[Depends(require_token)])
async def delete_agent(hostname: str) -> JSONResponse:
    """Remove o agente e todo o histórico de dados do banco."""
    found = await db.delete_agent(hostname)
    if not found:
        raise HTTPException(status_code=404, detail="Agente não encontrado")
    logger.info("Agente removido: %s", hostname)
    return JSONResponse({"status": "ok", "hostname": hostname})


@v1.get("/agents", dependencies=[Depends(require_token)])
async def list_agents(request: Request) -> _SafeJSONResponse:
    """Lista status atual de todos os agentes registrados."""
    async with db.get_conn() as conn:
        rows = await conn.fetch("SELECT * FROM v_agent_current_status ORDER BY hostname")
    return _SafeJSONResponse([dict(r) for r in rows])


@v1.get("/alerts", dependencies=[Depends(require_token)])
async def list_alerts(hostname: Optional[str] = None) -> _SafeJSONResponse:
    """Lista alertas abertos."""
    alerts = await db.get_open_alerts(hostname)
    return _SafeJSONResponse(alerts)


@v1.get("/commands/{hostname}")
async def get_commands(hostname: str, request: Request) -> _SafeJSONResponse:
    """Retorna comandos pendentes para o agente. Chamado pelo agente no poll."""
    await require_token(request)
    commands = await db.get_pending_commands(hostname)
    return _SafeJSONResponse(commands)


@v1.post("/commands/{command_id}/result")
async def post_command_result(command_id: int, request: Request) -> JSONResponse:
    """Agente reporta o resultado de um comando executado."""
    await require_token(request)
    body = await request.json()
    status = body.get("status", "done")   # 'done' | 'failed'
    result = body.get("result", "")
    if status not in ("done", "failed"):
        return JSONResponse({"error": "status deve ser 'done' ou 'failed'"}, status_code=422)

    # Grava o resultado no banco
    await db.mark_command_done(command_id, status, result)

    # Busca os dados do comando para montar a mensagem de alerta
    cmd = await db.get_command_by_id(command_id)
    if cmd:
        await tg.send_command_result(
            hostname  = cmd["hostname"],
            command   = cmd["command"],
            status    = status,
            result    = result,
            issued_by = cmd["issued_by"] or "admin",
        )

    return JSONResponse({"status": "ok"})


@v1.post("/commands")
async def create_command(request: Request) -> JSONResponse:
    """
    Cria um comando para um agente executar no próximo poll.
    Corpo JSON:
      { "hostname": "...", "command": "stop|disable|enable|purge",
        "issued_by": "admin", "expires_hours": 24 }
    Para purge, gera e retorna um confirm_token automaticamente.
    """
    await require_token(request)
    body = await request.json()
    hostname = body.get("hostname", "").strip()
    command  = body.get("command",  "").strip()
    issued_by = body.get("issued_by", "admin")
    expires_hours = body.get("expires_hours")
    params = body.get("params")

    if not hostname or not command:
        return JSONResponse({"error": "hostname e command são obrigatórios"}, status_code=422)

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
        response["warning"] = "purge é irreversível. Anote o confirm_token — o agente precisará dele para executar."
    return JSONResponse(response, status_code=201)


@v1.get("/commands/{hostname}/history")
async def get_command_history(hostname: str, request: Request) -> _SafeJSONResponse:
    """Histórico de comandos executados em um host."""
    await require_token(request)
    history = await db.get_commands_history(hostname)
    return _SafeJSONResponse(history)


@app.get("/admin/login", response_class=HTMLResponse, include_in_schema=False)
async def admin_login_page() -> HTMLResponse:
    """Formulário de login do painel admin."""
    html_path = pathlib.Path(__file__).parent / "static" / "login.html"
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


@app.post("/admin/login", include_in_schema=False)
async def admin_login_post(request: Request):
    """Valida credenciais e seta cookie de sessão."""
    if not ADMIN_USER or not ADMIN_PASSWORD:
        return HTMLResponse("ADMIN_USER/ADMIN_PASSWORD não configurados", status_code=503)

    form = await request.form()
    username = form.get("username", "")
    password = form.get("password", "")

    if not secrets.compare_digest(username, ADMIN_USER) or \
       not secrets.compare_digest(password, ADMIN_PASSWORD):
        return HTMLResponse("Credenciais inválidas", status_code=401)

    resp = RedirectResponse("/admin", status_code=303)
    cookie_val = _sign_admin_cookie(username)
    resp.set_cookie("admin_session", cookie_val, httponly=True, samesite="strict", max_age=86400)
    return resp


@app.get("/admin/logout", include_in_schema=False)
async def admin_logout():
    """Limpa cookie de sessão e redireciona para login."""
    resp = RedirectResponse("/admin/login", status_code=303)
    resp.delete_cookie("admin_session")
    return resp


@app.get("/admin", response_class=HTMLResponse, include_in_schema=False)
async def admin_panel(request: Request) -> HTMLResponse:
    """Painel de administração — protegido por cookie de sessão."""
    cookie = request.cookies.get("admin_session", "")
    if not _verify_admin_cookie(cookie):
        return RedirectResponse("/admin/login", status_code=303)
    html_path = pathlib.Path(__file__).parent / "static" / "admin.html"
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


@v1.get("/commands/history")
async def get_all_commands_history(request: Request, limit: int = 50) -> _SafeJSONResponse:
    """Histórico recente de todos os comandos (para o painel admin)."""
    await require_token(request)
    history = await db.get_all_commands_history(limit)
    return _SafeJSONResponse(history)


@v1.get("/agent/version")
async def agent_version_info(request: Request) -> JSONResponse:
    """
    Retorna a versão atual do agente disponível para download.
    Usado pelo agente e pelo painel admin para comparar versões.
    """
    await require_token(request)
    if not AGENT_FILE_PATH.exists():
        raise HTTPException(status_code=404, detail="Arquivo do agente não encontrado no servidor")
    content = AGENT_FILE_PATH.read_text(encoding="utf-8")
    m = _re.search(r'^AGENT_VERSION\s*=\s*["\']([^"\']+)["\']', content, _re.MULTILINE)
    version  = m.group(1) if m else "unknown"
    checksum = hashlib.sha256(content.encode()).hexdigest()
    return JSONResponse({
        "version":  version,
        "checksum": checksum,
        "size":     len(content.encode()),
    })


@v1.get("/agent/latest")
async def agent_latest_download(request: Request):
    """
    Serve o arquivo dns_agent.py atual para o agente baixar durante auto-update.
    Requer Bearer token.
    """
    await require_token(request)
    if not AGENT_FILE_PATH.exists():
        raise HTTPException(status_code=404, detail="Arquivo do agente não encontrado no servidor")
    from fastapi.responses import PlainTextResponse
    content = AGENT_FILE_PATH.read_text(encoding="utf-8")
    checksum = hashlib.sha256(content.encode()).hexdigest()
    return PlainTextResponse(
        content,
        media_type="text/x-python",
        headers={"X-Agent-Checksum": checksum},
    )


@v1.post("/tools/geolocate", dependencies=[Depends(require_token)])
async def geolocate_ips(request: Request) -> JSONResponse:
    """
    Geolocaliza uma lista de IPs usando ip-api.com (gratuito, sem chave).
    Retorna array com country, city, ISP, lat/lon por IP.
    """
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

    loop = asyncio.get_event_loop()
    data = await loop.run_in_executor(None, _fetch)
    return JSONResponse(data)


@v1.get("/commands/{command_id}/status")
async def get_command_status(command_id: int, request: Request) -> _SafeJSONResponse:
    """Retorna o status atual de um comando específico (para polling no painel)."""
    await require_token(request)
    cmd = await db.get_command_by_id(command_id)
    if not cmd:
        raise HTTPException(status_code=404, detail="Comando não encontrado")
    return _SafeJSONResponse(cmd)


@app.get("/health")
async def health() -> JSONResponse:
    """Healthcheck para Docker e load balancer."""
    try:
        async with db.get_conn() as conn:
            await conn.fetchval("SELECT 1")
        return JSONResponse({"status": "ok", "db": "connected"})
    except Exception as exc:
        return JSONResponse({"status": "error", "db": str(exc)}, status_code=503)


# ---------------------------------------------------------------------------
# Registra o router versionado
# ---------------------------------------------------------------------------
app.include_router(v1)