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

# Jobs movidos para scheduler_jobs.py — re-exportados aqui pra preservar
# `import main; main.job_*` em testes/integracoes existentes.
from scheduler_jobs import (  # noqa: F401
    REPORT_TIMES,
    job_check_offline, job_send_report, job_purge_inactive,
    job_monthly_email, job_daily_report,
    setup_scheduler as _setup_scheduler,
)


def setup_scheduler() -> None:
    """Wrapper que passa o scheduler local para scheduler_jobs.setup_scheduler."""
    _setup_scheduler(scheduler)


# ---------------------------------------------------------------------------
# Lifecycle FastAPI
# ---------------------------------------------------------------------------

from nats_handlers import setup_nats_subscriptions as _setup_nats_subscriptions  # noqa: F401


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
# Endpoints — extraidos para routes_agent.py
# ---------------------------------------------------------------------------

from routes_agent import (  # noqa: F401
    agent_v1,
    receive_metrics, _evaluate_alerts, _dispatch_webhooks_for_host,
    update_agent, delete_agent, list_agents,
    list_alerts,
    get_commands, post_command_result, create_command,
    get_command_history, get_all_commands_history, get_command_status,
    agent_version_info, agent_latest_download,
    geolocate_ips,
    ingest_speedtest, speedtest_data_endpoint,
    health,
)

from routes_admin import (  # noqa: F401
    admin_v1,
    admin_login_page, admin_login_post, admin_logout,
    session_whoami, session_token_deprecated,
    admin_panel, admin_help_page,
    dashboard_page, dashboard_data,
    list_blocked_ips, unblock_all_ips, unblock_ip,
    list_admin_users_endpoint, create_admin_user_endpoint,
    update_admin_user_endpoint, delete_admin_user_endpoint,
)


# Pagina speedtest (admin-protected HTML) — fica aqui pq usa _html_with_nonce local.
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


# /health vem de routes_agent.health (importado no topo)
app.get("/health")(health)


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
# Rotas admin (login, logout, sessao, painel, dashboard, help) — montadas no app
# ---------------------------------------------------------------------------
app.get("/admin/login", response_class=HTMLResponse, include_in_schema=False)(admin_login_page)
app.post("/admin/login", include_in_schema=False)(admin_login_post)
app.get("/admin/logout", include_in_schema=False)(admin_logout)
app.get("/api/v1/session/whoami", include_in_schema=False)(session_whoami)
app.get("/api/v1/session/token", include_in_schema=False)(session_token_deprecated)
app.get("/admin", response_class=HTMLResponse, include_in_schema=False)(admin_panel)
app.get("/admin/help", response_class=HTMLResponse, include_in_schema=False)(admin_help_page)
app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)(dashboard_page)


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



# ---------------------------------------------------------------------------
# Registra routers versionados (DEVE ficar depois de todos os endpoints)
# ---------------------------------------------------------------------------
v1.include_router(agent_v1)
v1.include_router(admin_v1)
v1.include_router(client_v1)
app.include_router(v1)
