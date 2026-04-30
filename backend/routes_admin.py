"""
routes_admin.py — Endpoints administrativos do backend.

Cobre:
  - Autenticacao admin (login/logout/session)
  - Pagina /admin (HTML do painel)
  - Security operations (lista/desbloqueia IPs)
  - CRUD de admin users (multi-user RBAC)
  - Dashboard (HTML + dados agregados)
  - Pagina de ajuda admin

Estrutura:
  - admin_v1: APIRouter que sera incluido no /api/v1 router
  - funcoes standalone para rotas no app (montadas em main.py)

main.py importa tudo e re-exporta para preservar a API
`import main as m; await m.admin_login_post(request)` que os testes usam.
"""

import hashlib
import logging
import os
import pathlib
import re as _re
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse

import db
from auth import (
    AGENT_TOKEN, ADMIN_USER, ADMIN_PASSWORD,
    require_token, require_admin, require_admin_role,
    _check_rate_limit, _record_failed_login, _clear_login_attempts,
    _hash_password, _verify_password,
    _sign_admin_cookie, _verify_admin_cookie, _verify_client_cookie,
    _ADMIN_SESSION_TTL,
)

logger = logging.getLogger("infra-vision.api")

# Router para endpoints versionados (/api/v1/security/*, /api/v1/admin-users, /api/v1/dashboard/data)
admin_v1 = APIRouter()


# ---------------------------------------------------------------------------
# Helpers locais (fallbacks pra _html_with_nonce que vive em main.py)
# ---------------------------------------------------------------------------

def _nonce_inject(html: str, nonce: str) -> str:
    """Wrapper sobre main._html_with_nonce — lazy import pra evitar circular."""
    from main import _html_with_nonce
    return _html_with_nonce(html, nonce)


# ---------------------------------------------------------------------------
# Pagina de login + handler de POST
# ---------------------------------------------------------------------------

async def admin_login_page(request: Request) -> HTMLResponse:
    """Formulario de login do painel admin."""
    html_path = pathlib.Path(__file__).parent / "static" / "login.html"
    html = html_path.read_text(encoding="utf-8")
    nonce = getattr(request.state, "csp_nonce", "")
    return HTMLResponse(_nonce_inject(html, nonce))


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


async def admin_logout():
    """Limpa cookie de sessao e redireciona para login."""
    resp = RedirectResponse("/admin/login", status_code=303)
    resp.delete_cookie("admin_session")
    return resp


# ---------------------------------------------------------------------------
# Sessao
# ---------------------------------------------------------------------------

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
async def session_token_deprecated(request: Request) -> JSONResponse:
    ip = request.client.host if request.client else "?"
    logger.warning("DEPRECATED: /session/token chamado de %s — atualizar frontend para /session/whoami", ip)
    raise HTTPException(
        status_code=410,  # Gone
        detail="Endpoint removido por motivos de seguranca. Use /api/v1/session/whoami.",
    )


# ---------------------------------------------------------------------------
# Pagina /admin (painel de administracao)
# ---------------------------------------------------------------------------

async def admin_panel(request: Request) -> HTMLResponse:
    """Painel de administracao — protegido por cookie de sessao."""
    cookie = request.cookies.get("admin_session", "")
    if not _verify_admin_cookie(cookie):
        return RedirectResponse("/admin/login", status_code=303)
    html_path = pathlib.Path(__file__).parent / "static" / "admin.html"
    nonce = getattr(request.state, "csp_nonce", "")
    return HTMLResponse(_nonce_inject(html_path.read_text(encoding="utf-8"), nonce))


async def admin_help_page(request: Request) -> HTMLResponse:
    cookie = request.cookies.get("admin_session", "")
    if not _verify_admin_cookie(cookie):
        return RedirectResponse("/admin/login", status_code=303)
    html_path = pathlib.Path(__file__).parent / "static" / "admin-help.html"
    nonce = getattr(request.state, "csp_nonce", "")
    return HTMLResponse(_nonce_inject(html_path.read_text(encoding="utf-8"), nonce))


# ---------------------------------------------------------------------------
# Security: lista/desbloqueia IPs (no /api/v1)
# ---------------------------------------------------------------------------

@admin_v1.get("/security/blocked", tags=["tools"], dependencies=[Depends(require_admin)])
async def list_blocked_ips() -> JSONResponse:
    """Lista IPs bloqueados pelo security monitor."""
    import security
    return JSONResponse(security.get_blocked_ips())


@admin_v1.delete("/security/blocked", tags=["tools"], dependencies=[Depends(require_admin)])
async def unblock_all_ips() -> JSONResponse:
    """Desbloqueia todos os IPs."""
    import security
    count = security.unblock_all()
    return JSONResponse({"unblocked": count})


@admin_v1.delete("/security/blocked/{ip}", tags=["tools"], dependencies=[Depends(require_admin)])
async def unblock_ip(ip: str) -> JSONResponse:
    """Desbloqueia um IP especifico."""
    import security
    found = security.unblock_ip(ip)
    return JSONResponse({"ip": ip, "was_blocked": found})


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

async def dashboard_page(request: Request) -> HTMLResponse:
    """Dashboard de metricas."""
    html_path = pathlib.Path(__file__).parent / "static" / "dashboard.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="Dashboard nao encontrado")
    nonce = getattr(request.state, "csp_nonce", "")
    return HTMLResponse(_nonce_inject(html_path.read_text(encoding="utf-8"), nonce))


@admin_v1.get("/dashboard/data", dependencies=[Depends(require_admin)], tags=["dashboard"])
async def dashboard_data(period: str = "24h", host: str = ""):
    """Dados agregados para o dashboard. Aceita ?period=1h|6h|24h|7d&host=hostname."""
    from main import _SafeJSONResponse
    hostnames = None
    if host and _re.match(r'^[a-zA-Z0-9._-]+$', host):
        hostnames = [host]
    data = await db.get_aggregated_metrics(period, hostnames)
    return _SafeJSONResponse(data)


# ---------------------------------------------------------------------------
# Admin users CRUD (RBAC)
# ---------------------------------------------------------------------------

@admin_v1.get("/admin-users", tags=["admin-users"])
async def list_admin_users_endpoint(request: Request):
    """Lista todos os admin users (requer role=admin)."""
    from main import _SafeJSONResponse
    await require_admin_role(request)
    users = await db.list_admin_users()
    return _SafeJSONResponse(users)


@admin_v1.post("/admin-users", tags=["admin-users"])
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


@admin_v1.patch("/admin-users/{user_id}", tags=["admin-users"])
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


# ---------------------------------------------------------------------------
# DNS Query Stats — admin pode ver de qualquer agente + ajustar intervalo
# ---------------------------------------------------------------------------

@admin_v1.get("/dns-stats", tags=["dns-stats"])
async def get_dns_stats_aggregated(request: Request, period: str = "24h", host: str = ""):
    """Stats DNS agregadas pra dashboard admin.

    Sem host: serie raw/horaria de TODOS os hostnames (frontend agrega client-side).
    Com host: serie de 1 hostname especifico.
    """
    from main import _SafeJSONResponse
    await require_admin(request)
    if host:
        if not _re.match(r'^[a-zA-Z0-9._-]{1,128}$', host):
            raise HTTPException(status_code=422, detail="hostname invalido")
        data = await db.get_dns_query_stats(hostname=host, period=period)
    else:
        data = await db.get_dns_query_stats(period=period)
    return _SafeJSONResponse({"period": period, "host": host or None, "samples": data})


@admin_v1.get("/agents/{hostname}/dns-stats", tags=["dns-stats"])
async def get_agent_dns_stats(hostname: str, request: Request, period: str = "24h"):
    """Serie temporal de stats DNS de um agente (admin)."""
    from main import _SafeJSONResponse
    await require_admin(request)
    if not _re.match(r'^[a-zA-Z0-9._-]{1,128}$', hostname):
        raise HTTPException(status_code=422, detail="hostname invalido")
    data = await db.get_dns_query_stats(hostname=hostname, period=period)
    return _SafeJSONResponse({"hostname": hostname, "period": period, "samples": data})


@admin_v1.patch("/agents/{hostname}/stats-interval", tags=["dns-stats"])
async def set_agent_stats_interval(hostname: str, request: Request) -> JSONResponse:
    """Ajusta intervalo de coleta de stats DNS pro agente (60-3600s)."""
    await require_admin_role(request)
    body = await request.json()
    interval = int(body.get("interval_seconds", 600))
    try:
        ok = await db.update_agent_stats_interval(hostname, interval)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=422)
    if not ok:
        raise HTTPException(status_code=404, detail="Agente nao encontrado")
    await db.audit("admin", "dns_stats_interval_set", hostname, detail=str(interval))
    return JSONResponse({"hostname": hostname, "interval_seconds": interval})


@admin_v1.delete("/admin-users/{user_id}", tags=["admin-users"])
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
# Audit log integrity (C2 — v1.5 security audit)
# ---------------------------------------------------------------------------

@admin_v1.get("/admin/audit/verify", tags=["audit"])
async def verify_audit_chain_endpoint(request: Request, limit: int | None = None) -> JSONResponse:
    """Verifica integridade do hash chain do audit_log.
    Admin only — operacao read-only mas expoe estado do chain.
    """
    caller = await require_admin_role(request)
    result = await db.verify_audit_chain(limit=limit)
    await db.audit(
        caller["username"], "audit_chain_verify",
        target=f"limit={limit or 'all'}",
        detail=f"valid={result['valid']} signed={result['signed_count']} legacy={result['legacy_count']}",
    )
    return JSONResponse(result)
