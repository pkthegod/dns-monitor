"""
routes_agent.py — Endpoints da API consumida pelos agentes + ferramentas admin
de gerenciamento de agentes/comandos.

Cobre:
  - POST /metrics                      (ingestao do agente)
  - GET/PATCH/DELETE /agents/*         (gerenciamento)
  - GET /alerts                        (alertas abertos)
  - /commands/*                        (poll, result, create, history, status)
  - /agent/version, /agent/latest      (auto-update do agente)
  - POST /tools/geolocate              (lookup IP via ip-api.com)
  - /speedtest, /speedtest/data        (ingestao+leitura speedtest)
  - GET /health                        (Docker healthcheck)

Tudo registrado num APIRouter `agent_v1` que main.py inclui no /api/v1 router.
Helpers _evaluate_alerts e _dispatch_webhooks_for_host ficam aqui pra co-localizar
com receive_metrics que e quem os usa.

Imports lazy de main (THRESHOLDS, AGENT_FILE_PATH) preservam o pattern de
monkey-patching dos testes (ex.: patch('main.AGENT_FILE_PATH', ...)).
"""

import asyncio
import hashlib
import hmac as _hmac
import json as _json
import logging
import os as _os
import re as _re
import secrets
import time as _time
import urllib.request as _urllib
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

import db


# SEC (M7 + Onda 2 SEC-2.4): comandos irreversiveis exigem confirm_token HMAC
# stateless valido por 5 min. Fluxo two-step:
#   1ª chamada (sem token) retorna o token e NAO enfileira o comando
#   2ª chamada (com token valido) enfileira de fato
# Comandos cobertos:
#   - purge        (M7, original)
#   - decommission (SEC-2.4, 2026-05-04 — antes nao tinha gate; backend
#                   passava confirm_token=None e o agente recusava com
#                   "decommission exige confirm_token", entao TODO
#                   decommission via /api/v1/commands virava status=failed)
#
# Token e HMAC de "{command}:{hostname}:{bucket}" — tokens NAO sao
# intercambiaveis entre comandos (token de purge nao funciona pra
# decommission e vice-versa).
_PURGE_TOKEN_LEN = 24  # hex chars (12 bytes de entropia)
_PURGE_WINDOW_MIN = 5  # minutos de validade
_TOKEN_REQUIRED_COMMANDS = {"purge", "decommission"}


def _critical_token_secret() -> bytes:
    """Chave HMAC dos tokens criticos. Reusa ADMIN_SESSION_SECRET (gerenciado
    e rotacionavel pelo operador). Cai pra AGENT_TOKEN se vazio."""
    s = _os.environ.get("ADMIN_SESSION_SECRET", "")
    if s:
        return s.encode()
    return _os.environ.get("AGENT_TOKEN", "").encode() or b"infra-vision-fallback"


def _critical_token_for(hostname: str, command: str, bucket: int) -> str:
    """HMAC de {command}:{hostname}:{bucket}. Inclusao de command no message
    impede atacante reusar token de purge pra autorizar decommission."""
    msg = f"{command}:{hostname}:{bucket}".encode()
    return _hmac.new(_critical_token_secret(), msg, hashlib.sha256).hexdigest()[:_PURGE_TOKEN_LEN]


def _verify_critical_token(hostname: str, command: str, token: str) -> bool:
    """True se token valida contra (hostname, command, bucket atual ou ate N
    minutos atras). Compara via hmac.compare_digest (timing-safe)."""
    if not token or len(token) != _PURGE_TOKEN_LEN:
        return False
    bucket = int(_time.time() // 60)
    for delta in range(0, _PURGE_WINDOW_MIN + 1):
        expected = _critical_token_for(hostname, command, bucket - delta)
        if _hmac.compare_digest(token, expected):
            return True
    return False


# Backward-compat aliases pra tests/scripts que ainda importam os nomes
# originais. Comportamento identico ao especifico de "purge".
def _purge_token_secret() -> bytes:  # pragma: no cover (alias)
    return _critical_token_secret()


def _purge_token_for(hostname: str, bucket: int) -> str:
    return _critical_token_for(hostname, "purge", bucket)


def _verify_purge_token(hostname: str, token: str) -> bool:
    return _verify_critical_token(hostname, "purge", token)
import telegram_bot as tg
from auth import (
    AGENT_TOKEN,
    require_token, require_admin, require_admin_role, require_admin_or_client,
    _verify_admin_cookie, _verify_client_cookie,
    _real_client_ip,
)
from models import AgentPayload, AgentMetaUpdate, SpeedtestPayload, DnsStatsPayload
from pydantic import ValidationError
from ws import ws_manager

try:
    import nats_client as nc
except ImportError:
    nc = None  # nats-py nao instalado — NATS desabilitado

logger = logging.getLogger("infra-vision.api")

agent_v1 = APIRouter()


def _safe_response(content):
    """Wrapper sobre main._SafeJSONResponse — lazy pra evitar circular import."""
    from main import _SafeJSONResponse
    return _SafeJSONResponse(content)


# ---------------------------------------------------------------------------
# POST /metrics — ingestao do agente
# ---------------------------------------------------------------------------

@agent_v1.post("/metrics", dependencies=[Depends(require_token)], tags=["metrics"])
async def receive_metrics(payload: AgentPayload) -> JSONResponse:
    """
    Recebe o payload do agente (check ou heartbeat),
    persiste todas as metricas e dispara alertas se necessario.

    Acessa db/tg via `import main as _m` pra preservar monkey-patching dos testes
    (patch.object(m, 'db', mock_db)).
    """
    import main as _m

    hostname = payload.hostname
    ts       = payload.timestamp

    if not _re.match(r'^[a-zA-Z0-9._-]{1,128}$', hostname):
        return JSONResponse({"error": "hostname invalido"}, status_code=422)

    agent_meta = await _m.db.upsert_agent(
        hostname,
        ts,
        display_name  = getattr(payload, "display_name", None),
        location      = getattr(payload, "location", None),
        agent_version = payload.agent_version or None,
    )
    if agent_meta.get("is_new"):
        logger.info("Novo agente detectado: %s", hostname)
        await _m.tg.send_new_agent_detected(hostname, payload.agent_version or "")

    if payload.fingerprint:
        fp_result = await _m.db.upsert_fingerprint(hostname, payload.fingerprint)
        if fp_result.get("changed"):
            logger.warning(
                "ALERTA: fingerprint mudou para '%s'. Anterior: %s | Atual: %s",
                hostname, fp_result.get("previous"), payload.fingerprint
            )

    await _m.db.insert_heartbeat(hostname, ts, payload.agent_version)

    if payload.system:
        from models import LoadModel
        sys = payload.system
        if sys.cpu:
            await _m.db.insert_metrics_cpu(hostname, ts, sys.cpu.model_dump(), (sys.load or LoadModel()).model_dump())
        if sys.ram:
            await _m.db.insert_metrics_ram(hostname, ts, sys.ram.model_dump())
        if sys.disk:
            await _m.db.insert_metrics_disk(hostname, ts, [d.model_dump() for d in sys.disk])
        if sys.io:
            await _m.db.insert_metrics_io(hostname, ts, sys.io.model_dump())

    if payload.dns_service:
        await _m.db.insert_dns_service_status(hostname, ts, payload.dns_service.model_dump())
    if payload.dns_checks:
        await _m.db.insert_dns_checks(hostname, ts, [c.model_dump() for c in payload.dns_checks])

    await _evaluate_alerts(payload)
    await _m.db.resolve_alert(hostname, "offline")

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


# ---------------------------------------------------------------------------
# Helpers de alerta (chamados por receive_metrics)
# ---------------------------------------------------------------------------

async def _evaluate_alerts(payload: AgentPayload) -> None:
    """Avalia thresholds e dispara alertas via Telegram quando necessario.

    Acessa db/tg via main pra preservar patch.object(m, 'db', mock) dos testes.
    """
    import main as _m
    THRESHOLDS = _m.THRESHOLDS

    hostname = payload.hostname
    sys = payload.system

    # A1 (R6 race-fix): insert_alert agora e atomico (ON CONFLICT DO NOTHING).
    # Retorna None se ja existia um alerta aberto pro mesmo (host,type,severity);
    # nesses casos pulamos o notify pra nao spammar Telegram/webhook. Antes,
    # has_open_alert + insert_alert era check-then-act vulneravel a race entre
    # 2 payloads do mesmo host chegando em <100ms.
    if sys:
        if sys.cpu and sys.cpu.percent is not None:
            pct = sys.cpu.percent
            if pct >= THRESHOLDS["cpu_critical"]:
                aid = await _m.db.insert_alert(hostname, "cpu", "critical", f"CPU {pct:.1f}%", "cpu_percent", pct, THRESHOLDS["cpu_critical"])
                if aid and await _m.tg.alert_cpu(hostname, pct, THRESHOLDS["cpu_critical"], "critical"):
                    await _m.db.mark_alert_notified(aid)
            elif pct >= THRESHOLDS["cpu_warning"]:
                await _m.db.insert_alert(hostname, "cpu", "warning", f"CPU {pct:.1f}%", "cpu_percent", pct, THRESHOLDS["cpu_warning"])

        if sys.ram and sys.ram.percent is not None:
            pct = sys.ram.percent
            if pct >= THRESHOLDS["ram_critical"]:
                aid = await _m.db.insert_alert(hostname, "ram", "critical", f"RAM {pct:.1f}%", "ram_percent", pct, THRESHOLDS["ram_critical"])
                if aid and await _m.tg.alert_ram(hostname, pct, THRESHOLDS["ram_critical"], "critical"):
                    await _m.db.mark_alert_notified(aid)
            elif pct >= THRESHOLDS["ram_warning"]:
                await _m.db.insert_alert(hostname, "ram", "warning", f"RAM {pct:.1f}%", "ram_percent", pct, THRESHOLDS["ram_warning"])

        for disk in (sys.disk or []):
            if disk.alert in ("warning", "critical") and disk.percent is not None:
                threshold = THRESHOLDS[f"disk_{disk.alert}"]
                aid = await _m.db.insert_alert(hostname, "disk", disk.alert, f"Disco {disk.mountpoint} {disk.percent:.1f}%", "disk_percent", disk.percent, threshold)
                if aid and disk.alert == "critical":
                    if await _m.tg.alert_disk(hostname, disk.mountpoint or "?", disk.percent, threshold, "critical"):
                        await _m.db.mark_alert_notified(aid)

    for check in (payload.dns_checks or []):
        if not check.success:
            aid = await _m.db.insert_alert(hostname, "dns_fail", "critical", f"DNS falhou: {check.domain} ({check.error})", "dns_success", 0, 1)
            if aid and await _m.tg.alert_dns_failure(hostname, check.domain, check.error or "unknown", check.attempts or 0):
                await _m.db.mark_alert_notified(aid)
        elif check.latency_ms is not None:
            if check.latency_ms >= THRESHOLDS["dns_latency_critical"]:
                aid = await _m.db.insert_alert(hostname, "dns_latency", "critical", f"DNS latencia {check.latency_ms:.0f}ms para {check.domain}", "latency_ms", check.latency_ms, THRESHOLDS["dns_latency_critical"])
                if aid and await _m.tg.alert_dns_latency(hostname, check.domain, check.latency_ms, THRESHOLDS["dns_latency_critical"], "critical"):
                    await _m.db.mark_alert_notified(aid)
            elif check.latency_ms >= THRESHOLDS["dns_latency_warning"]:
                await _m.db.insert_alert(hostname, "dns_latency", "warning", f"DNS latencia {check.latency_ms:.0f}ms para {check.domain}", "latency_ms", check.latency_ms, THRESHOLDS["dns_latency_warning"])

    if payload.dns_service and payload.dns_service.active is False:
        svc = payload.dns_service.name or "unknown"
        aid = await _m.db.insert_alert(hostname, "dns_service", "critical", f"Servico DNS '{svc}' inativo")
        if aid and await _m.tg.alert_dns_service_down(hostname, svc):
            await _m.db.mark_alert_notified(aid)

    # Dispatch webhooks para clientes que monitoram este hostname
    await _dispatch_webhooks_for_host(hostname, payload)


async def _dispatch_webhooks_for_host(hostname: str, payload: AgentPayload) -> None:
    """Envia alertas critical via webhook para clientes que monitoram este host."""
    import main as _m
    THRESHOLDS = _m.THRESHOLDS
    import webhooks
    try:
        clients = await _m.db.list_clients()
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


# ---------------------------------------------------------------------------
# /agents — gerenciamento (admin)
# ---------------------------------------------------------------------------

@agent_v1.patch("/agents/{hostname}", dependencies=[Depends(require_admin_role)], tags=["agents"])
async def update_agent(hostname: str, body: AgentMetaUpdate) -> JSONResponse:
    """Atualiza display_name, location e notes de um agente."""
    found = await db.update_agent_meta(
        hostname, body.display_name, body.location, body.notes, body.active
    )
    if not found:
        raise HTTPException(status_code=404, detail="Agente nao encontrado")
    return JSONResponse({"status": "ok", "hostname": hostname})


@agent_v1.delete("/agents/{hostname}", dependencies=[Depends(require_admin_role)], tags=["agents"])
async def delete_agent(hostname: str) -> JSONResponse:
    """Remove o agente e todo o historico de dados do banco."""
    found = await db.delete_agent(hostname)
    if not found:
        raise HTTPException(status_code=404, detail="Agente nao encontrado")
    logger.info("Agente removido: %s", hostname)
    return JSONResponse({"status": "ok", "hostname": hostname})


@agent_v1.get("/agents", dependencies=[Depends(require_admin)], tags=["agents"])
async def list_agents(request: Request):
    """Lista status atual de todos os agentes registrados."""
    async with db.get_conn() as conn:
        rows = await conn.fetch("SELECT * FROM v_agent_current_status ORDER BY hostname")
    return _safe_response([dict(r) for r in rows])


# ---------------------------------------------------------------------------
# /alerts
# ---------------------------------------------------------------------------

@agent_v1.get("/alerts", dependencies=[Depends(require_admin)], tags=["alerts"])
async def list_alerts(hostname: Optional[str] = None):
    """Lista alertas abertos."""
    alerts = await db.get_open_alerts(hostname)
    return _safe_response(alerts)


# ---------------------------------------------------------------------------
# /commands — poll/result/create/history/status
# ---------------------------------------------------------------------------

@agent_v1.get("/commands/{hostname}", tags=["commands"])
async def get_commands(hostname: str, request: Request):
    """Retorna comandos pendentes para o agente. Chamado pelo agente no poll."""
    import main as _m
    await _m.require_token(request)
    commands = await _m.db.get_pending_commands(hostname)
    return _safe_response(commands)


@agent_v1.post("/commands/{command_id}/result", tags=["commands"])
async def post_command_result(command_id: int, request: Request) -> JSONResponse:
    """Agente reporta o resultado de um comando executado."""
    import main as _m
    await _m.require_token(request)
    body = await request.json()
    cmd_status = body.get("status", "done")   # 'done' | 'failed'
    result = body.get("result", "")
    if cmd_status not in ("done", "failed"):
        return JSONResponse({"error": "status deve ser 'done' ou 'failed'"}, status_code=422)

    await _m.db.mark_command_done(command_id, cmd_status, result)

    # Dedupe Telegram: agente reporta ack via NATS + HTTP redundante.
    # Primeiro caller a vencer mark_command_notified atomico envia; segundo silencia.
    if await _m.db.mark_command_notified(command_id):
        cmd = await _m.db.get_command_by_id(command_id)
        if cmd:
            await _m.tg.send_command_result(
                hostname  = cmd["hostname"],
                command   = cmd["command"],
                status    = cmd_status,
                result    = result,
                issued_by = cmd["issued_by"] or "admin",
            )

    return JSONResponse({"status": "ok"})


@agent_v1.post("/commands", tags=["commands"])
async def create_command(request: Request) -> JSONResponse:
    """Cria um comando para um agente executar no proximo poll."""
    import main as _m
    info = await _m.require_admin_role(request)
    body = await request.json()
    hostname = body.get("hostname", "").strip()
    command  = body.get("command",  "").strip()
    issued_by = body.get("issued_by", info["username"])
    expires_hours = body.get("expires_hours")
    params = body.get("params")

    if not hostname or not command:
        return JSONResponse({"error": "hostname e command sao obrigatorios"}, status_code=422)

    # SEC (M7 + SEC-2.4): comandos irreversiveis (_TOKEN_REQUIRED_COMMANDS)
    # exigem fluxo two-step com confirm_token HMAC.
    confirm_token = None
    if command in _TOKEN_REQUIRED_COMMANDS:
        provided = (body.get("confirm_token") or "").strip()
        if not provided:
            issued = _critical_token_for(hostname, command, int(_time.time() // 60))
            return JSONResponse({
                "requires_confirm": True,
                "confirm_token": issued,
                "expires_in_seconds": _PURGE_WINDOW_MIN * 60,
                "message": (
                    f"{command} e irreversivel. Reenvie a request com este "
                    f"confirm_token dentro de 5 minutos para confirmar."
                ),
            }, status_code=202)
        if not _verify_critical_token(hostname, command, provided):
            await _m.db.audit(
                issued_by, f"{command}_confirm_invalid", hostname,
                detail="token invalido ou expirado",
                ip=_real_client_ip(request),
            )
            return JSONResponse(
                {"error": "confirm_token invalido ou expirado"},
                status_code=400,
            )
        confirm_token = provided

    try:
        cmd_id = await _m.db.insert_command(
            hostname, command, issued_by, confirm_token, expires_hours, params
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=422)

    response = {"id": cmd_id, "hostname": hostname, "command": command, "status": "pending"}
    if confirm_token:
        response["confirm_token"] = confirm_token  # ecoa o token validado (ja consumido)

    await _m.db.audit(issued_by, "command", hostname, detail=command, ip=_real_client_ip(request))
    nats_sent = False
    if nc and nc.is_connected():
        nats_sent = await nc.js_publish(f"dns.commands.{hostname}", {
            "id": cmd_id, "command": command,
            "confirm_token": confirm_token, "params": params,
        })
    response["nats"] = "sent" if nats_sent else "fallback_http"

    return JSONResponse(response, status_code=201)


@agent_v1.get("/commands/{hostname}/history", tags=["commands"])
async def get_command_history(hostname: str, request: Request):
    """Historico de comandos executados em um host."""
    import main as _m
    await _m.require_admin(request)
    history = await _m.db.get_commands_history(hostname)
    return _safe_response(history)


@agent_v1.get("/commands/history", tags=["commands"])
async def get_all_commands_history(request: Request, limit: int = 50):
    """Historico recente de todos os comandos (para o painel admin)."""
    import main as _m
    await _m.require_admin(request)
    history = await _m.db.get_all_commands_history(limit)
    return _safe_response(history)


@agent_v1.get("/commands/{command_id}/status", tags=["commands"])
async def get_command_status(command_id: int, request: Request):
    """Retorna o status atual de um comando.

    SEC: admin vê tudo; cliente só vê comandos de hostnames associados a ele.
    Antes, ambos usavam require_token com AGENT_TOKEN compartilhado, permitindo
    que um cliente lesse comandos de hosts de outros clientes.
    """
    import main as _m
    cmd = await _m.db.get_command_by_id(command_id)
    if not cmd:
        raise HTTPException(status_code=404, detail="Comando nao encontrado")

    # Admin: acesso irrestrito
    admin_info = _m._verify_admin_cookie(request.cookies.get("admin_session", ""))
    auth = request.headers.get("Authorization", "")
    if admin_info or (auth.startswith("Bearer ") and _m.AGENT_TOKEN and
                 secrets.compare_digest(auth[7:], _m.AGENT_TOKEN)):
        return _safe_response(cmd)

    # Cliente: só comandos de seus hostnames
    client_username = _m._verify_client_cookie(request.cookies.get("client_session", ""))
    if client_username:
        user = await _m.db.get_client(client_username)
        if user and user.get("active") and cmd.get("hostname") in (user.get("hostnames") or []):
            return _safe_response(cmd)

    raise HTTPException(status_code=403, detail="Acesso negado")


# ---------------------------------------------------------------------------
# /agents/{hostname}/dns-stats — recebe sample do agente (HTTP path)
# ---------------------------------------------------------------------------

@agent_v1.post("/agents/{hostname}/dns-stats", tags=["dns-stats"])
async def receive_dns_stats(hostname: str, request: Request) -> JSONResponse:
    """Agente publica stats DNS aqui via Bearer token.

    Mesmo handler que NATS dns.stats.* — converge em db.insert_dns_query_stats
    e _evaluate_dns_stats_alerts. Usa HTTP por default (mais simples; NATS e
    otimizacao opcional v1.1).
    """
    import main as _m
    await _m.require_token(request)
    if not _re.match(r'^[a-zA-Z0-9._-]{1,128}$', hostname):
        return JSONResponse({"error": "hostname invalido"}, status_code=422)
    try:
        raw = await request.json()
    except Exception as exc:
        return JSONResponse({"error": f"JSON invalido: {exc}"}, status_code=422)
    # SEC (Onda 2 SEC-2.1): valida schema antes de tocar no DB ou disparar
    # alertas. Antes, dict cru chegava em insert_dns_query_stats que fazia
    # int(.get(...,0)) — strings malucas viravam zeros silenciosamente; numeros
    # negativos passavam; alertas eram disparados com base em dado invalido.
    try:
        payload = DnsStatsPayload.model_validate(raw)
    except ValidationError as exc:
        return JSONResponse(
            {"error": "Payload de stats invalido", "detail": str(exc)[:500]},
            status_code=422,
        )
    data = payload.model_dump()
    try:
        await _m.db.insert_dns_query_stats(hostname, data)
        await _evaluate_dns_stats_alerts(hostname, data)
    except Exception as exc:
        logger.error("receive_dns_stats erro pra %s: %s", hostname, exc)
        return JSONResponse({"error": "Falha ao gravar stats"}, status_code=500)
    return JSONResponse({"status": "ok"}, status_code=202)


async def _evaluate_dns_stats_alerts(hostname: str, data: dict) -> None:
    """Avalia alertas DNS pos-ingestao de stats. Chamado por receive_dns_stats
    (HTTP) e handle_dns_stats (NATS).

    Alertas implementados:
      - dns_servfail_high (critical, >5% SERVFAIL com volume >=100)
      - dns_silence       (critical, queries=0 mas histórico tinha tráfego)
      - dns_nxdomain_high (warning, >50% NXDOMAIN — possivel scan/config errada)

    Auto-resolve quando metrica volta ao normal (resolve_alert apaga o open).
    Has_open_alert evita spam de Telegram pra mesmo problema persistente.

    db/tg via main pra preservar monkey-patching de testes.
    """
    import main as _m
    qt = int(data.get("queries_total") or 0)

    # A1 (R6 race-fix): insert_alert atomico (ON CONFLICT DO NOTHING).
    # has_open_alert removido — se o INSERT retorna None, ja havia alerta
    # aberto pra (host,type,severity) e pulamos o notify.

    # 1. SERVFAIL alto — critical, dispara Telegram
    if qt >= 100:
        sf = int(data.get("servfail") or 0)
        sf_pct = (sf / qt) * 100
        if sf_pct > 5.0:
            aid = await _m.db.insert_alert(
                hostname, "dns_servfail_high", "critical",
                f"SERVFAIL alto: {sf_pct:.1f}% das queries ({sf} de {qt})",
                "servfail_pct", sf_pct, 5.0,
            )
            if aid and await _m.tg.alert_dns_failure(
                hostname, "SERVFAIL spike",
                f"{sf_pct:.1f}% das queries falharam ({sf} de {qt})", 0,
            ):
                await _m.db.mark_alert_notified(aid)
        else:
            # Voltou ao normal — fecha o alerta aberto se houver
            await _m.db.resolve_alert(hostname, "dns_servfail_high")

    # 2. NXDOMAIN absurdo — warning, sem Telegram (apenas no painel)
    if qt >= 100:
        nxd = int(data.get("nxdomain") or 0)
        nxd_pct = (nxd / qt) * 100
        if nxd_pct > 50.0:
            await _m.db.insert_alert(
                hostname, "dns_nxdomain_high", "warning",
                f"NXDOMAIN alto: {nxd_pct:.0f}% das queries ({nxd} de {qt}) — possivel scan ou config errada",
                "nxdomain_pct", nxd_pct, 50.0,
            )
        else:
            await _m.db.resolve_alert(hostname, "dns_nxdomain_high")

    # 3. DNS silence — queries=0 quando deveria ter trafego
    if qt == 0:
        # Se ultima 1h teve >=2 amostras com >100 queries, agora zero e suspeito
        try:
            recent = await _m.db.get_dns_query_stats(hostname=hostname, period="1h")
        except Exception:
            recent = []
        had_traffic = sum(
            1 for s in recent if int(s.get("queries_total") or 0) > 100
        ) >= 2
        if had_traffic:
            aid = await _m.db.insert_alert(
                hostname, "dns_silence", "critical",
                "DNS sem trafego — resolver pode estar parado ou desconectado da rede",
            )
            if aid and await _m.tg.alert_dns_service_down(hostname, "DNS resolver (sem trafego)"):
                await _m.db.mark_alert_notified(aid)
    elif qt >= 100:
        # Voltou a ter trafego — fecha alerta de silence
        await _m.db.resolve_alert(hostname, "dns_silence")


# ---------------------------------------------------------------------------
# /agent/version, /agent/latest — auto-update
# ---------------------------------------------------------------------------

@agent_v1.get("/agent/version", tags=["agents"])
async def agent_version_info(request: Request) -> JSONResponse:
    """Versao+checksum do agente servido em /agent/latest.

    SEC: aceita admin cookie OU Bearer (require_admin). Painel admin precisa
    saber a versao remota pra mostrar badges de "desatualizado" na tabela
    de agentes; agente usa Bearer pro check de auto-update. Endpoint nao
    expoe nada sensivel — so version, checksum, tamanho do arquivo.
    """
    import main as _m
    await _m.require_admin(request)
    if not _m.AGENT_FILE_PATH.exists():
        raise HTTPException(status_code=404, detail="Arquivo do agente nao encontrado no servidor")
    content = _m.AGENT_FILE_PATH.read_text(encoding="utf-8")
    mt = _re.search(r'^AGENT_VERSION\s*=\s*["\']([^"\']+)["\']', content, _re.MULTILINE)
    version  = mt.group(1) if mt else "unknown"
    checksum = hashlib.sha256(content.encode()).hexdigest()
    return JSONResponse({
        "version":  version,
        "checksum": checksum,
        "size":     len(content.encode()),
    })


@agent_v1.get("/agent/latest", tags=["agents"])
async def agent_latest_download(request: Request):
    import main as _m
    await _m.require_token(request)
    if not _m.AGENT_FILE_PATH.exists():
        raise HTTPException(status_code=404, detail="Arquivo do agente nao encontrado no servidor")
    content = _m.AGENT_FILE_PATH.read_text(encoding="utf-8")
    checksum = hashlib.sha256(content.encode()).hexdigest()
    return PlainTextResponse(
        content,
        media_type="text/x-python",
        headers={"X-Agent-Checksum": checksum},
    )


# ---------------------------------------------------------------------------
# /tools/geolocate
# ---------------------------------------------------------------------------

# SEC (Onda 2 SEC-2.3): geolocate via HTTPS quando IPAPI_KEY configurado.
# ip-api.com FREE e HTTP-only — versao HTTPS exige plano pago em
# https://members.ip-api.com (~$13/mes). Se IPAPI_KEY setado, usamos
# https://pro.ip-api.com/batch (HTTPS); senao mantemos HTTP free.
#
# Risco mitigado: vazamento dos IPs do trace via plaintext. IPs sao publicos
# (servers DNS root/TLD/auth) — nao revelam dado privado do cliente — mas
# tracegrafia revela QUE host esta investigando QUAL dominio: padrao de uso
# leakable em rede compartilhada. HTTPS fecha esse vetor pra quem paga.
_IPAPI_FIELDS = "query,status,country,countryCode,regionName,city,isp,org,lat,lon"


def _ipapi_url() -> str:
    """URL do ip-api: pro (HTTPS) se IPAPI_KEY set; senao free (HTTP plain)."""
    key = _os.environ.get("IPAPI_KEY", "").strip()
    if key:
        return f"https://pro.ip-api.com/batch?key={key}&fields={_IPAPI_FIELDS}"
    return f"http://ip-api.com/batch?fields={_IPAPI_FIELDS}"


# Warning uma vez no import — em prod sem IPAPI_KEY, geo vai plaintext
if _os.environ.get("INFRA_VISION_ENV", "").lower() == "production" \
   and not _os.environ.get("IPAPI_KEY", "").strip():
    logger.warning(
        "IPAPI_KEY ausente em INFRA_VISION_ENV=production — geolocate fara "
        "HTTP plain pra ip-api.com (vetor leak de trace patterns). "
        "Pra HTTPS, configure IPAPI_KEY=<chave> de https://members.ip-api.com"
    )


@agent_v1.post("/tools/geolocate", dependencies=[Depends(require_admin_or_client)], tags=["tools"])
async def geolocate_ips(request: Request) -> JSONResponse:
    """Lookup IP via ip-api.com — admin OU cliente autenticado.

    SEC: IPs do trace sao publicos (servers DNS), nenhum dado sensivel.
    Cliente precisa pra mostrar mapa de saltos no portal — paridade com admin.
    Rate limit do middleware /api/ ja protege contra bombing (~120 req/min/IP).
    Transporte HTTP (free) ou HTTPS (com IPAPI_KEY) — ver _ipapi_url().
    """
    body = await request.json()
    ips  = list(dict.fromkeys(str(ip) for ip in body.get("ips", []) if ip))[:100]
    if not ips:
        return JSONResponse([])

    payload = _json.dumps([{"query": ip} for ip in ips]).encode()
    url = _ipapi_url()

    def _fetch():
        try:
            req = _urllib.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with _urllib.urlopen(req, timeout=10) as resp:
                return _json.loads(resp.read().decode())
        except Exception as exc:
            logger.warning("geolocate: ip-api falhou: %s", exc)
            return [{"query": ip, "status": "fail"} for ip in ips]

    loop = asyncio.get_running_loop()
    data = await loop.run_in_executor(None, _fetch)
    return JSONResponse(data)


# ---------------------------------------------------------------------------
# /speedtest — ingestao + leitura
# ---------------------------------------------------------------------------

@agent_v1.post("/speedtest", dependencies=[Depends(require_token)], tags=["speedtest"])
async def ingest_speedtest(payload: SpeedtestPayload) -> JSONResponse:
    """Recebe JSON validado do script domain checker (speedtest)."""
    metadata = payload.metadata
    summary = payload.summary
    domains = [d.model_dump() for d in payload.domains]
    scan_id = await db.insert_speedtest_scan(metadata, summary, domains)
    logger.info("Speedtest ingerido: scan_id=%d, domains=%d", scan_id, len(domains))
    return JSONResponse({"status": "ok", "scan_id": scan_id, "domains": len(domains)}, status_code=201)


@agent_v1.get("/speedtest/data", dependencies=[Depends(require_admin)], tags=["speedtest"])
async def speedtest_data_endpoint():
    """Dados do ultimo scan + historico para o frontend."""
    latest = await db.get_latest_speedtest()
    history = await db.get_speedtest_history(30)
    return _safe_response({"latest": latest, "history": history})


# ---------------------------------------------------------------------------
# /health (no app, nao no v1)
# ---------------------------------------------------------------------------

async def health() -> JSONResponse:
    """Healthcheck para Docker e load balancer."""
    import main as _m
    try:
        async with _m.db.get_conn() as conn:
            await conn.fetchval("SELECT 1")
        return JSONResponse({"status": "ok", "db": "connected"})
    except Exception as exc:
        logger.error("Health check falhou: %s", exc)
        return JSONResponse({"status": "error", "db": "unavailable"}, status_code=503)
