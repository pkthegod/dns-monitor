"""
routes_client.py — Endpoints do portal do cliente e CRUD de clientes (admin).
"""

import logging
import pathlib
import re as _re

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse

import db
from auth import (
    AGENT_TOKEN,
    require_token,
    _check_rate_limit, _record_failed_login, _clear_login_attempts,
    _check_cooldown, _record_action,
    _hash_password, _verify_password,
    _sign_client_cookie, _verify_client_cookie,
    _CLIENT_SESSION_TTL,
)

try:
    import nats_client as nc
except ImportError:
    nc = None

logger = logging.getLogger("dns-monitor.api")

# Router para endpoints versionados (/api/v1/client/*, /api/v1/clients)
client_v1 = APIRouter()

# ---------------------------------------------------------------------------
# CRUD de clientes (admin)
# ---------------------------------------------------------------------------


@client_v1.get("/clients", dependencies=[])
async def list_clients_endpoint(request: Request):
    """Lista todos os clientes (admin)."""
    await require_token(request)
    from main import _SafeJSONResponse
    return _SafeJSONResponse(await db.list_clients())


@client_v1.post("/clients", dependencies=[])
async def create_client_endpoint(request: Request) -> JSONResponse:
    """Cria um cliente (admin)."""
    await require_token(request)
    body = await request.json()
    username = body.get("username", "").strip()
    password = body.get("password", "").strip()
    hostnames = body.get("hostnames", [])
    notes = body.get("notes", "")
    if not username or not password:
        return JSONResponse({"error": "username e password obrigatorios"}, status_code=422)
    if not hostnames:
        return JSONResponse({"error": "hostnames obrigatorio (array)"}, status_code=422)
    existing = await db.get_client(username)
    if existing:
        return JSONResponse({"error": "username ja existe"}, status_code=409)
    email = body.get("email", "").strip() or None
    pw_hash = _hash_password(password)
    client_id = await db.create_client(username, pw_hash, hostnames, notes or None, email)
    await db.audit("admin", "client_created", username, detail=str(hostnames))
    return JSONResponse({"id": client_id, "username": username}, status_code=201)


@client_v1.patch("/clients/{client_id}", dependencies=[])
async def update_client_endpoint(client_id: int, request: Request) -> JSONResponse:
    """Atualiza um cliente (admin)."""
    await require_token(request)
    body = await request.json()
    fields = {}
    if "hostnames" in body:
        fields["hostnames"] = body["hostnames"]
    if "active" in body:
        fields["active"] = body["active"]
    if "notes" in body:
        fields["notes"] = body["notes"]
    if "password" in body and body["password"]:
        fields["password_hash"] = _hash_password(body["password"])
    if "email" in body:
        fields["email"] = body["email"].strip() or None
    ok = await db.update_client(client_id, **fields)
    if not ok:
        raise HTTPException(status_code=404, detail="Cliente nao encontrado")
    return JSONResponse({"status": "ok"})


@client_v1.delete("/clients/{client_id}", dependencies=[])
async def delete_client_endpoint(client_id: int, request: Request) -> JSONResponse:
    """Remove um cliente (admin)."""
    await require_token(request)
    ok = await db.delete_client(client_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Cliente nao encontrado")
    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------------------
# Portal do cliente — pages (montadas no app, nao no router v1)
# ---------------------------------------------------------------------------


async def client_login_page() -> HTMLResponse:
    html_path = pathlib.Path(__file__).parent / "static" / "client-login.html"
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


async def client_login_post(request: Request):
    ip = request.client.host if request.client else "unknown"
    if _check_rate_limit(ip):
        return RedirectResponse("/client/login?error=locked", status_code=303)

    form = await request.form()
    username = form.get("username", "")
    password = form.get("password", "")
    user = await db.authenticate_client(username)
    _dummy_hash = "$2b$12$000000000000000000000uGPOaHLkG6VgbGG7ZtBCRqGz4eXxWfS"
    if not _verify_password(password, user["password_hash"] if user else _dummy_hash) or not user:
        _record_failed_login(ip)
        logger.warning("Login cliente falhado de %s (user=%s)", ip, username)
        await db.audit("client", "login_failed", username, ip=ip)
        return RedirectResponse("/client/login?error=1", status_code=303)
    _clear_login_attempts(ip)
    await db.audit("client", "login_ok", username, ip=ip)
    resp = RedirectResponse("/client", status_code=303)
    resp.set_cookie("client_session", _sign_client_cookie(username),
                    httponly=True, samesite="strict", max_age=_CLIENT_SESSION_TTL)
    return resp


async def client_logout():
    resp = RedirectResponse("/client/login", status_code=303)
    resp.delete_cookie("client_session")
    return resp


async def client_portal(request: Request) -> HTMLResponse:
    cookie = request.cookies.get("client_session", "")
    username = _verify_client_cookie(cookie)
    if not username:
        return RedirectResponse("/client/login", status_code=303)
    html_path = pathlib.Path(__file__).parent / "static" / "client.html"
    html = html_path.read_text(encoding="utf-8")
    snippet = f'<script>window.__CLIENT__="{username}";</script>'
    html = html.replace("</head>", snippet + "\n</head>", 1)
    return HTMLResponse(html)


# ---------------------------------------------------------------------------
# Endpoints versionados do cliente (/api/v1/client/*)
# ---------------------------------------------------------------------------


@client_v1.post("/client/dns-test")
async def client_dns_test(request: Request) -> JSONResponse:
    """Teste DNS sob demanda — cliente clica 'Testar meu DNS'. Rate: 1/min."""
    cookie = request.cookies.get("client_session", "")
    client_user = _verify_client_cookie(cookie)
    if not client_user:
        raise HTTPException(status_code=403, detail="Acesso negado")
    user = await db.get_client(client_user)
    if not user or not user["active"]:
        raise HTTPException(status_code=403)

    ip = request.client.host if request.client else "unknown"
    rate_key = f"dnstest:{client_user}"
    if _check_cooldown(rate_key, 60):
        return JSONResponse({"error": "Aguarde 1 minuto entre testes"}, status_code=429)

    hostnames = user["hostnames"]
    if not hostnames:
        return JSONResponse({"error": "Nenhum host associado"}, status_code=404)

    hostname = hostnames[0]
    try:
        cmd_id = await db.insert_command(hostname, "run_script", "client:" + client_user, None, 1, "dig_test")
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=422)

    if nc and nc.is_connected():
        await nc.js_publish(f"dns.commands.{hostname}", {
            "id": cmd_id, "command": "run_script", "params": "dig_test",
        })

    _record_action(rate_key)
    await db.audit("client:" + client_user, "dns_test", hostname, ip=ip)
    return JSONResponse({"id": cmd_id, "hostname": hostname, "status": "testing"})


@client_v1.get("/client/report")
async def client_report(request: Request, month: str = "", format: str = "json"):
    """Relatorio mensal — uptime, latencia, alertas. ?format=pdf para PDF."""
    from main import _SafeJSONResponse
    cookie = request.cookies.get("client_session", "")
    client_user = _verify_client_cookie(cookie)
    if not client_user:
        raise HTTPException(status_code=403, detail="Acesso negado")
    user = await db.get_client(client_user)
    if not user or not user["active"]:
        raise HTTPException(status_code=403)

    hostnames = user["hostnames"]
    if not hostnames:
        return _SafeJSONResponse({"error": "Nenhum host associado"})

    from datetime import datetime as _dt
    if month and _re.match(r'^\d{4}-\d{2}$', month):
        year, mon = map(int, month.split("-"))
        start = _dt(year, mon, 1)
        if mon == 12:
            end = _dt(year + 1, 1, 1)
        else:
            end = _dt(year, mon + 1, 1)
    else:
        now = _dt.now()
        start = _dt(now.year, now.month, 1)
        end = now

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

    downtime_min = round(total_minutes * (1 - uptime_pct / 100))
    latency = dict(lat_stats) if lat_stats else {}

    report_data = {
        "period": {"start": start.isoformat(), "end": end.isoformat()},
        "hostnames": hostnames,
        "uptime_pct": uptime_pct,
        "downtime_minutes": downtime_min,
        "latency": latency,
        "alerts_total": alerts,
        "alerts_critical": critical,
        "heartbeats": hb_count,
        "expected_heartbeats": expected_hb,
    }

    if format == "pdf":
        pdf_bytes = _build_report_pdf(report_data, client_user)
        from starlette.responses import Response
        period_label = month or start.strftime("%Y-%m")
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="dns-report-{period_label}.pdf"'},
        )

    return _SafeJSONResponse(report_data)


def _build_report_pdf(data: dict, client_user: str) -> bytes:
    """Gera PDF do relatorio mensal usando reportlab."""
    import io
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Spacer, Paragraph
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=25*mm, bottomMargin=20*mm,
                            leftMargin=25*mm, rightMargin=25*mm)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title2", parent=styles["Title"], fontSize=18,
                                  textColor=HexColor("#7aa2f7"), spaceAfter=6)
    subtitle_style = ParagraphStyle("Sub", parent=styles["Normal"], fontSize=10,
                                     textColor=HexColor("#565f89"), spaceAfter=14)
    heading_style = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=13,
                                    textColor=HexColor("#c0caf5"), spaceBefore=14, spaceAfter=6)
    normal = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10,
                             textColor=HexColor("#a9b1d6"))

    elements = []

    # Header
    period = data["period"]
    elements.append(Paragraph("DNS Monitor — Relatorio Mensal", title_style))
    elements.append(Paragraph(f"Cliente: {client_user} | Periodo: {period['start'][:10]} a {period['end'][:10]}", subtitle_style))
    elements.append(Paragraph(f"Hosts: {', '.join(data['hostnames'])}", normal))
    elements.append(Spacer(1, 8*mm))

    # Disponibilidade
    elements.append(Paragraph("Disponibilidade", heading_style))
    uptime_data = [
        ["Uptime", f"{data['uptime_pct']}%"],
        ["Downtime", f"{data['downtime_minutes']} minutos"],
        ["Heartbeats recebidos", f"{data['heartbeats']} / {data['expected_heartbeats']}"],
    ]
    t = Table(uptime_data, colWidths=[55*mm, 80*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), HexColor("#1a1b26")),
        ("TEXTCOLOR", (0, 0), (-1, -1), HexColor("#a9b1d6")),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#3b4261")),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 6*mm))

    # Latencia
    lat = data.get("latency", {})
    if lat:
        elements.append(Paragraph("Latencia DNS", heading_style))
        lat_data = [
            ["Media", f"{lat.get('avg_ms', '—')} ms"],
            ["Maximo", f"{lat.get('max_ms', '—')} ms"],
            ["P95", f"{lat.get('p95_ms', '—')} ms"],
            ["Total de checks", str(lat.get("total_checks", 0))],
            ["Falhas", str(lat.get("failures", 0))],
        ]
        t2 = Table(lat_data, colWidths=[55*mm, 80*mm])
        t2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), HexColor("#1a1b26")),
            ("TEXTCOLOR", (0, 0), (-1, -1), HexColor("#a9b1d6")),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#3b4261")),
        ]))
        elements.append(t2)
        elements.append(Spacer(1, 6*mm))

    # Alertas
    elements.append(Paragraph("Alertas", heading_style))
    alert_data = [
        ["Total de alertas", str(data.get("alerts_total", 0))],
        ["Alertas criticos", str(data.get("alerts_critical", 0))],
    ]
    t3 = Table(alert_data, colWidths=[55*mm, 80*mm])
    t3.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), HexColor("#1a1b26")),
        ("TEXTCOLOR", (0, 0), (-1, -1), HexColor("#a9b1d6")),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#3b4261")),
    ]))
    elements.append(t3)

    # Footer
    elements.append(Spacer(1, 12*mm))
    from datetime import datetime as _dt
    elements.append(Paragraph(f"Gerado em {_dt.now().strftime('%d/%m/%Y %H:%M')} — DNS Monitor", subtitle_style))

    doc.build(elements)
    return buf.getvalue()


@client_v1.get("/client/data")
async def client_data(request: Request, period: str = "24h"):
    """Dados filtrados por hostnames do cliente logado. Auth via cookie."""
    from main import _SafeJSONResponse
    cookie = request.cookies.get("client_session", "")
    client_user = _verify_client_cookie(cookie)
    if not client_user:
        await require_token(request)
        client_user = request.headers.get("X-Client-User", "")
    if not client_user:
        raise HTTPException(status_code=403, detail="Acesso negado")
    user = await db.get_client(client_user)
    if not user or not user["active"]:
        raise HTTPException(status_code=403, detail="Cliente inativo ou inexistente")
    hostnames = user["hostnames"]
    if not hostnames:
        return _SafeJSONResponse({"agents": [], "dns_latency": [], "cpu_history": [],
                                   "ram_history": [], "dns_history": [], "recent_alerts": []})

    data = await db.get_aggregated_metrics(period, hostnames)
    return _SafeJSONResponse(data)
