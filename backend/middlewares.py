"""
middlewares.py — Middlewares HTTP do backend.

Ordem de registro em main.py (do externo para o interno):
    NPlusOneDetectorMiddleware   — Fase B (C1): detecta loop N+1 de queries
    SlowRequestMiddleware        — Fase B (C2): warn em request > threshold ms
    RequestLoggingMiddleware     — audit log de POST/PATCH/DELETE
    SecurityMonitorMiddleware    — bloqueia IPs, detecta scan/brute/honeypot
    RequestSizeLimitMiddleware   — rejeita body > 10MB
    APIRateLimitMiddleware       — rate limit por IP + path prefix
    CSRFMiddleware               — valida Origin/Referer (cookies; Bearer isento)
    SecurityHeadersMiddleware    — CSP, HSTS, etc. + gera nonce por request

Starlette executa middlewares em ordem REVERSA do add_middleware,
então o último adicionado é o mais externo.
"""

import asyncio
import base64
import logging
import os
import secrets
import time as _time
from urllib.parse import urlparse

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

import db_observability as _obs
import telegram_bot as tg
from auth import _real_client_ip

logger = logging.getLogger("infra-vision.api")


# SEC (Onda 1 P2): origens autorizadas em CSRF. Sem ALLOWED_ORIGINS configurado,
# so aceita o proprio Host da request (comportamento legado, mas via comparacao
# exata em vez de endsWith). Aceita lista separada por virgula:
#   ALLOWED_ORIGINS=nsmonitor.procyontecnologia.net,localhost:8000
# Hostnames sem schema, com porta opcional (porta sera ignorada na comparacao).
_ALLOWED_ORIGINS_RAW = os.environ.get("ALLOWED_ORIGINS", "").strip()
_ALLOWED_ORIGINS = {
    h.strip().lower().split(":")[0]
    for h in _ALLOWED_ORIGINS_RAW.split(",")
    if h.strip()
}


def _origin_matches(origin_or_referer: str, host_header: str) -> bool:
    """True se origin/referer aponta pra host autorizado.

    Comparacao por hostname EXATO (nao endsWith) — fix do bug onde
    'malicioso-exemplo.com' passava como sufixo de 'exemplo.com'.

    host_header e o cabecalho Host da request (autoritativo do servidor).
    Tambem aceita qualquer host em ALLOWED_ORIGINS (multi-domain).
    """
    if not origin_or_referer:
        return False
    try:
        parsed = urlparse(origin_or_referer)
    except Exception:
        return False
    origin_host = (parsed.hostname or "").lower()
    if not origin_host:
        return False
    expected = (host_header or "").lower().split(":")[0]
    if origin_host == expected:
        return True
    return origin_host in _ALLOWED_ORIGINS


# ---------------------------------------------------------------------------
# Rate limit por IP + path prefix
# ---------------------------------------------------------------------------

class APIRateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limit por IP com limites diferenciados por endpoint.

    A2 (R5 race-fix): _requests e _lock sao class vars compartilhados entre
    requests concorrentes. O lock atomiza read+filter+write — sem ele, dois
    requests simultaneos do mesmo IP podem ler a mesma lista, ambos acharem
    'abaixo do limit' e burlar o cap. Em single-thread asyncio sem await
    interno isso ja seria atomic, mas usamos lock como defesa em profundidade.
    """
    _requests: dict[str, list[float]] = {}
    _lock = asyncio.Lock()

    # Limites por path prefix (requests/window)
    LIMITS = {
        "/api/v1/speedtest": (5, 300),       # 5 req / 5min (scans sao pesados)
        "/api/v1/metrics": (30, 60),          # 30 req/min (agentes enviam a cada 5min)
        "/api/v1/commands": (90, 60),         # 90 req/min (1 dns-test = 30 polls/min)
        "/api/v1/session/token": (10, 60),    # 10 req/min
        "/api/v1/client": (180, 60),          # 180 req/min (portal: data + report + tests; cooldown per-user ja protege)
        "/admin/login": (5, 900),             # 5 tentativas / 15min
        "/client/login": (5, 900),            # 5 tentativas / 15min
        "/api/": (120, 60),                   # 120 req/min (default API)
    }

    def _get_limit(self, path: str) -> tuple[int, int]:
        for prefix, limit in self.LIMITS.items():
            if path.startswith(prefix):
                return limit
        return (120, 60)  # default

    async def dispatch(self, request, call_next):
        if not request.url.path.startswith(("/api/", "/admin/login", "/client/login")):
            return await call_next(request)

        ip = _real_client_ip(request)

        # Whitelisted IPs skip rate limiting (same list as security module)
        import security
        if ip in security._WHITELIST or not security.SECURITY_ENABLED:
            return await call_next(request)

        path = request.url.path
        limit, window = self._get_limit(path)

        # Key combines IP + path prefix for granular limiting
        key = f"{ip}:{path.split('/')[1:4]}"  # e.g. "1.2.3.4:['api', 'v1', 'speedtest']"
        async with self._lock:
            now = _time.time()
            reqs = self._requests.get(key, [])
            reqs = [t for t in reqs if now - t < window]

            if len(reqs) >= limit:
                logger.warning("Rate limit: %s %s (%d req/%ds)", ip, path, len(reqs), window)
                return JSONResponse(
                    {"error": "Rate limit exceeded. Try again later."},
                    status_code=429,
                    headers={"Retry-After": str(window)},
                )

            reqs.append(now)
            self._requests[key] = reqs
        return await call_next(request)


# ---------------------------------------------------------------------------
# CSRF — valida Origin/Referer em mutativos com cookie
# ---------------------------------------------------------------------------

class CSRFMiddleware(BaseHTTPMiddleware):
    """Valida Origin/Referer em requests mutativos (POST/PATCH/DELETE).
    Requests com Bearer token (agentes) sao isentos — CSRF so afeta cookies.

    SEC (Onda 1 P2): valida via comparacao EXATA de hostname (urlparse), nao
    endsWith. Bug anterior: host='exemplo.com' aceitava origin='https://malicioso-
    exemplo.com' porque a string terminava em 'exemplo.com'. Fix: extrai hostname
    do origin/referer e exige match exato OU presenca em ALLOWED_ORIGINS.
    """
    async def dispatch(self, request, call_next):
        if request.method in ("POST", "PATCH", "DELETE"):
            # Agentes usam Bearer token, nao cookies — isentos de CSRF
            auth = request.headers.get("authorization", "")
            if auth.startswith("Bearer "):
                return await call_next(request)

            origin = request.headers.get("origin", "")
            referer = request.headers.get("referer", "")
            host = request.headers.get("host", "")

            if origin:
                if not _origin_matches(origin, host):
                    logger.warning("CSRF bloqueado: origin=%s host=%s", origin, host)
                    return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
            elif referer:
                if not _origin_matches(referer, host):
                    logger.warning("CSRF bloqueado: referer=%s host=%s", referer, host)
                    return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
            # Se nenhum header presente: requests de form POST do browser SEMPRE enviam origin/referer
            # Requests sem ambos sao provavelmente curl/API — ok (cobertos por Bearer token)

        return await call_next(request)


# ---------------------------------------------------------------------------
# Security monitor — bloqueia IPs, detecta scan/brute/honeypot
# ---------------------------------------------------------------------------

class SecurityMonitorMiddleware(BaseHTTPMiddleware):
    """Detecta anomalias (scans, brute force, honeypots) e bloqueia IPs."""
    async def dispatch(self, request, call_next):
        import security

        ip = _real_client_ip(request)
        path = request.url.path

        # IP bloqueado?
        if await security.is_blocked(ip):
            return JSONResponse({"error": "Access denied"}, status_code=403)

        # Honeypot?
        if security.is_honeypot_hit(path):
            alert = await security.handle_honeypot(ip, path)
            if alert:
                await _security_alert(alert)
            return JSONResponse({"error": "Not found"}, status_code=404)

        response = await call_next(request)

        # Analisa resposta para detectar padroes
        alert = await security.analyze_request(ip, path, response.status_code, request.method)
        if alert:
            await _security_alert(alert)

        return response


async def _security_alert(alert: dict) -> None:
    """Envia alerta de seguranca via Telegram (HTML escapado).

    SEC (LL3): antes usava parse_mode="Markdown" interpolando path/IP/type
    direto entre backticks. Atacante podia injetar formatacao via path
    (`*` `_` `[`). Agora HTML com html.escape em todos campos vindos da
    request (untrusted), consistente com restante do telegram_bot.
    """
    import html as _html
    def _esc(v):
        return _html.escape(str(v) if v is not None else "")
    try:
        msg = (
            f"🚨 <b>SECURITY ALERT</b>\n"
            f"Type: <code>{_esc(alert.get('type', 'unknown'))}</code>\n"
            f"IP: <code>{_esc(alert.get('ip', '?'))}</code>\n"
        )
        if alert.get("count"):
            msg += f"Count: {int(alert['count'])} in {_esc(alert.get('window', '?'))}\n"
        if alert.get("path"):
            msg += f"Path: <code>{_esc(alert['path'])}</code>\n"
        msg += "Action: IP blocked 30min"
        await tg.send_message(msg)  # default parse_mode=HTML
    except Exception as exc:
        logger.warning("Security alert telegram failed: %s", exc)


# ---------------------------------------------------------------------------
# Audit log de mutativos
# ---------------------------------------------------------------------------

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Loga chamadas de API mutativas (POST/PATCH/DELETE) para auditoria."""
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        if request.method in ("POST", "PATCH", "DELETE") and request.url.path.startswith("/api/"):
            ip = _real_client_ip(request)
            logger.info("AUDIT %s %s %s -> %d", request.method, request.url.path, ip, response.status_code)
        return response


# ---------------------------------------------------------------------------
# Headers de seguranca + nonce CSP
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Gera nonce unico por request para CSP script-src
        nonce = base64.b64encode(secrets.token_bytes(16)).decode()
        request.state.csp_nonce = nonce

        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        # CSP refactor B (concluido 2026-05-06): unsafe-inline removido do
        # script-src. Antes era debt deliberado pq tinhamos ~40 handlers
        # inline (onclick=/onchange=/onsubmit=) que CSP3 strict bloqueia
        # quando 'nonce-X' esta presente. Refactor migrou tudo pra
        # event-bus.js + addEventListener delegado por data-action.
        #
        # Atual: 'self' + 'nonce-{nonce}' + cdn.jsdelivr.net + cf insights.
        # Inline <script> tags continuam servidas (com nonce injetado pelo
        # _html_with_nonce em main.py); event handlers HTML inline NAO
        # funcionam mais — exatamente o ponto.
        #
        # connect-src inclui cdn.jsdelivr.net pra DevTools baixar sourcemaps
        # (.js.map) sem violar CSP. Afeta so DX, nao runtime.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://static.cloudflareinsights.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
            "font-src https://fonts.gstatic.com; "
            # img-src: tiles do mapa 2D (Leaflet + CartoDB Dark Matter / Voyager) +
            # texturas do globo 3D (Globe.gl puxa earth-night/blue-marble do
            # three-globe via jsdelivr). OpenStreetMap como fallback pros tiles.
            # Adicionado 2026-05-03 pra feature de mapa de saltos de DNS trace.
            "img-src 'self' data: blob: "
            "https://*.basemaps.cartocdn.com "
            "https://*.tile.openstreetmap.org "
            "https://cdn.jsdelivr.net; "
            "connect-src 'self' https://cdn.jsdelivr.net https://cloudflareinsights.com; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        if request.url.path.startswith("/api/") or "text/html" in response.headers.get("content-type", ""):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        return response


# ---------------------------------------------------------------------------
# Limite de tamanho do body
# ---------------------------------------------------------------------------

class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Rejeita requests com body > 10MB."""
    MAX_BODY = 10 * 1024 * 1024  # 10MB

    async def dispatch(self, request, call_next):
        if request.method in ("POST", "PATCH", "PUT"):
            cl = request.headers.get("content-length")
            if cl and int(cl) > self.MAX_BODY:
                return JSONResponse({"error": "Request body too large"}, status_code=413)
        return await call_next(request)


# ---------------------------------------------------------------------------
# Fase B (C1): detector de N+1 query
# ---------------------------------------------------------------------------

# Paths estaticos / health: pular tracking pra reduzir ruido. Aceitam
# prefix match (ex: /static/foo.css cai em /static).
_N1_SKIP_PATHS = ("/static", "/favicon", "/health", "/metrics-export")


class NPlusOneDetectorMiddleware(BaseHTTPMiddleware):
    """Inicia/finaliza tracking de queries por request. Loga warning se
    algum template SQL repetiu acima de N1_DETECTOR_THRESHOLD (default: 10).

    Por que: vimos N+1 silencioso em flows admin que iteram lista de agentes
    e fazem 1 query por host. Em 100 agentes = 101 round-trips desnecessarios.
    Sem detector, so aparece quando o p95 da rota explode em prod.

    Este middleware NAO bloqueia request — apenas observa. Custo: 1 hash +
    1 dict update por query (~50us em load tipico).
    """

    async def dispatch(self, request, call_next):
        path = request.url.path
        if any(path.startswith(p) for p in _N1_SKIP_PATHS):
            return await call_next(request)

        if not _obs.N1_DETECTOR_ENABLED:
            return await call_next(request)

        _obs.start_request()
        try:
            response = await call_next(request)
        finally:
            tracker = _obs.end_request()
            if tracker is not None and tracker.total > 0:
                offenders = tracker.report(_obs.N1_DETECTOR_THRESHOLD)
                if offenders:
                    template, count = offenders[0]
                    logger.warning(
                        "N+1 detectado: %s %s — %d queries do mesmo template "
                        "(%d total no request) | template=%s",
                        request.method, path, count, tracker.total, template,
                    )
        return response


# ---------------------------------------------------------------------------
# Fase B (C2): threshold global de slow request
# ---------------------------------------------------------------------------

# Threshold em milissegundos. Default 1000ms = 1s. Configuravel pra apertar
# em ambiente de prod (e.g. 500ms).
SLOW_REQUEST_THRESHOLD_MS = int(os.environ.get("SLOW_REQUEST_THRESHOLD_MS", "1000"))

# Paths que naturalmente sao lentos (geracao de PDF, scan de speedtest,
# WebSocket): isentar pra nao spammar warnings.
_SLOW_REQUEST_SKIP_PATHS = (
    "/api/v1/speedtest",
    "/api/v1/client/report",
    "/api/v1/reports",
    "/ws/",
    "/static",
    "/favicon",
    "/health",
)


class SlowRequestMiddleware(BaseHTTPMiddleware):
    """Mede duracao de cada request e loga warning se exceder threshold.

    Capta regressoes de performance cedo: handler que era 50ms e virou 1.2s
    apos um refactor aparece no log antes de o p95 da rota explodir.
    Threshold default 1000ms — apertavel via SLOW_REQUEST_THRESHOLD_MS.

    Inclui tracker.total no log (se N+1 detector ativo) — slow request
    com muitas queries indica candidato pra batch/JOIN.
    """

    async def dispatch(self, request, call_next):
        path = request.url.path
        if any(path.startswith(p) for p in _SLOW_REQUEST_SKIP_PATHS):
            return await call_next(request)

        start = _time.monotonic()
        response = await call_next(request)
        elapsed_ms = (_time.monotonic() - start) * 1000.0

        if elapsed_ms >= SLOW_REQUEST_THRESHOLD_MS:
            # Tracker do N+1 detector (mesmo request scope, se ainda nao
            # foi limpo — middleware ordem matters). Helper get_total e
            # defensive: retorna 0 se nao houver tracker.
            tracker = _obs._query_tracker.get()
            qcount = tracker.total if tracker else 0
            logger.warning(
                "Slow request: %s %s -> %d em %.0fms (queries=%d, threshold=%dms)",
                request.method, path, response.status_code,
                elapsed_ms, qcount, SLOW_REQUEST_THRESHOLD_MS,
            )
        return response
