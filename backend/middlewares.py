"""
middlewares.py — Middlewares HTTP do backend.

Ordem de registro em main.py (do externo para o interno):
    RequestLoggingMiddleware     — audit log de POST/PATCH/DELETE
    SecurityMonitorMiddleware    — bloqueia IPs, detecta scan/brute/honeypot
    RequestSizeLimitMiddleware   — rejeita body > 10MB
    APIRateLimitMiddleware       — rate limit por IP + path prefix
    CSRFMiddleware               — valida Origin/Referer (cookies; Bearer isento)
    SecurityHeadersMiddleware    — CSP, HSTS, etc. + gera nonce por request

Starlette executa middlewares em ordem REVERSA do add_middleware,
então o último adicionado é o mais externo.
"""

import base64
import logging
import secrets
import time as _time

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

import telegram_bot as tg

logger = logging.getLogger("infra-vision.api")


# ---------------------------------------------------------------------------
# Rate limit por IP + path prefix
# ---------------------------------------------------------------------------

class APIRateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limit por IP com limites diferenciados por endpoint."""
    _requests: dict[str, list[float]] = {}

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

        ip = request.client.host if request.client else "unknown"

        # Whitelisted IPs skip rate limiting (same list as security module)
        import security
        if ip in security._WHITELIST or not security.SECURITY_ENABLED:
            return await call_next(request)

        path = request.url.path
        limit, window = self._get_limit(path)

        # Key combines IP + path prefix for granular limiting
        key = f"{ip}:{path.split('/')[1:4]}"  # e.g. "1.2.3.4:['api', 'v1', 'speedtest']"
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
    Requests com Bearer token (agentes) sao isentos — CSRF so afeta cookies."""
    async def dispatch(self, request, call_next):
        if request.method in ("POST", "PATCH", "DELETE"):
            # Agentes usam Bearer token, nao cookies — isentos de CSRF
            auth = request.headers.get("authorization", "")
            if auth.startswith("Bearer "):
                return await call_next(request)

            origin = request.headers.get("origin", "")
            referer = request.headers.get("referer", "")
            host = request.headers.get("host", "")

            # Valida que origin/referer pertence ao mesmo host
            if origin:
                if not origin.endswith(host) and not origin.endswith(host.split(":")[0]):
                    logger.warning("CSRF bloqueado: origin=%s host=%s", origin, host)
                    return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
            elif referer:
                from urllib.parse import urlparse
                ref_host = urlparse(referer).netloc
                if ref_host != host and ref_host.split(":")[0] != host.split(":")[0]:
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

        ip = request.client.host if request.client else "unknown"
        path = request.url.path

        # IP bloqueado?
        if security.is_blocked(ip):
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
            ip = request.client.host if request.client else "-"
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
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://static.cloudflareinsights.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self' https://cloudflareinsights.com; "
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
