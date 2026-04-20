"""
security.py — Deteccao de anomalias, rate abuse e alertas de seguranca.
Monitora padroes suspeitos e alerta via Telegram.
"""

import logging
import time
from collections import defaultdict

logger = logging.getLogger("infra-vision.security")

# ---------------------------------------------------------------------------
# Contadores de eventos por IP (janela deslizante)
# ---------------------------------------------------------------------------

_events: dict[str, list[tuple[float, str]]] = defaultdict(list)  # ip -> [(ts, event_type)]
_blocked_ips: dict[str, float] = {}  # ip -> blocked_until timestamp
_alerted: dict[str, float] = {}  # key -> last_alert_ts (anti-spam)

# Thresholds
SCAN_THRESHOLD = 20        # 404s em 1 min = scan
BRUTE_THRESHOLD = 10       # login failures em 5 min = brute force
AUTH_FAIL_THRESHOLD = 30   # 401/403 em 1 min = credential stuffing
BLOCK_DURATION = 1800      # 30 min de block automatico
ALERT_COOLDOWN = 300       # 5 min entre alertas do mesmo tipo/ip


def record_event(ip: str, event_type: str) -> None:
    """Registra evento de seguranca para um IP."""
    now = time.time()
    _events[ip].append((now, event_type))
    # Limpa eventos antigos (> 10 min)
    _events[ip] = [(t, e) for t, e in _events[ip] if now - t < 600]


def is_blocked(ip: str) -> bool:
    """Retorna True se IP esta bloqueado."""
    blocked_until = _blocked_ips.get(ip, 0)
    if time.time() < blocked_until:
        return True
    if blocked_until:
        del _blocked_ips[ip]
    return False


def _block_ip(ip: str, reason: str) -> None:
    """Bloqueia IP por BLOCK_DURATION segundos."""
    _blocked_ips[ip] = time.time() + BLOCK_DURATION
    logger.warning("SECURITY: IP %s bloqueado por %ds — %s", ip, BLOCK_DURATION, reason)


def _should_alert(key: str) -> bool:
    """Anti-spam: retorna True se pode alertar (cooldown expirou)."""
    now = time.time()
    last = _alerted.get(key, 0)
    if now - last < ALERT_COOLDOWN:
        return False
    _alerted[key] = now
    return True


async def analyze_request(ip: str, path: str, status_code: int, method: str) -> dict | None:
    """
    Analisa request para detectar anomalias. Retorna dict com detalhes se detectado.
    Chamado pelo middleware apos cada response.
    """
    now = time.time()

    # Classifica o evento
    if status_code == 404:
        record_event(ip, "404")
    elif status_code in (401, 403):
        record_event(ip, "auth_fail")
    elif status_code == 429:
        record_event(ip, "rate_limited")

    events = _events.get(ip, [])
    recent_1m = [(t, e) for t, e in events if now - t < 60]
    recent_5m = [(t, e) for t, e in events if now - t < 300]

    # Deteccao 1: Port/path scan (muitos 404 em 1 min)
    n404 = sum(1 for _, e in recent_1m if e == "404")
    if n404 >= SCAN_THRESHOLD:
        _block_ip(ip, f"scan detectado ({n404} 404s em 1 min)")
        if _should_alert(f"scan:{ip}"):
            return {"type": "scan", "ip": ip, "count": n404, "window": "1 min"}

    # Deteccao 2: Brute force (muitos auth failures em 5 min)
    n_auth = sum(1 for _, e in recent_5m if e == "auth_fail")
    if n_auth >= BRUTE_THRESHOLD:
        _block_ip(ip, f"brute force detectado ({n_auth} auth failures em 5 min)")
        if _should_alert(f"brute:{ip}"):
            return {"type": "brute_force", "ip": ip, "count": n_auth, "window": "5 min"}

    # Deteccao 3: Credential stuffing (muitos 401/403 rapidos)
    if n_auth >= AUTH_FAIL_THRESHOLD:
        _block_ip(ip, f"credential stuffing ({n_auth} em 1 min)")
        if _should_alert(f"stuffing:{ip}"):
            return {"type": "credential_stuffing", "ip": ip, "count": n_auth, "window": "1 min"}

    return None


# ---------------------------------------------------------------------------
# Honeypot paths — atrai scanners/bots automaticos
# ---------------------------------------------------------------------------

HONEYPOT_PATHS = {
    "/wp-admin", "/wp-login.php", "/.env", "/phpmyadmin",
    "/admin.php", "/xmlrpc.php", "/config.json", "/debug",
    "/.git/config", "/api/v1/admin/config", "/backup.sql",
    "/shell", "/cmd", "/eval", "/.aws/credentials",
}


def is_honeypot_hit(path: str) -> bool:
    """Retorna True se path e um honeypot (scanner/bot)."""
    path_lower = path.lower().split("?")[0]
    return path_lower in HONEYPOT_PATHS


async def handle_honeypot(ip: str, path: str) -> dict:
    """Registra hit em honeypot, bloqueia IP, retorna detalhes para alerta."""
    record_event(ip, "honeypot")
    _block_ip(ip, f"honeypot hit: {path}")
    logger.warning("HONEYPOT: %s acessou %s — IP bloqueado", ip, path)
    if _should_alert(f"honeypot:{ip}"):
        return {"type": "honeypot", "ip": ip, "path": path}
    return {}


def get_blocked_ips() -> list[dict]:
    """Lista IPs atualmente bloqueados (para admin)."""
    now = time.time()
    return [
        {"ip": ip, "blocked_until": until, "remaining_seconds": int(until - now)}
        for ip, until in _blocked_ips.items()
        if until > now
    ]
