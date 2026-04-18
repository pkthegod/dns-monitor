"""
auth.py — Autenticacao, cookies HMAC, rate limiting e password hashing.

Nota: AGENT_TOKEN, ADMIN_USER, ADMIN_PASSWORD e secrets sao recalculados
a cada importacao/reload para compatibilidade com testes que usam
importlib.reload(main) + patch.dict(os.environ).
"""

import hashlib
import hmac
import os
import secrets
import time
from typing import Optional

from fastapi import HTTPException, Request, status


# ---------------------------------------------------------------------------
# Token Bearer (agentes)
# ---------------------------------------------------------------------------

AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")


async def require_token(request: Request) -> None:
    if not AGENT_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servico indisponivel",
        )
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or auth[7:] != AGENT_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalido ou ausente",
        )


# ---------------------------------------------------------------------------
# Rate limiting — protecao contra brute-force em logins
# ---------------------------------------------------------------------------

_login_attempts: dict[str, list[float]] = {}  # ip -> [timestamps]
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_LOCKOUT_SECONDS = 900  # 15 minutos


def _check_rate_limit(ip: str) -> bool:
    """Retorna True se IP esta bloqueado. Limpa tentativas expiradas."""
    now = time.time()
    attempts = _login_attempts.get(ip, [])
    attempts = [t for t in attempts if now - t < _LOGIN_LOCKOUT_SECONDS]
    _login_attempts[ip] = attempts
    return len(attempts) >= _LOGIN_MAX_ATTEMPTS


def _record_failed_login(ip: str) -> None:
    """Registra tentativa falhada de login."""
    _login_attempts.setdefault(ip, []).append(time.time())


def _clear_login_attempts(ip: str) -> None:
    """Limpa tentativas apos login bem-sucedido."""
    _login_attempts.pop(ip, None)


# ---------------------------------------------------------------------------
# Rate limiting generico — acoes com cooldown (dns-test, etc.)
# ---------------------------------------------------------------------------

_action_cooldowns: dict[str, float] = {}  # key -> timestamp do ultimo uso


def _check_cooldown(key: str, cooldown_seconds: int = 60) -> bool:
    """Retorna True se a acao esta em cooldown."""
    now = time.time()
    last = _action_cooldowns.get(key, 0)
    return (now - last) < cooldown_seconds


def _record_action(key: str) -> None:
    """Registra timestamp da acao para cooldown."""
    _action_cooldowns[key] = time.time()


# ---------------------------------------------------------------------------
# Cookies HMAC — admin e cliente
# ---------------------------------------------------------------------------

ADMIN_USER = os.environ.get("ADMIN_USER", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

def _load_secret(env_name: str, context: str) -> bytes:
    """Carrega secret do env. Se vazio, gera aleatorio (warn: sessions invalidam no restart)."""
    val = os.environ.get(env_name, "").encode()
    if val and len(val) >= 16:
        return val
    import logging as _log
    _log.getLogger("dns-monitor.auth").warning(
        "%s nao configurado ou muito curto — gerando aleatorio (sessions invalidam no restart). "
        "Configure %s com pelo menos 32 chars para persistencia.", env_name, env_name
    )
    return secrets.token_bytes(32)

_ADMIN_SECRET  = _load_secret("ADMIN_SESSION_SECRET", "admin")
_CLIENT_SECRET = _load_secret("CLIENT_SESSION_SECRET", "client")

# Secrets anteriores para rotacao sem downtime — aceita cookies do secret antigo durante transicao
_ADMIN_SECRET_PREV  = os.environ.get("ADMIN_SESSION_SECRET_PREV", "").encode() or None
_CLIENT_SECRET_PREV = os.environ.get("CLIENT_SESSION_SECRET_PREV", "").encode() or None

_ADMIN_SESSION_TTL  = 14400   # 4 horas
_CLIENT_SESSION_TTL = 43200   # 12 horas


def _sign_admin_cookie(username: str) -> str:
    """Gera cookie assinado com nonce aleatorio (previne session fixation)."""
    nonce = secrets.token_hex(8)
    payload = f"{username}:{nonce}"
    sig = hmac.new(_ADMIN_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def _verify_admin_cookie(cookie: str) -> Optional[str]:
    """Verifica cookie admin. Tenta secret atual e anterior (rotacao). Retorna username ou None."""
    if not cookie or "." not in cookie:
        return None
    payload, sig = cookie.rsplit(".", 1)
    for secret in (_ADMIN_SECRET, _ADMIN_SECRET_PREV):
        if not secret:
            continue
        expected = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, expected):
            return payload.split(":")[0] if ":" in payload else payload
    return None


def _hash_password(password: str) -> str:
    """Hash de senha com bcrypt (cost=12). Retorna string segura para armazenar."""
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def _verify_password(password: str, hashed: str) -> bool:
    """Verifica senha contra hash bcrypt. Suporta legado SHA256 para migracao."""
    import bcrypt
    if hashed.startswith("$2b$") or hashed.startswith("$2a$"):
        return bcrypt.checkpw(password.encode(), hashed.encode())
    legacy = hashlib.sha256((_CLIENT_SECRET + password.encode())).hexdigest()
    return hmac.compare_digest(legacy, hashed)


def _sign_client_cookie(username: str) -> str:
    """Cookie assinado com nonce aleatorio."""
    nonce = secrets.token_hex(8)
    payload = f"client:{username}:{nonce}"
    sig = hmac.new(_CLIENT_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def _verify_client_cookie(cookie: str) -> Optional[str]:
    """Verifica cookie de cliente. Tenta secret atual e anterior (rotacao). Retorna username ou None."""
    if not cookie or "." not in cookie:
        return None
    payload, sig = cookie.rsplit(".", 1)
    if not payload.startswith("client:"):
        return None
    for secret in (_CLIENT_SECRET, _CLIENT_SECRET_PREV):
        if not secret:
            continue
        expected = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, expected):
            parts = payload[7:].split(":")
            return parts[0] if parts else None
    return None
