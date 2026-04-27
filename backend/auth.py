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
    if not auth.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalido ou ausente",
        )
    # SEC: timing-safe comparison — previne enumeração do token via timing diff
    if not hmac.compare_digest(auth[7:].encode(), AGENT_TOKEN.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalido ou ausente",
        )


# ---------------------------------------------------------------------------
# Authn dedicada — admin (cookie OU Bearer) e cliente (cookie ONLY)
# ---------------------------------------------------------------------------
# SEC: separa autenticação de agentes (Bearer) de admin (cookie + Bearer
# fallback para curl/tooling) e de clientes (cookie ONLY). Antes, qualquer
# sessão — admin ou cliente — recebia o AGENT_TOKEN via /session/token e
# podia chamar qualquer rota Bearer, quebrando isolamento multi-tenant.

async def require_admin(request: Request) -> dict:
    """Aceita admin_session cookie OU Bearer AGENT_TOKEN (curl/tooling externo).
    Retorna {"username": ..., "role": ...} para audit log e role checks."""
    cookie = request.cookies.get("admin_session", "")
    info = _verify_admin_cookie(cookie)
    if info:
        return info

    # Fallback Bearer — apenas para tooling/curl administrativo.
    # Frontend nunca deve enviar Bearer (usa cookie via credentials=same-origin).
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer ") and AGENT_TOKEN and \
       hmac.compare_digest(auth[7:].encode(), AGENT_TOKEN.encode()):
        return {"username": "admin:bearer", "role": "admin"}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Acesso negado: requer sessao admin",
    )


async def require_admin_role(request: Request) -> dict:
    """Exige role='admin'. Viewers recebem 403.
    Usado em endpoints mutativos (commands, delete, client CRUD, user management)."""
    info = await require_admin(request)
    if info["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado: requer permissao de administrador",
        )
    return info


async def require_client(request: Request) -> dict:
    """Exige client_session cookie + cliente ativo. Retorna dict do cliente
    (com 'username', 'hostnames', 'active', etc.) para o handler usar no filtro.

    NUNCA aceita Bearer — clientes não devem ter acesso a token de agente."""
    cookie = request.cookies.get("client_session", "")
    username = _verify_client_cookie(cookie)
    if not username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sessao de cliente invalida",
        )
    # Lazy import para evitar ciclo (db importa nada de auth, mas defensivo)
    import db
    user = await db.get_client(username)
    if not user or not user.get("active"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cliente inativo",
        )
    return user


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

_MIN_SECRET_BYTES = 32  # alinhado com o aviso historico ("pelo menos 32 chars")


def _load_secret(env_name: str, context: str) -> bytes:
    """Carrega secret do env.

    SEC: minimo 32 bytes (256 bits) — abaixo disso o espaço de busca pra brute
    force fica viavel. Em producao (INFRA_VISION_ENV=production) faz hard-fail
    se faltando ou abaixo do minimo. Em dev/test, gera aleatorio com warning
    (sessoes invalidam no restart, comportamento aceitavel pra desenvolvimento).
    """
    val = os.environ.get(env_name, "").encode()
    is_prod = os.environ.get("INFRA_VISION_ENV", "").lower() == "production"

    if val and len(val) >= _MIN_SECRET_BYTES:
        return val

    if is_prod:
        # Falha-fechada em producao — refuse to start sem secret valido
        raise RuntimeError(
            f"{env_name} ausente ou menor que {_MIN_SECRET_BYTES} bytes. "
            f"Em INFRA_VISION_ENV=production, secret valido e obrigatorio. "
            f"Gere com: `python -c \"import secrets; print(secrets.token_urlsafe(48))\"`"
        )

    import logging as _log
    _log.getLogger("infra-vision.auth").warning(
        "%s ausente ou menor que %d bytes — gerando aleatorio (sessions invalidam no restart). "
        "Em producao, configure INFRA_VISION_ENV=production e %s >= %d bytes.",
        env_name, _MIN_SECRET_BYTES, env_name, _MIN_SECRET_BYTES,
    )
    return secrets.token_bytes(_MIN_SECRET_BYTES)

_ADMIN_SECRET  = _load_secret("ADMIN_SESSION_SECRET", "admin")
_CLIENT_SECRET = _load_secret("CLIENT_SESSION_SECRET", "client")

# Secrets anteriores para rotacao sem downtime — aceita cookies do secret antigo durante transicao
_ADMIN_SECRET_PREV  = os.environ.get("ADMIN_SESSION_SECRET_PREV", "").encode() or None
_CLIENT_SECRET_PREV = os.environ.get("CLIENT_SESSION_SECRET_PREV", "").encode() or None

_ADMIN_SESSION_TTL  = 14400   # 4 horas
_CLIENT_SESSION_TTL = 43200   # 12 horas


def _sign_admin_cookie(username: str, role: str = "admin") -> str:
    """Gera cookie assinado com role e nonce aleatorio (previne session fixation)."""
    if role not in ("admin", "viewer"):
        role = "viewer"
    nonce = secrets.token_hex(8)
    payload = f"{username}:{role}:{nonce}"
    sig = hmac.new(_ADMIN_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def _verify_admin_cookie(cookie: str) -> Optional[dict]:
    """Verifica cookie admin. Tenta secret atual e anterior (rotacao).
    Retorna {"username": ..., "role": ...} ou None.

    SEC: formato exigido e `username:role:nonce.signature` (3 partes). Cookies
    legados de 1-2 partes (sem role explicito) sao REJEITADOS — antes eram
    tratados como role='admin' por compat, o que era surface de privilege
    escalation se atacante conseguisse forjar payload por outro canal.
    """
    if not cookie or "." not in cookie:
        return None
    payload, sig = cookie.rsplit(".", 1)
    for secret in (_ADMIN_SECRET, _ADMIN_SECRET_PREV):
        if not secret:
            continue
        expected = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, expected):
            parts = payload.split(":")
            # Formato canonico: username:role:nonce
            if len(parts) >= 3 and parts[1] in ("admin", "viewer"):
                return {"username": parts[0], "role": parts[1]}
            # Formato legado rejeitado — forca re-login com role explicito
            return None
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
