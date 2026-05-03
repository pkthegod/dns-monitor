"""
auth.py — Autenticacao, cookies HMAC, rate limiting e password hashing.

Nota: AGENT_TOKEN, ADMIN_USER, ADMIN_PASSWORD e secrets sao recalculados
a cada importacao/reload para compatibilidade com testes que usam
importlib.reload(main) + patch.dict(os.environ).
"""

import hashlib
import hmac
import ipaddress
import os
import secrets
import time
from typing import Optional

from fastapi import HTTPException, Request, status


# ---------------------------------------------------------------------------
# Token Bearer (agentes)
# ---------------------------------------------------------------------------

AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")


# SEC (M8): whitelist de IPs autorizados a usar o fallback Bearer no endpoint
# require_admin. Mitigacao parcial enquanto AGENT_TOKEN ainda e compartilhado:
# mesmo com o token vazado, atacante so age como admin se vier de um IP
# pre-aprovado (rede do operador).
#
# Formatos aceitos (vingula-separados): "10.0.0.0/8,192.168.1.5,2001:db8::/32"
# Vazio (default) = sem whitelist = mantem comportamento legado (todos IPs).
_ADMIN_BEARER_RAW = os.environ.get("ADMIN_BEARER_ALLOWED_IPS", "").strip()


def _parse_ip_whitelist(raw: str) -> list:
    out = []
    for entry in (e.strip() for e in raw.split(",")):
        if not entry:
            continue
        try:
            if "/" in entry:
                out.append(ipaddress.ip_network(entry, strict=False))
            else:
                out.append(ipaddress.ip_address(entry))
        except ValueError:
            # entry invalida — pulamos silenciosamente (log no startup do main)
            continue
    return out


_ADMIN_BEARER_ALLOWED = _parse_ip_whitelist(_ADMIN_BEARER_RAW)

# SEC (Onda 1 P3): em INFRA_VISION_ENV=production o fallback Bearer admin DEVE
# estar gateado por ADMIN_BEARER_ALLOWED_IPS OU explicitamente desabilitado via
# ADMIN_BEARER_DISABLED=true. Sem isso, qualquer IP com AGENT_TOKEN vira admin —
# e AGENT_TOKEN esta em todos os agentes, entao um agente comprometido = admin
# global. Hard-fail no startup forca decisao consciente.
_PROD = os.environ.get("INFRA_VISION_ENV", "").lower() == "production"
_ADMIN_BEARER_DISABLED = os.environ.get(
    "ADMIN_BEARER_DISABLED", ""
).lower() in ("true", "1", "yes")

if _PROD and not _ADMIN_BEARER_ALLOWED and not _ADMIN_BEARER_DISABLED:
    raise RuntimeError(
        "INFRA_VISION_ENV=production exige ADMIN_BEARER_ALLOWED_IPS "
        "(range autorizado, ex: 10.0.0.0/24) OU ADMIN_BEARER_DISABLED=true "
        "(rejeita todo Bearer admin). Sem nenhum dos dois, qualquer IP com "
        "AGENT_TOKEN vira admin — surface de privilege escalation."
    )


def _ip_in_admin_bearer_whitelist(ip_str: str) -> bool:
    """Retorna True se a whitelist esta vazia (legado) OU se o IP bate."""
    if not _ADMIN_BEARER_ALLOWED:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for entry in _ADMIN_BEARER_ALLOWED:
        if isinstance(entry, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            if ip in entry:
                return True
        elif ip == entry:
            return True
    return False


# ---------------------------------------------------------------------------
# Trusted proxy + IP real do cliente
# ---------------------------------------------------------------------------
# SEC (Onda 1 P1): rate-limit, security monitor e audit precisam do IP REAL
# do cliente, nao do nginx/CF imediato. Antes, request.client.host retornava
# IP do proxy => todo trafego "vinha de 1 IP" e burlava rate-limit + escondia
# atacante real no audit_log.
#
# Header trust gating: so confiamos em CF-Connecting-IP / X-Forwarded-For se
# o hop imediato (request.client.host) bater em TRUSTED_PROXIES. Sem isso,
# atacante setaria X-Forwarded-For: 1.2.3.4 direto e burlaria.
#
# TRUSTED_PROXIES aceita IPs e CIDRs separados por virgula. Tipico:
#   - Docker bridge gateway (172.20.0.1) se nginx e outro container
#   - 127.0.0.1 se nginx roda no host e backend escuta em 8000

_TRUSTED_PROXIES_RAW = os.environ.get("TRUSTED_PROXIES", "").strip()
_TRUSTED_PROXIES = _parse_ip_whitelist(_TRUSTED_PROXIES_RAW)


def _ip_in_trusted_proxies(ip_str: str) -> bool:
    """True se IP esta em TRUSTED_PROXIES (lista vazia = ninguem confiavel)."""
    if not _TRUSTED_PROXIES:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for entry in _TRUSTED_PROXIES:
        if isinstance(entry, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            if ip in entry:
                return True
        elif ip == entry:
            return True
    return False


def _real_client_ip(request) -> str:
    """Retorna IP real do cliente respeitando proxies confiaveis.

    Logica:
      1. direct = request.client.host (IP do hop imediato)
      2. Se direct nao esta em TRUSTED_PROXIES -> retorna direct
         (atacante poderia ter forjado X-Forwarded-For; ignora)
      3. Senao tenta CF-Connecting-IP (Cloudflare proxied), depois
         X-Forwarded-For[0] (left-most do XFF chain)
      4. Se nenhum header valido -> volta pra direct

    Compat: TRUSTED_PROXIES vazio = comportamento legado (sempre retorna
    request.client.host). Migrate sem precisar reconfigurar nada.
    """
    direct = request.client.host if request.client else "unknown"
    if not _ip_in_trusted_proxies(direct):
        return direct
    cf = request.headers.get("cf-connecting-ip", "").strip()
    if cf:
        try:
            ipaddress.ip_address(cf)
            return cf
        except ValueError:
            pass
    xff = request.headers.get("x-forwarded-for", "").strip()
    if xff:
        first = xff.split(",")[0].strip()
        try:
            ipaddress.ip_address(first)
            return first
        except ValueError:
            pass
    return direct


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
    # SEC (M8 + Onda 1 P3): triagem em 3 niveis:
    #  1. ADMIN_BEARER_DISABLED=true -> rejeita TUDO (recomendado em prod com
    #     operadores que so usam cookie via /admin/login)
    #  2. ADMIN_BEARER_ALLOWED_IPS set -> aceita so IPs pre-aprovados
    #  3. Sem nenhum dos dois (legado dev) -> aceita de qualquer IP
    # Em prod, item 1 ou 2 e exigido no startup (ver _PROD check acima).
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer ") and AGENT_TOKEN and \
       hmac.compare_digest(auth[7:].encode(), AGENT_TOKEN.encode()):
        if _ADMIN_BEARER_DISABLED:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Bearer admin desativado neste ambiente (use cookie de sessao)",
            )
        ip = _real_client_ip(request)
        if not _ip_in_admin_bearer_whitelist(ip):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Bearer fallback admin nao autorizado deste IP",
            )
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
#
# A2 (R1 race-fix): asyncio.Lock protege estado mutavel compartilhado entre
# coroutines. Em Python asyncio single-thread, codigo sem await nao preempta —
# entao os corpos sync abaixo ja seriam atomic se chamados isoladamente. O
# lock e necessario porque os callers fazem CHECK em uma coroutine, suspendem
# (await form/db/etc), e ACT em outra — entre os awaits, outras coroutines
# podem rodar a mesma sequencia.
#
# Limitacao: vale apenas pra single-process. Multi-worker exige Redis ou
# Postgres advisory lock (D7 no roadmap).

_login_attempts: dict[str, list[float]] = {}  # ip -> [timestamps]
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_LOCKOUT_SECONDS = 900  # 15 minutos

import asyncio
_login_lock = asyncio.Lock()


async def _check_rate_limit(ip: str) -> bool:
    """Retorna True se IP esta bloqueado. Limpa tentativas expiradas."""
    async with _login_lock:
        now = time.time()
        attempts = _login_attempts.get(ip, [])
        attempts = [t for t in attempts if now - t < _LOGIN_LOCKOUT_SECONDS]
        _login_attempts[ip] = attempts
        return len(attempts) >= _LOGIN_MAX_ATTEMPTS


async def _record_failed_login(ip: str) -> None:
    """Registra tentativa falhada de login."""
    async with _login_lock:
        _login_attempts.setdefault(ip, []).append(time.time())


async def _clear_login_attempts(ip: str) -> None:
    """Limpa tentativas apos login bem-sucedido."""
    async with _login_lock:
        _login_attempts.pop(ip, None)


# ---------------------------------------------------------------------------
# Rate limiting generico — acoes com cooldown (dns-test, etc.)
# ---------------------------------------------------------------------------

_action_cooldowns: dict[str, float] = {}  # key -> timestamp do ultimo uso
_cooldown_lock = asyncio.Lock()


async def _check_cooldown(key: str, cooldown_seconds: int = 60) -> bool:
    """Retorna True se a acao esta em cooldown."""
    async with _cooldown_lock:
        now = time.time()
        last = _action_cooldowns.get(key, 0)
        return (now - last) < cooldown_seconds


async def _record_action(key: str) -> None:
    """Registra timestamp da acao para cooldown."""
    async with _cooldown_lock:
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
