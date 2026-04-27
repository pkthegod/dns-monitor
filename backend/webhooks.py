"""
webhooks.py — Disparo de alertas para webhooks externos (Slack, Teams, PagerDuty, generico).

SEC: webhook_url e fornecido pelo admin do tenant. Sem validacao, vira vetor
SSRF — atacante seta URL apontando pra metadata service da nuvem (ex.
http://169.254.169.254/), localhost (http://localhost:6379 ataca redis),
ou redes privadas internas. Validamos em 2 camadas: na criacao do cliente
(rejeita URL invalida) e antes de cada send (defense in depth).
"""

import ipaddress
import json
import logging
import os
import socket
import urllib.parse
import urllib.request
from typing import Optional

logger = logging.getLogger("infra-vision.webhooks")


# Permite override em dev (ex: testar webhook localhost). Em prod, deixar vazio.
_ALLOW_PRIVATE_WEBHOOKS = os.environ.get(
    "INFRA_VISION_ALLOW_PRIVATE_WEBHOOKS", ""
).lower() in ("1", "true", "yes")


def _is_private_ip(ip_str: str) -> bool:
    """True se IP esta em range privado/reservado/loopback/link-local/metadata."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (
        ip.is_private        # 10/8, 172.16/12, 192.168/16, fc00::/7
        or ip.is_loopback    # 127.0.0.0/8, ::1
        or ip.is_link_local  # 169.254/16, fe80::/10 (cobre AWS/GCP/Azure metadata)
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_safe_webhook_url(url: str) -> tuple[bool, str]:
    """Valida webhook URL contra SSRF. Retorna (ok, motivo_se_invalido).

    Regras:
      1. Schema = https (http rejeitado — webhook deveria ser TLS)
      2. Host nao pode ser IP privado direto
      3. Hostname nao pode resolver pra IP privado (DNS rebind protection)
      4. Porta nao pode ser <1024 exceto 443 (impede SSH/Redis/etc)
      5. URL <= 2KB (anti-DoS)

    Em INFRA_VISION_ALLOW_PRIVATE_WEBHOOKS=true (dev), libera. Em prod, NAO setar.
    """
    if not url or len(url) > 2048:
        return False, "URL vazia ou muito longa (>2KB)"

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as exc:
        return False, f"URL malformada: {exc}"

    if parsed.scheme != "https":
        return False, "Apenas https permitido (http e fragil; webhook deve ser TLS)"

    if not parsed.hostname:
        return False, "Hostname ausente"

    if _ALLOW_PRIVATE_WEBHOOKS:
        return True, ""

    # Porta — bloqueia portas privilegiadas exceto 443 (https) e >=1024
    port = parsed.port
    if port is not None and port < 1024 and port != 443:
        return False, f"Porta {port} bloqueada (use 443 ou >=1024)"
    if port is not None and port > 65535:
        return False, "Porta invalida"

    # Host literal IP
    try:
        ipaddress.ip_address(parsed.hostname)
        if _is_private_ip(parsed.hostname):
            return False, f"IP {parsed.hostname} em range privado/reservado"
        return True, ""
    except ValueError:
        pass  # nao e IP literal — resolver via DNS

    # DNS resolve — pode retornar multiplos A/AAAA, todos precisam ser publicos
    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as exc:
        return False, f"Hostname nao resolve: {exc}"

    for info in infos:
        ip_resolved = info[4][0]
        if _is_private_ip(ip_resolved):
            return False, f"Hostname resolve pra IP privado: {ip_resolved}"

    return True, ""


def detect_format(url: str) -> str:
    """Auto-detecta o formato do webhook pela URL."""
    if "hooks.slack.com" in url:
        return "slack"
    if "webhook.office.com" in url or "microsoft.com" in url:
        return "teams"
    if "events.pagerduty.com" in url:
        return "pagerduty"
    return "generic"


def _build_payload(
    fmt: str,
    alert_type: str,
    severity: str,
    hostname: str,
    message: str,
) -> dict:
    """Monta payload no formato correto para cada servico."""
    color = "#f7768e" if severity == "critical" else "#e0af68" if severity == "warning" else "#9ece6a"

    if fmt == "slack":
        return {
            "attachments": [{
                "color": color,
                "title": f"Infra-Vision — {severity.upper()}",
                "text": message,
                "fields": [
                    {"title": "Host", "value": hostname, "short": True},
                    {"title": "Tipo", "value": alert_type, "short": True},
                ],
                "footer": "Infra-Vision",
            }]
        }

    if fmt == "teams":
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color.replace("#", ""),
            "summary": f"Infra-Vision — {alert_type} ({severity})",
            "sections": [{
                "activityTitle": f"Infra-Vision — {severity.upper()}",
                "facts": [
                    {"name": "Host", "value": hostname},
                    {"name": "Tipo", "value": alert_type},
                    {"name": "Severidade", "value": severity},
                ],
                "text": message,
            }]
        }

    if fmt == "pagerduty":
        return {
            "routing_key": "",  # preenchido pela URL
            "event_action": "trigger",
            "payload": {
                "summary": f"[{severity.upper()}] {hostname}: {message}",
                "severity": "critical" if severity == "critical" else "warning",
                "source": "infra-vision",
                "component": hostname,
                "custom_details": {"alert_type": alert_type, "message": message},
            },
        }

    # generic — JSON simples
    return {
        "source": "infra-vision",
        "severity": severity,
        "alert_type": alert_type,
        "hostname": hostname,
        "message": message,
    }


def send_webhook(
    url: str,
    alert_type: str,
    severity: str,
    hostname: str,
    message: str,
) -> bool:
    """Envia alerta para webhook. Retorna True se 2xx."""
    if not url:
        return False

    # SEC: defense in depth — re-valida antes de cada send. Mesmo com validacao
    # na criacao do cliente, DNS pode ter mudado (rebind), URL pode ter sido
    # alterada via DB direto, etc.
    safe, reason = is_safe_webhook_url(url)
    if not safe:
        logger.warning("Webhook bloqueado por SSRF check: %s — %s", url[:80], reason)
        return False

    fmt = detect_format(url)
    payload = _build_payload(fmt, alert_type, severity, hostname, message)
    data = json.dumps(payload).encode("utf-8")

    try:
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            ok = 200 <= resp.status < 300
            if ok:
                logger.info("Webhook %s enviado: %s %s/%s", fmt, hostname, alert_type, severity)
            else:
                logger.warning("Webhook %s retornou %d", fmt, resp.status)
            return ok
    except Exception as exc:
        logger.warning("Webhook %s falhou para %s: %s", fmt, url[:50], exc)
        return False


async def dispatch_alert_webhooks(
    hostname: str,
    alert_type: str,
    severity: str,
    message: str,
    webhook_urls: list[str],
) -> int:
    """Envia alerta para todos os webhooks configurados. Retorna qtd de sucesso."""
    import asyncio
    loop = asyncio.get_running_loop()
    sent = 0
    for url in webhook_urls:
        ok = await loop.run_in_executor(None, send_webhook, url, alert_type, severity, hostname, message)
        if ok:
            sent += 1
    return sent
