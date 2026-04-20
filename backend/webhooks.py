"""
webhooks.py — Disparo de alertas para webhooks externos (Slack, Teams, PagerDuty, generico).
"""

import json
import logging
import urllib.request
from typing import Optional

logger = logging.getLogger("infra-vision.webhooks")


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
