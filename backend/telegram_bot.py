"""
telegram_bot.py — Envio de mensagens via Telegram Bot API.
Formata alertas e relatórios periódicos para o chat configurado.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Optional

import httpx

logger = logging.getLogger("dns-monitor.telegram")

TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"

# Lidos de variáveis de ambiente (definidas no docker-compose)
def _token() -> str:
    return os.environ.get("TELEGRAM_BOT_TOKEN", "")

def _chat_id() -> str:
    return os.environ.get("TELEGRAM_CHAT_ID", "")


# ---------------------------------------------------------------------------
# Envio base
# ---------------------------------------------------------------------------

async def send_message(text: str, parse_mode: str = "HTML") -> bool:
    """
    Envia uma mensagem ao chat configurado.
    Retorna True se enviado com sucesso.
    Silencia erros — alerta de Telegram nunca deve derrubar o backend.
    """
    token = _token()
    chat_id = _chat_id()

    if not token or not chat_id:
        logger.warning("Telegram não configurado (TELEGRAM_BOT_TOKEN ou TELEGRAM_CHAT_ID ausente)")
        return False

    url = TELEGRAM_API.format(token=token)
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True,
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                logger.debug("Telegram: mensagem enviada com sucesso")
                return True
            logger.warning("Telegram retornou HTTP %d: %s", resp.status_code, resp.text[:200])
    except httpx.TimeoutException:
        logger.warning("Telegram: timeout ao enviar mensagem")
    except httpx.RequestError as exc:
        logger.error("Telegram: erro de conexão: %s", exc)

    return False


# ---------------------------------------------------------------------------
# Formatadores de alerta
# ---------------------------------------------------------------------------

def _ts_now() -> str:
    return datetime.now(timezone.utc).strftime("%d/%m %H:%M UTC")


async def alert_dns_failure(hostname: str, domain: str, error: str, attempts: int) -> bool:
    text = (
        f"🔴 <b>DNS FALHOU</b>\n"
        f"<b>Host:</b> <code>{hostname}</code>\n"
        f"<b>Domínio:</b> {domain}\n"
        f"<b>Erro:</b> {error}\n"
        f"<b>Tentativas:</b> {attempts}/3\n"
        f"<b>Hora:</b> {_ts_now()}"
    )
    return await send_message(text)


async def alert_dns_latency(hostname: str, domain: str, latency_ms: float, threshold_ms: int, severity: str) -> bool:
    icon = "🔴" if severity == "critical" else "🟡"
    text = (
        f"{icon} <b>DNS LATÊNCIA ALTA</b>\n"
        f"<b>Host:</b> <code>{hostname}</code>\n"
        f"<b>Domínio:</b> {domain}\n"
        f"<b>Latência:</b> {latency_ms:.0f}ms (limite: {threshold_ms}ms)\n"
        f"<b>Hora:</b> {_ts_now()}"
    )
    return await send_message(text)


async def alert_dns_service_down(hostname: str, service_name: str) -> bool:
    text = (
        f"🔴 <b>SERVIÇO DNS INATIVO</b>\n"
        f"<b>Host:</b> <code>{hostname}</code>\n"
        f"<b>Serviço:</b> {service_name}\n"
        f"<b>Hora:</b> {_ts_now()}"
    )
    return await send_message(text)


async def alert_cpu(hostname: str, cpu_percent: float, threshold: int, severity: str) -> bool:
    icon = "🔴" if severity == "critical" else "🟡"
    text = (
        f"{icon} <b>CPU ALTA</b>\n"
        f"<b>Host:</b> <code>{hostname}</code>\n"
        f"<b>CPU:</b> {cpu_percent:.1f}% (limite: {threshold}%)\n"
        f"<b>Hora:</b> {_ts_now()}"
    )
    return await send_message(text)


async def alert_ram(hostname: str, ram_percent: float, threshold: int, severity: str) -> bool:
    icon = "🔴" if severity == "critical" else "🟡"
    text = (
        f"{icon} <b>RAM ALTA</b>\n"
        f"<b>Host:</b> <code>{hostname}</code>\n"
        f"<b>RAM:</b> {ram_percent:.1f}% (limite: {threshold}%)\n"
        f"<b>Hora:</b> {_ts_now()}"
    )
    return await send_message(text)


async def alert_disk(hostname: str, mountpoint: str, disk_percent: float, threshold: int, severity: str) -> bool:
    icon = "🔴" if severity == "critical" else "🟡"
    text = (
        f"{icon} <b>DISCO CRÍTICO</b>\n"
        f"<b>Host:</b> <code>{hostname}</code>\n"
        f"<b>Partição:</b> {mountpoint}\n"
        f"<b>Uso:</b> {disk_percent:.1f}% (limite: {threshold}%)\n"
        f"<b>Hora:</b> {_ts_now()}"
    )
    return await send_message(text)


async def alert_agent_offline(hostname: str, last_seen: Optional[datetime]) -> bool:
    last = last_seen.strftime("%d/%m %H:%M UTC") if last_seen else "nunca visto"
    text = (
        f"⚫ <b>AGENTE OFFLINE</b>\n"
        f"<b>Host:</b> <code>{hostname}</code>\n"
        f"<b>Último contato:</b> {last}\n"
        f"<b>Detectado em:</b> {_ts_now()}"
    )
    return await send_message(text)


async def alert_agent_recovered(hostname: str) -> bool:
    text = (
        f"🟢 <b>AGENTE RECUPERADO</b>\n"
        f"<b>Host:</b> <code>{hostname}</code>\n"
        f"<b>Hora:</b> {_ts_now()}"
    )
    return await send_message(text)


# ---------------------------------------------------------------------------
# Relatório periódico (enviado 4×/dia junto com os ciclos)
# ---------------------------------------------------------------------------

async def send_report(
    total_agents: int,
    online_agents: int,
    offline_agents: list[str],
    dns_failures: list[dict],
    disk_warnings: list[dict],
    open_alerts: int,
) -> bool:
    """
    Relatório consolidado de todos os agentes.
    Chamado pelo scheduler do backend nos mesmos horários dos checks.
    """
    status_icon = "✅" if not offline_agents and not dns_failures else "⚠️"

    lines = [
        f"{status_icon} <b>Relatório DNS Monitor</b> — {_ts_now()}",
        "",
        f"<b>Agentes:</b> {online_agents}/{total_agents} online",
    ]

    if offline_agents:
        lines.append(f"<b>Offline:</b> {', '.join(f'<code>{h}</code>' for h in offline_agents)}")

    if dns_failures:
        lines.append("")
        lines.append("<b>Falhas DNS:</b>")
        for f in dns_failures[:10]:  # Limita para não estourar mensagem
            lines.append(f"  • <code>{f['hostname']}</code> → {f['domain']} ({f['error']})")

    if disk_warnings:
        lines.append("")
        lines.append("<b>Disco acima do limite:</b>")
        for d in disk_warnings[:10]:
            lines.append(f"  • <code>{d['hostname']}</code> {d['mountpoint']}: {d['disk_percent']:.0f}%")

    if open_alerts:
        lines.append("")
        lines.append(f"<b>Alertas abertos:</b> {open_alerts}")

    if not offline_agents and not dns_failures and not disk_warnings:
        lines.append("")
        lines.append("Tudo operacional. 🟢")

    return await send_message("\n".join(lines))
