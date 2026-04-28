"""
telegram_bot.py — Envio de mensagens via Telegram Bot API.
Formata alertas e relatórios periódicos para o chat configurado.
"""

import html as _html
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import httpx

logger = logging.getLogger("infra-vision.telegram")

TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"


# SEC (LL3): helper para escapar campos user-controlled antes de interpolar
# em mensagens HTML. Hostname/erro/dominio/mountpoint vem do agente (potencial
# atacante se 1 agente comprometido) e podem conter `<`, `>`, `&` que quebram
# o parse HTML do Telegram OU injetam tags forjadas alterando aparencia.
def _h(value) -> str:
    """HTML-escape generico. Trata None como string vazia."""
    return _html.escape(str(value) if value is not None else "", quote=False)

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
        f"<b>Host:</b> <code>{_h(hostname)}</code>\n"
        f"<b>Domínio:</b> {_h(domain)}\n"
        f"<b>Erro:</b> {_h(error)}\n"
        f"<b>Tentativas:</b> {int(attempts)}/3\n"
        f"<b>Hora:</b> {_ts_now()}"
    )
    return await send_message(text)


async def alert_dns_latency(hostname: str, domain: str, latency_ms: float, threshold_ms: int, severity: str) -> bool:
    icon = "🔴" if severity == "critical" else "🟡"
    text = (
        f"{icon} <b>DNS LATÊNCIA ALTA</b>\n"
        f"<b>Host:</b> <code>{_h(hostname)}</code>\n"
        f"<b>Domínio:</b> {_h(domain)}\n"
        f"<b>Latência:</b> {latency_ms:.0f}ms (limite: {int(threshold_ms)}ms)\n"
        f"<b>Hora:</b> {_ts_now()}"
    )
    return await send_message(text)


async def alert_dns_service_down(hostname: str, service_name: str) -> bool:
    text = (
        f"🔴 <b>SERVIÇO DNS INATIVO</b>\n"
        f"<b>Host:</b> <code>{_h(hostname)}</code>\n"
        f"<b>Serviço:</b> {_h(service_name)}\n"
        f"<b>Hora:</b> {_ts_now()}"
    )
    return await send_message(text)


async def alert_cpu(hostname: str, cpu_percent: float, threshold: int, severity: str) -> bool:
    icon = "🔴" if severity == "critical" else "🟡"
    text = (
        f"{icon} <b>CPU ALTA</b>\n"
        f"<b>Host:</b> <code>{_h(hostname)}</code>\n"
        f"<b>CPU:</b> {cpu_percent:.1f}% (limite: {int(threshold)}%)\n"
        f"<b>Hora:</b> {_ts_now()}"
    )
    return await send_message(text)


async def alert_ram(hostname: str, ram_percent: float, threshold: int, severity: str) -> bool:
    icon = "🔴" if severity == "critical" else "🟡"
    text = (
        f"{icon} <b>RAM ALTA</b>\n"
        f"<b>Host:</b> <code>{_h(hostname)}</code>\n"
        f"<b>RAM:</b> {ram_percent:.1f}% (limite: {int(threshold)}%)\n"
        f"<b>Hora:</b> {_ts_now()}"
    )
    return await send_message(text)


async def alert_disk(hostname: str, mountpoint: str, disk_percent: float, threshold: int, severity: str) -> bool:
    icon = "🔴" if severity == "critical" else "🟡"
    text = (
        f"{icon} <b>DISCO CRÍTICO</b>\n"
        f"<b>Host:</b> <code>{_h(hostname)}</code>\n"
        f"<b>Partição:</b> {_h(mountpoint)}\n"
        f"<b>Uso:</b> {disk_percent:.1f}% (limite: {int(threshold)}%)\n"
        f"<b>Hora:</b> {_ts_now()}"
    )
    return await send_message(text)


async def alert_agent_offline(hostname: str, last_seen: Optional[datetime]) -> bool:
    last = last_seen.strftime("%d/%m %H:%M UTC") if last_seen else "nunca visto"
    text = (
        f"⚫ <b>AGENTE OFFLINE</b>\n"
        f"<b>Host:</b> <code>{_h(hostname)}</code>\n"
        f"<b>Último contato:</b> {last}\n"
        f"<b>Detectado em:</b> {_ts_now()}"
    )
    return await send_message(text)


async def alert_agent_recovered(hostname: str) -> bool:
    text = (
        f"🟢 <b>AGENTE RECUPERADO</b>\n"
        f"<b>Host:</b> <code>{_h(hostname)}</code>\n"
        f"<b>Hora:</b> {_ts_now()}"
    )
    return await send_message(text)



async def send_command_result(
    hostname: str,
    command: str,
    status: str,
    result: str,
    issued_by: str = "admin",
) -> bool:
    """
    Alerta disparado quando o agente reporta o resultado de um comando remoto.

    Casos cobertos:
      enable  + done    → serviço restabelecido
      stop    + done    → serviço suspenso
      disable + done    → serviço suspenso
      purge   + done    → serviço removido (crítico)
      qualquer + failed → comando falhou
    """
    ts = _ts_now()
    detail = result[:300] if result else ""
    # SEC: hostname, command e issued_by escapados; detail/result vem do agente
    # (untrusted) e tambem precisa escapar.
    h_host = _h(hostname)
    h_cmd = _h(command)
    h_by = _h(issued_by)
    h_detail = _h(detail)

    # ── update_agent — feedback detalhado ────────────────────────────────────
    if command == "update_agent":
        if status == "done":
            if "já está" in detail or "nenhuma ação" in detail:
                text = (
                    f"✅ <b>AGENTE JÁ ATUALIZADO</b>\n"
                    f"<b>Host:</b> <code>{h_host}</code>\n"
                    f"<b>Info:</b> {h_detail}\n"
                    f"<b>Por:</b> {h_by}\n"
                    f"<b>Hora:</b> {ts}"
                )
            else:
                text = (
                    f"🔄 <b>AGENTE ATUALIZADO</b>\n"
                    f"<b>Host:</b> <code>{h_host}</code>\n"
                    f"<b>Resultado:</b> {h_detail}\n"
                    f"<b>Por:</b> {h_by}\n"
                    f"<b>Hora:</b> {ts}"
                )
        else:
            text = (
                f"❌ <b>UPDATE FALHOU</b>\n"
                f"<b>Host:</b> <code>{h_host}</code>\n"
                f"<b>Erro:</b> <code>{h_detail or 'sem detalhes'}</code>\n"
                f"<b>Por:</b> {h_by}\n"
                f"<b>Hora:</b> {ts}"
            )
        return await send_message(text)

    # ── demais comandos ──────────────────────────────────────────────────────
    if status == "done":
        if command == "restart":
            text = (
                f"🔁 <b>SERVIÇO DNS REINICIADO</b>\n"
                f"<b>Host:</b> <code>{h_host}</code>\n"
                f"<b>Por:</b> {h_by}\n"
                f"<b>Hora:</b> {ts}"
            )
        elif command == "enable":
            text = (
                f"✅ <b>SERVIÇO DNS RESTABELECIDO</b>\n"
                f"<b>Host:</b> <code>{h_host}</code>\n"
                f"<b>Por:</b> {h_by}\n"
                f"<b>Hora:</b> {ts}"
            )
        elif command == "purge":
            text = (
                f"🚨 <b>SERVIÇO DNS REMOVIDO</b>\n"
                f"<b>Host:</b> <code>{h_host}</code>\n"
                f"<b>Por:</b> {h_by}\n"
                f"<b>Hora:</b> {ts}\n"
                f"⚠️ O pacote DNS foi desinstalado desta máquina."
            )
        elif command in ("stop", "disable"):
            acao = "parado" if command == "stop" else "desabilitado"
            text = (
                f"⏸️ <b>SERVIÇO DNS SUSPENSO</b>\n"
                f"<b>Host:</b> <code>{h_host}</code>\n"
                f"<b>Ação:</b> {h_cmd} ({acao})\n"
                f"<b>Por:</b> {h_by}\n"
                f"<b>Hora:</b> {ts}"
            )
        else:
            text = (
                f"✅ <b>COMANDO EXECUTADO</b>\n"
                f"<b>Host:</b> <code>{h_host}</code>\n"
                f"<b>Comando:</b> {h_cmd}\n"
                f"<b>Resultado:</b> {h_detail or 'OK'}\n"
                f"<b>Por:</b> {h_by}\n"
                f"<b>Hora:</b> {ts}"
            )
    else:
        # failed
        text = (
            f"⚠️ <b>COMANDO FALHOU</b>\n"
            f"<b>Host:</b> <code>{h_host}</code>\n"
            f"<b>Comando:</b> {h_cmd}\n"
            f"<b>Erro:</b> <code>{h_detail or 'sem detalhes'}</code>\n"
            f"<b>Por:</b> {h_by}\n"
            f"<b>Hora:</b> {ts}"
        )

    return await send_message(text)


async def send_new_agent_detected(hostname: str, version: str = "") -> bool:
    """Alerta quando um novo agente faz o primeiro heartbeat."""
    text = (
        f"🆕 <b>NOVO AGENTE DETECTADO</b>\n"
        f"<b>Host:</b> <code>{_h(hostname)}</code>\n"
        f"<b>Versão:</b> {_h(version) or 'desconhecida'}\n"
        f"<b>Hora:</b> {_ts_now()}\n"
        f"ℹ️ Agente registrado automaticamente."
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
        f"{status_icon} <b>Relatório Infra-Vision</b> — {_ts_now()}",
        "",
        f"<b>Agentes:</b> {online_agents}/{total_agents} online",
    ]

    if offline_agents:
        lines.append(f"<b>Offline:</b> {', '.join(f'<code>{_h(host)}</code>' for host in offline_agents)}")

    if dns_failures:
        lines.append("")
        lines.append("<b>Falhas DNS:</b>")
        for f in dns_failures[:10]:  # Limita para não estourar mensagem
            lines.append(f"  • <code>{_h(f['hostname'])}</code> → {_h(f['domain'])} ({_h(f['error'])})")

    if disk_warnings:
        lines.append("")
        lines.append("<b>Disco acima do limite:</b>")
        for d in disk_warnings[:10]:
            lines.append(f"  • <code>{_h(d['hostname'])}</code> {_h(d['mountpoint'])}: {d['disk_percent']:.0f}%")

    if open_alerts:
        lines.append("")
        lines.append(f"<b>Alertas abertos:</b> {open_alerts}")

    if not offline_agents and not dns_failures and not disk_warnings:
        lines.append("")
        lines.append("Tudo operacional. 🟢")

    return await send_message("\n".join(lines))