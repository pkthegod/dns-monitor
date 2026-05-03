"""
nats_handlers.py — Handlers e subscriptions NATS do backend.

Hoje cobre apenas a confirmacao de execucao de comandos remotos
(dns.commands.*.ack). Quando novos topicos surgirem, adicionar aqui
e registrar em setup_nats_subscriptions().
"""

import json
import logging

import db
import telegram_bot as tg
from models import CommandAckPayload, DnsStatsPayload
from pydantic import ValidationError

try:
    import nats_client as nc
except ImportError:
    nc = None  # nats-py nao instalado — NATS desabilitado

logger = logging.getLogger("infra-vision.api")


# SEC (Onda 2 SEC-2.1): tamanho maximo de mensagem antes do parse JSON.
# Anti-DoS: NATS aceita ate 1MB por default no servidor; nosso payload de
# stats fica em ~500B, ack em ~200B. 8KB cobre folga ampla pra crescimento
# (mais campos opcionais futuros) e ainda corta atacante mandando blob de MB.
_NATS_MAX_PAYLOAD_BYTES = 8 * 1024


async def _parse_validated(msg, model_cls):
    """Parse + validacao Pydantic do payload. Retorna instancia ou None.

    Em caso de falha (size, JSON invalido, schema violation): loga warning,
    da msg.ack() pra nao ficar redeliverying, e retorna None.

    SEC: limita size ANTES de parsear pra evitar DoS por blob enorme. Nao
    encolhe ataque-superficie em si (NATS protege isso na borda) mas faz
    parte da defesa em profundidade.
    """
    raw = msg.data or b""
    if len(raw) > _NATS_MAX_PAYLOAD_BYTES:
        logger.warning(
            "NATS %s: payload %d bytes > limite %d — descartado",
            msg.subject, len(raw), _NATS_MAX_PAYLOAD_BYTES,
        )
        await msg.ack()
        return None
    try:
        data = json.loads(raw.decode())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.warning("NATS %s: JSON invalido (%s) — descartado", msg.subject, exc)
        await msg.ack()
        return None
    try:
        return model_cls.model_validate(data)
    except ValidationError as exc:
        logger.warning(
            "NATS %s: payload nao valida contra %s — %s",
            msg.subject, model_cls.__name__, str(exc)[:300],
        )
        await msg.ack()
        return None


async def handle_command_ack(msg):
    """Recebe resultado de comando via NATS (dns.commands.{hostname}.ack)."""
    payload = await _parse_validated(msg, CommandAckPayload)
    if payload is None:
        return
    try:
        await db.mark_command_done(payload.command_id, payload.status, payload.result)
        # Dedupe Telegram — ver routes_agent.post_command_result pra contexto.
        if await db.mark_command_notified(payload.command_id):
            cmd = await db.get_command_by_id(payload.command_id)
            if cmd:
                await tg.send_command_result(
                    hostname=cmd["hostname"], command=cmd["command"],
                    status=payload.status, result=payload.result,
                    issued_by=cmd["issued_by"] or "admin",
                )
            logger.info("NATS ACK: comando #%s -> %s (telegram enviado)",
                        payload.command_id, payload.status)
        else:
            logger.debug("NATS ACK: comando #%s -> %s (telegram silenciado, ja notificado via outro caminho)",
                         payload.command_id, payload.status)
        await msg.ack()
    except Exception as exc:
        logger.error("NATS ACK handler erro: %s", exc)


async def handle_dns_stats(msg):
    """Recebe sample de stats DNS via NATS (dns.stats.<hostname>).

    Subject extrai hostname. Payload validado contra DnsStatsPayload.
    Mesmo handler logico que routes_agent.receive_dns_stats (HTTP path) —
    refeito aqui pra usar o modelo validado em vez de dict cru.
    """
    # Subject: "dns.stats.<hostname>" — extrai hostname
    parts = msg.subject.split(".", 2)
    hostname = parts[2] if len(parts) >= 3 else ""
    if not hostname:
        logger.warning("NATS dns.stats sem hostname (subject=%s)", msg.subject)
        await msg.ack()
        return

    payload = await _parse_validated(msg, DnsStatsPayload)
    if payload is None:
        return

    try:
        # db.insert_dns_query_stats ainda recebe dict — converte do model.
        # exclude_unset=False mantem defaults; insert_dns_query_stats ja faz
        # int(.get(...,0)) entao defaults zerados nao causam corrupcao.
        data = payload.model_dump()
        await db.insert_dns_query_stats(hostname, data)
        # Avalia alertas (lazy import — routes_agent ainda nao foi carregado quando
        # nats_handlers e importado). Helper unico pros 2 caminhos (HTTP + NATS).
        from routes_agent import _evaluate_dns_stats_alerts
        await _evaluate_dns_stats_alerts(hostname, data)
        logger.debug("NATS dns.stats: %s recebido (queries_total=%s)",
                     hostname, payload.queries_total)
        await msg.ack()
    except Exception as exc:
        logger.error("NATS dns.stats handler erro: %s", exc)


async def setup_nats_subscriptions():
    """Registra subscriptions NATS no backend."""
    if nc:
        await nc.js_subscribe("dns.commands.*.ack", handle_command_ack, durable="backend-cmd-ack")
        await nc.js_subscribe("dns.stats.*", handle_dns_stats, durable="backend-dns-stats")
