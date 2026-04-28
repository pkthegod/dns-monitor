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

try:
    import nats_client as nc
except ImportError:
    nc = None  # nats-py nao instalado — NATS desabilitado

logger = logging.getLogger("infra-vision.api")


async def handle_command_ack(msg):
    """Recebe resultado de comando via NATS (dns.commands.{hostname}.ack)."""
    try:
        data = json.loads(msg.data.decode())
        cmd_id = data.get("command_id")
        cmd_status = data.get("status", "done")
        result = data.get("result", "")
        if cmd_id:
            await db.mark_command_done(cmd_id, cmd_status, result)
            # Dedupe Telegram — ver routes_agent.post_command_result pra contexto.
            if await db.mark_command_notified(cmd_id):
                cmd = await db.get_command_by_id(cmd_id)
                if cmd:
                    await tg.send_command_result(
                        hostname=cmd["hostname"], command=cmd["command"],
                        status=cmd_status, result=result,
                        issued_by=cmd["issued_by"] or "admin",
                    )
                logger.info("NATS ACK: comando #%s -> %s (telegram enviado)", cmd_id, cmd_status)
            else:
                logger.debug("NATS ACK: comando #%s -> %s (telegram silenciado, ja notificado via outro caminho)", cmd_id, cmd_status)
        await msg.ack()
    except Exception as exc:
        logger.error("NATS ACK handler erro: %s", exc)


async def handle_dns_stats(msg):
    """Recebe sample de stats DNS via NATS (dns.stats.<hostname>).

    Payload esperado: JSON com chaves period_seconds, source, RCODEs (delta),
    tipos de query, queries_total, qps_avg, cache_hits/misses (Unbound).
    Ver project_dns_stats_feature.md pra schema completo.
    """
    try:
        data = json.loads(msg.data.decode())
        # Subject: "dns.stats.<hostname>" — extrai hostname do subject
        parts = msg.subject.split(".", 2)
        hostname = parts[2] if len(parts) >= 3 else data.get("hostname", "")
        if not hostname:
            logger.warning("NATS dns.stats sem hostname (subject=%s)", msg.subject)
            await msg.ack()
            return
        await db.insert_dns_query_stats(hostname, data)
        # Avalia alertas (lazy import — routes_agent ainda nao foi carregado quando
        # nats_handlers e importado). Helper unico pros 2 caminhos (HTTP + NATS).
        from routes_agent import _evaluate_dns_stats_alerts
        await _evaluate_dns_stats_alerts(hostname, data)
        logger.debug("NATS dns.stats: %s recebido (queries_total=%s)",
                     hostname, data.get("queries_total"))
        await msg.ack()
    except Exception as exc:
        logger.error("NATS dns.stats handler erro: %s", exc)


async def setup_nats_subscriptions():
    """Registra subscriptions NATS no backend."""
    if nc:
        await nc.js_subscribe("dns.commands.*.ack", handle_command_ack, durable="backend-cmd-ack")
        await nc.js_subscribe("dns.stats.*", handle_dns_stats, durable="backend-dns-stats")
