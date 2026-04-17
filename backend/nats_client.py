"""
nats_client.py — Cliente NATS para o backend DNS Monitor.
Gerencia conexao, publish, subscribe e JetStream.
Fallback gracioso: se NATS indisponivel, operacoes sao no-op.
"""

import asyncio
import json
import logging
import os
from typing import Callable, Optional

import nats
from nats.js.api import StreamConfig, RetentionPolicy

logger = logging.getLogger("dns-monitor.nats")

_nc: Optional[nats.NATS] = None
_js = None  # JetStream context

NATS_URL = os.environ.get("NATS_URL", "nats://localhost:4222")

# Streams JetStream (criados no connect)
STREAMS = {
    "COMMANDS": StreamConfig(
        name="COMMANDS",
        subjects=["dns.commands.*", "dns.commands.*.ack"],
        retention=RetentionPolicy.WORK_QUEUE,
        max_age=7 * 24 * 3600 * 10**9,  # 7 dias em nanosegundos
    ),
}


async def connect() -> bool:
    """Conecta ao NATS e inicializa JetStream. Retorna True se sucesso."""
    global _nc, _js
    try:
        _nc = await nats.connect(
            NATS_URL,
            name="dns-monitor-backend",
            reconnect_time_wait=2,
            max_reconnect_attempts=-1,  # reconecta indefinidamente
        )
        _js = _nc.jetstream()

        # Cria streams se nao existem
        for name, cfg in STREAMS.items():
            try:
                await _js.find_stream_name_by_subject(cfg.subjects[0])
                logger.debug("Stream %s ja existe", name)
            except Exception:
                await _js.add_stream(cfg)
                logger.info("Stream %s criado", name)

        logger.info("NATS conectado: %s", NATS_URL)
        return True
    except Exception as exc:
        logger.warning("NATS indisponivel (%s) — operando sem mensageria", exc)
        _nc = None
        _js = None
        return False


async def close() -> None:
    """Fecha conexao NATS."""
    global _nc, _js
    if _nc and _nc.is_connected:
        await _nc.close()
        logger.info("NATS desconectado")
    _nc = None
    _js = None


def is_connected() -> bool:
    """Retorna True se NATS esta conectado."""
    return _nc is not None and _nc.is_connected


async def publish(subject: str, data: dict) -> bool:
    """Publica mensagem JSON no NATS. Retorna False se nao conectado."""
    if not is_connected():
        return False
    try:
        payload = json.dumps(data, default=str).encode()
        await _nc.publish(subject, payload)
        logger.debug("NATS publish: %s (%d bytes)", subject, len(payload))
        return True
    except Exception as exc:
        logger.warning("NATS publish falhou em %s: %s", subject, exc)
        return False


async def js_publish(subject: str, data: dict) -> bool:
    """Publica via JetStream (persistido). Retorna False se nao conectado."""
    if not _js:
        return False
    try:
        payload = json.dumps(data, default=str).encode()
        ack = await _js.publish(subject, payload)
        logger.debug("NATS JS publish: %s (seq=%s)", subject, ack.seq)
        return True
    except Exception as exc:
        logger.warning("NATS JS publish falhou em %s: %s", subject, exc)
        return False


async def subscribe(subject: str, callback: Callable, queue: str = None):
    """Subscribe simples (pub/sub). Retorna subscription ou None."""
    if not is_connected():
        return None
    try:
        if queue:
            sub = await _nc.subscribe(subject, queue=queue, cb=callback)
        else:
            sub = await _nc.subscribe(subject, cb=callback)
        logger.info("NATS subscribe: %s", subject)
        return sub
    except Exception as exc:
        logger.warning("NATS subscribe falhou em %s: %s", subject, exc)
        return None


async def js_subscribe(subject: str, callback: Callable, durable: str = None):
    """Subscribe JetStream (com entrega garantida). Retorna subscription ou None."""
    if not _js:
        return None
    try:
        if durable:
            sub = await _js.subscribe(subject, durable=durable, cb=callback)
        else:
            sub = await _js.subscribe(subject, cb=callback)
        logger.info("NATS JS subscribe: %s (durable=%s)", subject, durable)
        return sub
    except Exception as exc:
        logger.warning("NATS JS subscribe falhou em %s: %s", subject, exc)
        return None
