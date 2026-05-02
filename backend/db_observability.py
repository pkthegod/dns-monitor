"""
db_observability.py — Detector de N+1 query e tracking por request.

Bloco B (C1) da matriz de fundamentos. N+1 e o anti-pattern em que o
codigo busca N rows e depois faz uma query por row pra puxar dado
relacionado — geralmente loop de `for row in rows: await conn.fetch(...)`.
Em ambiente single-worker async, 100 agentes com 1 alerta cada vira 101
queries pro mesmo handler. Detector materializa em log/warning quando
um template SQL repete > threshold no mesmo request scope.

Uso
---
1. Middleware (NPlusOneDetectorMiddleware em middlewares.py) chama
   `start_request()` ao entrar, `end_request_and_report()` ao sair.
2. `db.get_conn()` injeta um `_TrackedConn` que chama `record_query(sql)`
   antes de delegar pra asyncpg.
3. Threshold configuravel via env N1_DETECTOR_THRESHOLD (default: 10).

Custo
-----
1 hash + 1 dict update por query. Em load realista (~10 queries/req)
fica abaixo de 50us/request. Pra desligar em prod onde o sinal nao
compensa, set N1_DETECTOR_ENABLED=false (default: true em dev/test,
true em prod tb pra cacar regressoes — ja vimos N+1 silencioso em
admin/agents).
"""

import os
import re
from collections import Counter
from contextvars import ContextVar
from typing import Optional


# ContextVar e per-task-aware no asyncio — cada request roda em uma task
# diferente, entao o tracker fica isolado por request automaticamente.
_query_tracker: ContextVar[Optional["QueryTracker"]] = ContextVar(
    "_query_tracker", default=None,
)


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


N1_DETECTOR_ENABLED = _bool_env("N1_DETECTOR_ENABLED", True)
N1_DETECTOR_THRESHOLD = max(2, int(os.environ.get("N1_DETECTOR_THRESHOLD", "10")))


# Regex pra normalizar template:
# - Whitespace / quebras de linha viram um espaco (queries multi-line podem
#   ser equivalentes mesmo com formatacao diferente — agrupamos)
# - Numeros literais (excluindo placeholders $1/$2/...) viram '?' pra
#   detectar loop com IDs diferentes (e.g. WHERE id = 5, id = 12, id = 89...)
_RE_WHITESPACE = re.compile(r"\s+")
_RE_NUM_LITERAL = re.compile(r"(?<!\$)(?<![\w.])\d+(?![\w.])")


def _normalize_template(sql: str) -> str:
    """Reduz uma query SQL a um template comparavel.

    O objetivo nao e ser perfeito — e detectar repeticao do MESMO padrao
    com placeholders/literais variando. Strings muito longas sao truncadas
    pra economizar memoria (e SQL > 200 chars geralmente e DDL/migration,
    nao loop hot path).
    """
    if not sql:
        return ""
    s = _RE_WHITESPACE.sub(" ", sql).strip()
    s = _RE_NUM_LITERAL.sub("?", s)
    if len(s) > 200:
        s = s[:200] + "..."
    return s


class QueryTracker:
    """Conta queries por template normalizado dentro de um request scope.

    Nao thread-safe — assume request-per-task no asyncio (que e o modelo
    do FastAPI). Cada request tem seu proprio tracker via ContextVar.
    """

    def __init__(self):
        self._counts: Counter[str] = Counter()
        self._total: int = 0

    def record(self, sql: str) -> None:
        if not sql:
            return
        template = _normalize_template(sql)
        self._counts[template] += 1
        self._total += 1

    @property
    def total(self) -> int:
        return self._total

    def report(self, threshold: int) -> list[tuple[str, int]]:
        """Templates que estouraram o threshold, ordenados por contagem desc."""
        offenders = [
            (template, count)
            for template, count in self._counts.items()
            if count >= threshold
        ]
        offenders.sort(key=lambda x: x[1], reverse=True)
        return offenders


def start_request() -> Optional[QueryTracker]:
    """Inicia tracking pro request atual. Retorna o tracker (ou None se desligado)."""
    if not N1_DETECTOR_ENABLED:
        return None
    tracker = QueryTracker()
    _query_tracker.set(tracker)
    return tracker


def end_request() -> Optional[QueryTracker]:
    """Recupera o tracker do request atual e limpa. Retorna None se nao havia."""
    tracker = _query_tracker.get()
    _query_tracker.set(None)
    return tracker


def record_query(sql: str) -> None:
    """Hook chamado pelo _TrackedConn antes de cada query.

    Silencioso quando fora de request scope (ex: scheduler_jobs, startup) —
    nao queremos detectar N+1 em jobs cron, eles sao naturalmente em batch.
    """
    tracker = _query_tracker.get()
    if tracker is not None:
        tracker.record(sql)
