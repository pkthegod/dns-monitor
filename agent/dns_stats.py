"""
dns_stats.py — coleta periodica de RCODEs/tipos/QPS/cache do resolver DNS.

Bind9: `rndc stats` → parse /var/cache/bind/named.stats
Unbound: `unbound-control stats_noreset` → parse key=value

Counters sao cumulativos. Modulo guarda snapshot anterior em
/var/lib/dns-agent/last_dns_stats.json e calcula delta. Resolver restart
(counters voltam a zero) e detectado e tratado como "delta = current".

Publica via HTTP POST /api/v1/agents/{hostname}/dns-stats (Bearer token).
NATS publish e v1.1 (otimizacao opcional).

Schedule: configuravel via agent.toml [dns_stats] interval (default 600s).
"""

import json
import logging
import pathlib
import subprocess
import time
from datetime import datetime, timezone
from typing import Optional

import requests

_SNAPSHOT_FILE = pathlib.Path("/var/lib/dns-agent/last_dns_stats.json")


# ---------------------------------------------------------------------------
# Coleta — Unbound
# ---------------------------------------------------------------------------

def _collect_unbound_stats() -> Optional[dict]:
    """unbound-control stats_noreset → dict de counters cumulativos."""
    out = None
    for cmd in (["unbound-control", "stats_noreset"],
                ["sudo", "-n", "unbound-control", "stats_noreset"]):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode == 0 and result.stdout:
                out = result.stdout
                break
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
    if not out:
        return None

    kv: dict = {}
    for line in out.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        try:
            kv[k.strip()] = int(v.strip())
        except ValueError:
            pass

    # Tipos "outros" = soma de todos num.queries.type.* exceto A/AAAA/MX/PTR
    main_types = {"A", "AAAA", "MX", "PTR"}
    queries_other = sum(
        v for k, v in kv.items()
        if k.startswith("num.queries.type.")
        and k.split(".")[-1] not in main_types
    )

    return {
        "source": "unbound",
        "noerror":  kv.get("num.answer.rcode.NOERROR", 0),
        "nxdomain": kv.get("num.answer.rcode.NXDOMAIN", 0),
        "servfail": kv.get("num.answer.rcode.SERVFAIL", 0),
        "refused":  kv.get("num.answer.rcode.REFUSED", 0),
        "notimpl":  kv.get("num.answer.rcode.NOTIMPL", 0),
        "formerr":  kv.get("num.answer.rcode.FORMERR", 0),
        "queries_a":     kv.get("num.queries.type.A", 0),
        "queries_aaaa":  kv.get("num.queries.type.AAAA", 0),
        "queries_mx":    kv.get("num.queries.type.MX", 0),
        "queries_ptr":   kv.get("num.queries.type.PTR", 0),
        "queries_other": queries_other,
        "queries_total": kv.get("total.num.queries", 0),
        "cache_hits":    kv.get("total.num.cachehits", 0),
        "cache_misses":  kv.get("total.num.cachemiss", 0),
    }


# ---------------------------------------------------------------------------
# Coleta — Bind9
# ---------------------------------------------------------------------------

def _collect_bind9_stats() -> Optional[dict]:
    """rndc stats → dump em /var/cache/bind/named.stats. Parse o ultimo dump."""
    stats_file = pathlib.Path("/var/cache/bind/named.stats")
    triggered = False
    for cmd in (["rndc", "stats"], ["sudo", "-n", "rndc", "stats"]):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                triggered = True
                break
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
    if not triggered:
        return None

    # rndc stats e assincrono — aguarda flush
    time.sleep(0.5)
    if not stats_file.exists():
        return None

    try:
        text = stats_file.read_text(encoding="utf-8", errors="ignore")
    except PermissionError:
        # Fallback sudo cat
        try:
            text = subprocess.check_output(["sudo", "-n", "cat", str(stats_file)],
                                            text=True, timeout=5)
        except Exception:
            return None

    return _parse_bind_stats_text(text)


def _parse_bind_stats_text(text: str) -> dict:
    """Extrai counters do texto do named.stats (Bind9 9.18+).

    O arquivo acumula multiplos dumps separados por '+++ Statistics Dump +++'.
    Pegamos sempre o mais recente (ultimo no arquivo).
    """
    import re as _re

    # Pega o ULTIMO dump
    parts = text.split("+++ Statistics Dump +++")
    last = parts[-1] if len(parts) > 1 else text

    def _grep_int(pattern: str) -> int:
        m = _re.search(rf'^\s*(\d+)\s+{pattern}\s*$', last, _re.MULTILINE)
        return int(m.group(1)) if m else 0

    # Bind9 reporta RCODEs como "Result codes" section. Tambem suporta
    # variantes em ingles antigas.
    rcode_patterns = {
        "noerror":  r"queries resulted in successful answer|NOERROR",
        "nxdomain": r"queries resulted in NXDOMAIN|NXDOMAIN",
        "servfail": r"queries resulted in SERVFAIL|SERVFAIL",
        "refused":  r"queries resulted in REFUSED|REFUSED",
        "notimpl":  r"queries resulted in NOTIMP|NOTIMPL",
        "formerr":  r"queries resulted in FORMERR|FORMERR",
    }

    result: dict = {"source": "bind9"}
    for k, pat in rcode_patterns.items():
        result[k] = _grep_int(pat)

    # Tipos
    result["queries_a"]    = _grep_int(r"^A$")
    result["queries_aaaa"] = _grep_int(r"^AAAA$")
    result["queries_mx"]   = _grep_int(r"^MX$")
    result["queries_ptr"]  = _grep_int(r"^PTR$")
    # Outros tipos: nao tentamos enumerar; usuario interessado roda `rndc stats` direto
    result["queries_other"] = 0
    result["queries_total"] = _grep_int(r"queries received|IPv4 queries received|IPv6 queries received")

    return result


# ---------------------------------------------------------------------------
# Delta + persistencia de snapshot
# ---------------------------------------------------------------------------

def _compute_delta(current: dict, previous: dict) -> dict:
    """Subtrai snapshots. Counter negativo (resolver reiniciado) → assume current."""
    delta: dict = {}
    for k, v in current.items():
        if k == "source":
            delta[k] = v
            continue
        if not isinstance(v, (int, float)):
            continue
        prev = previous.get(k, 0)
        d = v - prev
        if d < 0:
            d = v
        delta[k] = d
    return delta


def _persist_snapshot(snapshot: dict) -> None:
    try:
        _SNAPSHOT_FILE.parent.mkdir(parents=True, exist_ok=True)
        _SNAPSHOT_FILE.write_text(json.dumps(snapshot))
    except Exception:
        pass  # primeira coleta proxima vira "baseline"


def _load_snapshot() -> dict:
    if not _SNAPSHOT_FILE.exists():
        return {}
    try:
        return json.loads(_SNAPSHOT_FILE.read_text())
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Entry point pro scheduler
# ---------------------------------------------------------------------------

def collect_and_publish(cfg, logger: logging.Logger) -> None:
    """Coleta stats DNS, calcula delta, publica no backend via HTTP POST."""
    # Lazy import pra evitar circular
    try:
        from dns_agent import detect_dns_service
    except ImportError:
        logger.debug("dns_stats: detect_dns_service nao disponivel")
        return

    detected = detect_dns_service()
    svc_name = (detected.get("name") or "").lower()

    if svc_name == "unbound":
        current = _collect_unbound_stats()
    elif svc_name in ("named", "bind9"):
        current = _collect_bind9_stats()
    else:
        logger.debug("dns_stats: nenhum servico DNS detectado, skip")
        return

    if not current:
        logger.warning("dns_stats: coleta retornou vazio (servico=%s)", svc_name)
        return

    previous = _load_snapshot()
    prev_ts = previous.pop("__ts__", None)
    now = datetime.now(timezone.utc)

    # Primeira execucao: salva baseline e sai
    if not previous or not prev_ts:
        _persist_snapshot({**current, "__ts__": now.isoformat()})
        logger.info("dns_stats: baseline salvo (%s, %d counters)",
                    svc_name, len(current))
        return

    try:
        prev_dt = datetime.fromisoformat(prev_ts)
    except ValueError:
        prev_dt = now
    period_seconds = max(1, int((now - prev_dt).total_seconds()))

    delta = _compute_delta(current, previous)
    delta["ts"] = now.isoformat()
    delta["period_seconds"] = period_seconds

    # queries_total derivado se ausente
    if not delta.get("queries_total"):
        delta["queries_total"] = sum(
            delta.get(k, 0) for k in
            ("noerror", "nxdomain", "servfail", "refused", "notimpl", "formerr")
        )

    delta["qps_avg"] = round(delta["queries_total"] / period_seconds, 2)

    # Cache hit pct (Unbound)
    if delta.get("cache_hits") is not None and delta.get("cache_misses") is not None:
        total_cache = delta["cache_hits"] + delta["cache_misses"]
        delta["cache_hit_pct"] = (
            round(100 * delta["cache_hits"] / total_cache, 2)
            if total_cache > 0 else None
        )

    # Publish via HTTP — endpoint POST /api/v1/agents/{hostname}/dns-stats
    try:
        backend_url = cfg.get("backend", "url").rstrip("/")
        token = cfg.get("agent", "auth_token")
        hostname = cfg.get("agent", "hostname", fallback="unknown")
        timeout = cfg.getint("backend", "timeout_seconds", fallback=15)

        resp = requests.post(
            f"{backend_url}/api/v1/agents/{hostname}/dns-stats",
            json=delta,
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        )
        if resp.status_code in (200, 201, 202):
            logger.info(
                "dns_stats publicado: %d queries em %ds (qps=%.2f, NXD=%d, SVF=%d)",
                delta["queries_total"], period_seconds, delta["qps_avg"],
                delta.get("nxdomain", 0), delta.get("servfail", 0),
            )
        else:
            logger.warning("dns_stats POST falhou: HTTP %d %s",
                           resp.status_code, resp.text[:200])
    except Exception as exc:
        logger.warning("dns_stats POST erro: %s", exc)

    # Persiste snapshot atual pra proxima execucao
    _persist_snapshot({**current, "__ts__": now.isoformat()})
