#!/usr/bin/env python3
"""
dns_agent.py — Agente de monitoramento DNS + sistema
Coleta métricas do host e testa resolução DNS, enviando para o backend central.

Compatível com: Unbound, Bind9 (auto-detectado via systemctl)
Requer: Python 3.8+
Dependências: pip install psutil dnspython requests schedule
"""

import configparser
import json
import logging
import logging.handlers
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import dns.resolver
import psutil
import requests
import schedule

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

CONFIG_PATHS = [
    Path(__file__).parent / "agent.conf",
    Path("/etc/dns-agent/agent.conf"),
]


def load_config() -> configparser.ConfigParser:
    """
    Carrega agent.conf com interpolação de variáveis de ambiente.

    O arquivo suporta a sintaxe %(AGENT_HOSTNAME)s, %(AGENT_TOKEN)s e
    %(AGENT_BACKEND)s — expandidas automaticamente a partir do ambiente.
    Isso evita duplicar valores entre /etc/dns-agent/env e agent.conf.
    """
    defaults = {
        "AGENT_HOSTNAME": os.environ.get("AGENT_HOSTNAME", ""),
        "AGENT_TOKEN":    os.environ.get("AGENT_TOKEN",    ""),
        "AGENT_BACKEND":  os.environ.get("AGENT_BACKEND",  ""),
    }
    cfg = configparser.ConfigParser(defaults=defaults)
    for path in CONFIG_PATHS:
        if path.exists():
            cfg.read(path)
            return cfg
    print("ERRO: agent.conf não encontrado. Copie agent.conf.example e configure.", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(cfg: configparser.ConfigParser) -> logging.Logger:
    level_name = cfg.get("logging", "level", fallback="INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    logger = logging.getLogger("dns-agent")
    logger.setLevel(level)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    )

    # Handler para stdout/journald
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(fmt)
    logger.addHandler(stdout_handler)

    # Handler para arquivo (opcional)
    log_file = cfg.get("logging", "file", fallback="").strip()
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        max_bytes = cfg.getint("logging", "max_size_mb", fallback=10) * 1024 * 1024
        backup_count = cfg.getint("logging", "backup_count", fallback=5)
        file_handler = logging.handlers.RotatingFileHandler(
            log_path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
        )
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)

    return logger


# ---------------------------------------------------------------------------
# Detecção do serviço DNS
# ---------------------------------------------------------------------------

DNS_SERVICES = ["unbound", "bind9", "named"]


def detect_dns_service() -> dict:
    """
    Detecta qual serviço DNS está instalado e qual seu status atual.
    Retorna: { "name": "unbound", "active": True, "version": "1.17.0" }
    """
    result = {"name": "unknown", "active": False, "version": None}

    for service in DNS_SERVICES:
        try:
            status = subprocess.run(
                ["systemctl", "is-active", service],
                capture_output=True, text=True, timeout=5
            )
            if status.returncode == 0 and status.stdout.strip() == "active":
                result["name"] = service
                result["active"] = True
                result["version"] = _get_dns_version(service)
                return result

            # Serviço existe mas pode estar inativo
            enabled = subprocess.run(
                ["systemctl", "is-enabled", service],
                capture_output=True, text=True, timeout=5
            )
            if enabled.returncode == 0:
                result["name"] = service
                result["active"] = False
                result["version"] = _get_dns_version(service)
                return result

        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

    return result


def _get_dns_version(service: str) -> Optional[str]:
    """Obtém a versão do serviço DNS instalado."""
    version_cmds = {
        "unbound": ["unbound", "-V"],
        "bind9":   ["named", "-v"],
        "named":   ["named", "-v"],
    }
    cmd = version_cmds.get(service)
    if not cmd:
        return None
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        first_line = (out.stdout or out.stderr).splitlines()[0]
        return first_line.strip()[:100]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Testes DNS
# ---------------------------------------------------------------------------

def test_dns_resolution(cfg: configparser.ConfigParser, logger: logging.Logger) -> list:
    """
    Testa resolução DNS para cada domínio configurado.
    Retorna lista de resultados por domínio.
    """
    domains_raw = cfg.get("dns", "test_domains", fallback="google.com")
    domains = [d.strip() for d in domains_raw.split(",") if d.strip()]
    resolver_ip = cfg.get("dns", "local_resolver", fallback="").strip() or None
    dns_port = cfg.getint("dns", "dns_port", fallback=53)
    timeout = cfg.getfloat("dns", "query_timeout", fallback=5.0)
    retries = cfg.getint("dns", "query_retries", fallback=3)

    results = []

    for domain in domains:
        result = _resolve_domain(domain, resolver_ip, dns_port, timeout, retries, logger)
        results.append(result)
        logger.debug(
            "DNS %s → %s latência=%sms",
            domain,
            "OK" if result["success"] else "FALHA",
            result.get("latency_ms")
        )

    return results


def _resolve_domain(
    domain: str,
    resolver_ip: Optional[str],
    port: int,
    timeout: float,
    retries: int,
    logger: logging.Logger
) -> dict:
    """Resolve um domínio e mede a latência. Tenta `retries` vezes."""
    base = {
        "domain": domain,
        "resolver": resolver_ip or "system",
        "success": False,
        "latency_ms": None,
        "response_ips": [],
        "error": None,
        "attempts": 0,
    }

    resolver = dns.resolver.Resolver()
    if resolver_ip:
        resolver.nameservers = [resolver_ip]
        resolver.port = port
    resolver.lifetime = timeout

    for attempt in range(1, retries + 1):
        base["attempts"] = attempt
        try:
            start = time.perf_counter()
            answer = resolver.resolve(domain, "A")
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

            base["success"] = True
            base["latency_ms"] = elapsed_ms
            base["response_ips"] = [str(r) for r in answer]
            base["error"] = None
            return base

        except dns.resolver.NXDOMAIN:
            base["error"] = "NXDOMAIN"
            return base  # Sem retry — domínio não existe
        except dns.resolver.NoNameservers:
            base["error"] = "NO_NAMESERVERS"
        except dns.resolver.Timeout:
            base["error"] = "TIMEOUT"
        except dns.exception.DNSException as exc:
            base["error"] = str(exc)[:120]

        if attempt < retries:
            time.sleep(1)

    logger.warning("DNS falhou para %s após %d tentativas: %s", domain, retries, base["error"])
    return base


# ---------------------------------------------------------------------------
# Métricas do sistema
# ---------------------------------------------------------------------------

def collect_system_metrics(cfg: configparser.ConfigParser) -> dict:
    """
    Coleta CPU, RAM, disco e I/O do sistema.
    Retorna dicionário com todas as métricas.
    """
    return {
        "cpu":  _collect_cpu(),
        "ram":  _collect_ram(),
        "disk": _collect_disk(cfg),
        "io":   _collect_io(),
        "load": _collect_load(),
    }


def _collect_cpu() -> dict:
    # interval=1 evita leituras 0% imediatas
    cpu_percent = psutil.cpu_percent(interval=1)
    cpu_count = psutil.cpu_count(logical=True)
    cpu_freq = psutil.cpu_freq()
    return {
        "percent":     round(cpu_percent, 1),
        "count":       cpu_count,
        "freq_mhz":    round(cpu_freq.current, 1) if cpu_freq else None,
    }


def _collect_ram() -> dict:
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {
        "total_mb":    round(mem.total / 1024 / 1024, 1),
        "used_mb":     round(mem.used  / 1024 / 1024, 1),
        "percent":     round(mem.percent, 1),
        "swap_total_mb": round(swap.total / 1024 / 1024, 1),
        "swap_used_mb":  round(swap.used  / 1024 / 1024, 1),
        "swap_percent":  round(swap.percent, 1),
    }


def _collect_disk(cfg: configparser.ConfigParser) -> list:
    """Coleta uso de cada partição montada (exclui tmpfs, devtmpfs)."""
    disk_warning = cfg.getint("thresholds", "disk_warning", fallback=80)
    disk_critical = cfg.getint("thresholds", "disk_critical", fallback=90)
    partitions = []

    for part in psutil.disk_partitions(all=False):
        # Ignora sistemas de arquivo virtuais
        if part.fstype in ("tmpfs", "devtmpfs", "squashfs", "overlay"):
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except PermissionError:
            continue

        pct = round(usage.percent, 1)
        alert = "ok"
        if pct >= disk_critical:
            alert = "critical"
        elif pct >= disk_warning:
            alert = "warning"

        partitions.append({
            "mountpoint": part.mountpoint,
            "device":     part.device,
            "fstype":     part.fstype,
            "total_gb":   round(usage.total  / 1024**3, 2),
            "used_gb":    round(usage.used   / 1024**3, 2),
            "free_gb":    round(usage.free   / 1024**3, 2),
            "percent":    pct,
            "alert":      alert,
        })

    return partitions


def _collect_io() -> dict:
    """Coleta contadores de I/O do disco desde o boot."""
    try:
        io = psutil.disk_io_counters(perdisk=False)
        if io is None:
            return {}
        return {
            "read_bytes":   io.read_bytes,
            "write_bytes":  io.write_bytes,
            "read_count":   io.read_count,
            "write_count":  io.write_count,
            "read_time_ms": io.read_time,
            "write_time_ms":io.write_time,
        }
    except Exception:
        return {}


def _collect_load() -> dict:
    """Load average do sistema (1, 5, 15 minutos)."""
    try:
        la = os.getloadavg()
        return {
            "load_1m":  round(la[0], 2),
            "load_5m":  round(la[1], 2),
            "load_15m": round(la[2], 2),
        }
    except OSError:
        # Windows não suporta getloadavg
        return {}


# ---------------------------------------------------------------------------
# Construção do payload
# ---------------------------------------------------------------------------

def build_payload(
    cfg: configparser.ConfigParser,
    dns_service: dict,
    dns_results: list,
    system_metrics: dict,
    payload_type: str = "check"
) -> dict:
    """
    Monta o JSON que será enviado ao backend.
    payload_type: "check" (ciclo completo) | "heartbeat" (sinal de vida)
    """
    return {
        "type":      payload_type,
        "hostname":  cfg.get("agent", "hostname", fallback=socket.gethostname()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_version": "1.0.0",
        "os": {
            "system":  platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "dns_service": dns_service,
        "dns_checks":  dns_results,
        "system":      system_metrics,
    }


# ---------------------------------------------------------------------------
# Envio ao backend
# ---------------------------------------------------------------------------

def send_payload(cfg: configparser.ConfigParser, payload: dict, logger: logging.Logger) -> bool:
    """
    Envia o payload ao backend com retry automático.
    Retorna True se enviado com sucesso.
    """
    url     = cfg.get("backend", "url").rstrip("/") + "/metrics"
    token   = cfg.get("agent", "auth_token")
    timeout = cfg.getint("backend", "timeout", fallback=10)
    retries = cfg.getint("backend", "retries", fallback=3)
    delay   = cfg.getint("backend", "retry_delay", fallback=5)

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
        "User-Agent":    "dns-agent/1.0",
    }

    for attempt in range(1, retries + 1):
        try:
            resp = requests.post(
                url,
                data=json.dumps(payload, default=str),
                headers=headers,
                timeout=timeout
            )
            if resp.status_code == 200:
                logger.info("Payload enviado com sucesso (tipo=%s)", payload["type"])
                return True
            logger.warning(
                "Backend retornou HTTP %d (tentativa %d/%d): %s",
                resp.status_code, attempt, retries, resp.text[:200]
            )
        except requests.exceptions.ConnectionError:
            logger.warning("Sem conexão com backend (tentativa %d/%d)", attempt, retries)
        except requests.exceptions.Timeout:
            logger.warning("Timeout ao enviar para backend (tentativa %d/%d)", attempt, retries)
        except requests.exceptions.RequestException as exc:
            logger.error("Erro inesperado no envio: %s", exc)

        if attempt < retries:
            time.sleep(delay)

    logger.error("Falha ao enviar payload após %d tentativas.", retries)
    return False


# ---------------------------------------------------------------------------
# Jobs agendados
# ---------------------------------------------------------------------------

def run_full_check(cfg: configparser.ConfigParser, logger: logging.Logger) -> None:
    """Ciclo completo: DNS + sistema + envio."""
    logger.info("Iniciando ciclo completo de verificação...")
    start = time.perf_counter()

    dns_service    = detect_dns_service()
    dns_results    = test_dns_resolution(cfg, logger)
    system_metrics = collect_system_metrics(cfg)

    # Avalia alertas locais para log mais visível
    _log_alert_summary(cfg, dns_service, dns_results, system_metrics, logger)

    payload = build_payload(cfg, dns_service, dns_results, system_metrics, "check")
    send_payload(cfg, payload, logger)

    elapsed = round((time.perf_counter() - start), 2)
    logger.info("Ciclo completo concluído em %.2fs", elapsed)


def run_heartbeat(cfg: configparser.ConfigParser, logger: logging.Logger) -> None:
    """Heartbeat leve: apenas sinal de vida + métricas rápidas."""
    logger.debug("Enviando heartbeat...")
    dns_service    = detect_dns_service()
    system_metrics = collect_system_metrics(cfg)
    payload = build_payload(cfg, dns_service, [], system_metrics, "heartbeat")
    send_payload(cfg, payload, logger)


def _log_alert_summary(cfg, dns_service, dns_results, system_metrics, logger):
    """Loga no nível WARNING se alguma métrica ultrapassar os limites configurados."""
    # DNS service down
    if not dns_service.get("active"):
        logger.warning("ALERTA: Serviço DNS '%s' está INATIVO", dns_service.get("name"))

    # Falhas DNS
    failed = [r["domain"] for r in dns_results if not r["success"]]
    if failed:
        logger.warning("ALERTA: Falha de resolução DNS para: %s", ", ".join(failed))

    # Latência DNS alta
    lat_warn  = cfg.getint("thresholds", "dns_latency_warning",  fallback=200)
    lat_crit  = cfg.getint("thresholds", "dns_latency_critical", fallback=1000)
    for r in dns_results:
        if r["latency_ms"] and r["latency_ms"] >= lat_crit:
            logger.warning("ALERTA CRÍTICO: DNS %s latência=%sms (limite crítico=%sms)", r["domain"], r["latency_ms"], lat_crit)
        elif r["latency_ms"] and r["latency_ms"] >= lat_warn:
            logger.warning("ALERTA: DNS %s latência=%sms (limite=%sms)", r["domain"], r["latency_ms"], lat_warn)

    # CPU
    cpu_warn = cfg.getint("thresholds", "cpu_warning",  fallback=80)
    cpu_crit = cfg.getint("thresholds", "cpu_critical", fallback=95)
    cpu_pct  = system_metrics["cpu"]["percent"]
    if cpu_pct >= cpu_crit:
        logger.warning("ALERTA CRÍTICO: CPU em %.1f%% (limite=%d%%)", cpu_pct, cpu_crit)
    elif cpu_pct >= cpu_warn:
        logger.warning("ALERTA: CPU em %.1f%% (limite=%d%%)", cpu_pct, cpu_warn)

    # RAM
    ram_warn = cfg.getint("thresholds", "ram_warning",  fallback=85)
    ram_crit = cfg.getint("thresholds", "ram_critical", fallback=95)
    ram_pct  = system_metrics["ram"]["percent"]
    if ram_pct >= ram_crit:
        logger.warning("ALERTA CRÍTICO: RAM em %.1f%% (limite=%d%%)", ram_pct, ram_crit)
    elif ram_pct >= ram_warn:
        logger.warning("ALERTA: RAM em %.1f%% (limite=%d%%)", ram_pct, ram_warn)

    # Disco por partição
    for part in system_metrics["disk"]:
        if part["alert"] == "critical":
            logger.warning("ALERTA CRÍTICO: Disco %s em %.1f%% (limite=%d%%)", part["mountpoint"], part["percent"], cfg.getint("thresholds", "disk_critical", fallback=90))
        elif part["alert"] == "warning":
            logger.warning("ALERTA: Disco %s em %.1f%% (limite=%d%%)", part["mountpoint"], part["percent"], cfg.getint("thresholds", "disk_warning", fallback=80))


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

def setup_schedule(cfg: configparser.ConfigParser, logger: logging.Logger) -> None:
    """Configura os jobs agendados com base no agent.conf."""
    # Testes completos nos horários configurados
    times_raw = cfg.get("schedule", "check_times", fallback="00:00,06:00,12:00,18:00")
    check_times = [t.strip() for t in times_raw.split(",") if t.strip()]

    for t in check_times:
        schedule.every().day.at(t).do(run_full_check, cfg=cfg, logger=logger)
        logger.info("Agendado ciclo completo às %s", t)

    # Heartbeat periódico
    heartbeat_interval = cfg.getint("schedule", "heartbeat_interval", fallback=300)
    schedule.every(heartbeat_interval).seconds.do(run_heartbeat, cfg=cfg, logger=logger)
    logger.info("Heartbeat agendado a cada %ds", heartbeat_interval)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    cfg    = load_config()
    logger = setup_logging(cfg)

    hostname = cfg.get("agent", "hostname", fallback=socket.gethostname())
    logger.info("DNS Agent iniciando — host=%s", hostname)

    # Verifica dependências de sistema
    if not shutil.which("systemctl"):
        logger.warning("systemctl não encontrado — detecção de serviço DNS limitada")

    # Roda um ciclo completo imediatamente na inicialização
    run_full_check(cfg, logger)

    # Configura agenda
    setup_schedule(cfg, logger)

    logger.info("Scheduler ativo. Aguardando próximos ciclos...")
    while True:
        schedule.run_pending()
        time.sleep(10)


if __name__ == "__main__":
    main()