#!/usr/bin/env python3
"""
dns_agent.py — Agente de monitoramento DNS + sistema
Coleta métricas do host e testa resolução DNS, enviando para o backend central.

Compatível com: Unbound, Bind9 (auto-detectado via systemctl)
Requer: Python 3.8+
Dependências: pip install psutil dnspython requests schedule
"""

import configparser
import hashlib
import json
import logging
import logging.handlers
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import tomllib                    # Python 3.11+
except ModuleNotFoundError:
    try:
        import tomli as tomllib       # pip install tomli  (Python 3.8-3.10)
    except ModuleNotFoundError:
        tomllib = None                # fallback: só .conf

import dns.resolver
import psutil
import requests
import schedule

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

CONFIG_PATHS = [
    Path(__file__).parent / "agent.toml",
    Path(__file__).parent / "agent.conf",
    Path("/etc/dns-agent/agent.toml"),
    Path("/etc/dns-agent/agent.conf"),
]


AGENT_VERSION = "1.3.0"


# ---------------------------------------------------------------------------
# Config — wrapper compatível com ConfigParser sobre dict TOML
# ---------------------------------------------------------------------------

_UNSET = object()


class Config:
    """
    Configuração baseada em TOML com interface idêntica a ConfigParser.
    Todos os callsites (cfg.get, cfg.getint, etc.) funcionam sem mudança.
    """

    def __init__(self, data: dict):
        self._data = data

    def get(self, section: str, key: str, fallback=_UNSET) -> str:
        try:
            val = self._data[section][key]
            return str(val) if val is not None else ""
        except KeyError:
            if fallback is not _UNSET:
                return fallback
            raise

    def getint(self, section: str, key: str, fallback=_UNSET) -> int:
        try:
            return int(self._data[section][key])
        except (KeyError, TypeError, ValueError):
            if fallback is not _UNSET:
                return fallback
            raise

    def getfloat(self, section: str, key: str, fallback=_UNSET) -> float:
        try:
            return float(self._data[section][key])
        except (KeyError, TypeError, ValueError):
            if fallback is not _UNSET:
                return fallback
            raise

    def getboolean(self, section: str, key: str, fallback=_UNSET) -> bool:
        try:
            val = self._data[section][key]
            if isinstance(val, bool):
                return val
            return str(val).lower() in ("true", "1", "yes")
        except KeyError:
            if fallback is not _UNSET:
                return fallback
            raise


# ---------------------------------------------------------------------------
# Fingerprint de hardware
# ---------------------------------------------------------------------------

def generate_fingerprint() -> str:
    """
    Gera SHA256 baseado em hostname + MAC address + /etc/machine-id.
    Identifica unicamente o hardware onde o agente está instalado.
    Se o fingerprint enviado ao backend divergir do registrado,
    o backend gera um alerta de possível cópia ou migração não autorizada.
    """
    parts = []

    # Hostname do sistema operacional
    parts.append(socket.gethostname())

    # MAC address da primeira interface não-loopback
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == psutil.AF_LINK and addr.address not in ("", "00:00:00:00:00:00"):
                    parts.append(addr.address)
                    break
            if len(parts) > 1:
                break
    except Exception:
        parts.append("no-mac")

    # /etc/machine-id (único por instalação Linux)
    try:
        machine_id = Path("/etc/machine-id").read_text().strip()
        parts.append(machine_id)
    except Exception:
        parts.append("no-machine-id")

    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()


def _expand_env(data: dict) -> dict:
    """Expande ${VAR} para o valor da variável de ambiente em strings do TOML."""
    _env_re = re.compile(r"\$\{(\w+)\}")
    out = {}
    for section, values in data.items():
        if isinstance(values, dict):
            out[section] = {}
            for key, val in values.items():
                if isinstance(val, str):
                    out[section][key] = _env_re.sub(
                        lambda m: os.environ.get(m.group(1), ""), val
                    )
                else:
                    out[section][key] = val
        else:
            out[section] = values
    return out


def load_config() -> Config:
    """
    Carrega configuração em TOML (preferencial) ou .conf (legado).

    - agent.toml: lido com tomllib, variáveis expandidas via ${VAR}
    - agent.conf: fallback via ConfigParser com interpolação %(VAR)s
    Ambos retornam um objeto Config com interface idêntica.
    """
    for path in CONFIG_PATHS:
        if not path.exists():
            continue

        # ── TOML ────────────────────────────────────────────────────
        if path.suffix == ".toml":
            if tomllib is None:
                continue          # sem parser TOML — pula pro .conf
            with open(path, "rb") as f:
                data = tomllib.load(f)
            return Config(_expand_env(data))

        # ── .conf (legado) ──────────────────────────────────────────
        defaults = {
            "AGENT_HOSTNAME": os.environ.get("AGENT_HOSTNAME", ""),
            "AGENT_TOKEN":    os.environ.get("AGENT_TOKEN",    ""),
            "AGENT_BACKEND":  os.environ.get("AGENT_BACKEND",  ""),
        }
        cfg_parser = configparser.ConfigParser(defaults=defaults)
        cfg_parser.read(path)
        # Converte para dict e retorna como Config
        data = {s: dict(cfg_parser.items(s)) for s in cfg_parser.sections()}
        return Config(data)

    print("ERRO: agent.toml/agent.conf não encontrado. Copie o exemplo e configure.", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(cfg: Config) -> logging.Logger:
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
    Retorna: { "name": "named", "active": True, "version": "BIND 9.18" }

    O nome retornado é o nome REAL do serviço (resolvido via SERVICE_ALIASES),
    não o alias. Ex: no Debian, bind9 → named para que o banco reflita
    o serviço que o systemctl realmente controla.
    """
    result = {"name": "unknown", "active": False, "version": None}

    for service in DNS_SERVICES:
        try:
            status = subprocess.run(
                ["systemctl", "is-active", service],
                capture_output=True, text=True, timeout=5
            )
            if status.returncode == 0 and status.stdout.strip() == "active":
                real_name = SERVICE_ALIASES.get(service, service)
                result["name"]    = real_name
                result["active"]  = True
                result["version"] = _get_dns_version(real_name)
                return result

            # Serviço existe mas pode estar inativo
            enabled = subprocess.run(
                ["systemctl", "is-enabled", service],
                capture_output=True, text=True, timeout=5
            )
            if enabled.returncode == 0:
                real_name = SERVICE_ALIASES.get(service, service)
                result["name"]    = real_name
                result["active"]  = False
                result["version"] = _get_dns_version(real_name)
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

def test_dns_resolution(cfg: Config, logger: logging.Logger) -> list:
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

def collect_system_metrics(cfg: Config) -> dict:
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


def _collect_disk(cfg: Config) -> list:
    """
    Coleta uso de cada partição física montada (exclui tmpfs, devtmpfs).

    Filtra duplicatas por device — quando um disco físico está montado em
    múltiplos pontos (bind mounts, subvolumes), mantém apenas o mountpoint
    mais representativo: preferencialmente '/', depois o mais curto.
    """
    disk_warning = cfg.getint("thresholds", "disk_warning", fallback=80)
    disk_critical = cfg.getint("thresholds", "disk_critical", fallback=90)

    # Sistemas de arquivo a ignorar — virtuais, sem dados reais de disco
    IGNORE_FS = {"tmpfs", "devtmpfs", "squashfs", "overlay", "sysfs",
                 "proc", "cgroup", "cgroup2", "pstore", "bpf", "tracefs"}

    seen_devices: dict = {}  # device → melhor mountpoint já visto

    for part in psutil.disk_partitions(all=False):
        if part.fstype in IGNORE_FS:
            continue
        if not part.device or part.device.startswith("none"):
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except PermissionError:
            continue

        # Escolhe o mountpoint mais representativo por device físico:
        # '/' tem prioridade, depois o caminho mais curto
        if part.device in seen_devices:
            prev = seen_devices[part.device]
            if part.mountpoint == "/":
                seen_devices[part.device] = part
            elif prev.mountpoint != "/" and len(part.mountpoint) < len(prev.mountpoint):
                seen_devices[part.device] = part
        else:
            seen_devices[part.device] = part

    partitions = []
    for part in seen_devices.values():
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
    cfg: Config,
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
        "agent_version": AGENT_VERSION,
        "fingerprint":   generate_fingerprint(),
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

def send_payload(cfg: Config, payload: dict, logger: logging.Logger) -> bool:
    """
    Envia o payload ao backend com retry automático.
    Retorna True se enviado com sucesso.
    """
    url     = cfg.get("backend", "url").rstrip("/") + "/api/v1/metrics"
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

def run_full_check(cfg: Config, logger: logging.Logger) -> None:
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


# ---------------------------------------------------------------------------
# Quick Probe — teste DNS leve de alta frequência
# ---------------------------------------------------------------------------

_latest_quick_probe: dict = None  # type: ignore[assignment]


def run_quick_probe(cfg: Config, logger: logging.Logger) -> None:
    """
    Executa um teste DNS leve em um único domínio com timeout curto e sem retries.
    Armazena o resultado em _latest_quick_probe para o próximo heartbeat.
    """
    global _latest_quick_probe

    domain = cfg.get("schedule", "quick_probe_domain", fallback="").strip()
    if not domain:
        domains_raw = cfg.get("dns", "test_domains", fallback="google.com")
        domain = domains_raw.split(",")[0].strip()

    resolver_ip = cfg.get("dns", "local_resolver", fallback="").strip() or None
    dns_port    = cfg.getint("dns", "dns_port", fallback=53)
    timeout     = cfg.getfloat("schedule", "quick_probe_timeout", fallback=2.0)

    result = _resolve_domain(domain, resolver_ip, dns_port, timeout, 1, logger)
    _latest_quick_probe = result

    logger.debug("quick_probe: %s → %s (%.1fms)",
                 domain,
                 "OK" if result["success"] else result.get("error", "FAIL"),
                 result.get("latency_ms") or 0)


def run_heartbeat(cfg: Config, logger: logging.Logger) -> None:
    """Heartbeat leve: sinal de vida + métricas rápidas + quick probe se disponível."""
    global _latest_quick_probe
    logger.debug("Enviando heartbeat...")
    dns_service    = detect_dns_service()
    system_metrics = collect_system_metrics(cfg)

    # Inclui resultado do quick probe no heartbeat se disponível
    dns_checks = []
    if _latest_quick_probe is not None:
        dns_checks = [_latest_quick_probe]
        _latest_quick_probe = None

    payload = build_payload(cfg, dns_service, dns_checks, system_metrics, "heartbeat")
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

# ---------------------------------------------------------------------------
# Polling de comandos remotos
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Scripts de diagnóstico embutidos (executados remotamente via run_script)
# ---------------------------------------------------------------------------

_BIND9_VALIDATE_SCRIPT = r"""#!/bin/bash
ERROR_COUNT=0
check_status() {
    if [ $? -eq 0 ]; then
        echo "CHECK_OK $1"
    else
        echo "CHECK_FAIL $1"
        ERROR_COUNT=$((ERROR_COUNT + 1))
    fi
}
SERVICE_NAME="named"
if ! systemctl cat named > /dev/null 2>&1; then SERVICE_NAME="bind9"; fi
systemctl is-active --quiet $SERVICE_NAME
check_status "Serviço $SERVICE_NAME está rodando"
ss -lntu | grep -q ":53 "
check_status "Porta 53 em escuta"
if command -v named-checkconf > /dev/null; then
    named-checkconf > /dev/null 2>&1
    check_status "Sintaxe named.conf válida"
else
    echo "CHECK_SKIP Comando named-checkconf não encontrado"
fi
dig @127.0.0.1 google.com +short +time=2 | grep -q .
check_status "Resolução externa google.com"
DNSSEC_AD=$(dig @127.0.0.1 internetsociety.org A +dnssec +time=5 +tries=1 2>/dev/null)
if echo "$DNSSEC_AD" | grep -q "flags:.*ad"; then
    echo "CHECK_OK Validação DNSSEC ativa (flag AD presente)"
else
    FAIL_STATUS=$(dig @127.0.0.1 dnssec-failed.org A +time=5 +tries=1 2>/dev/null | grep -i "status:")
    if echo "$FAIL_STATUS" | grep -qi "SERVFAIL"; then
        echo "CHECK_OK Validação DNSSEC ativa (dnssec-failed.org retornou SERVFAIL)"
    else
        echo "CHECK_FAIL DNSSEC pode não estar validando corretamente"
        ERROR_COUNT=$((ERROR_COUNT + 1))
    fi
fi
MEM_MAX=$(systemctl show $SERVICE_NAME -p MemoryMax 2>/dev/null | cut -d= -f2)
if [ -z "$MEM_MAX" ] || [ "$MEM_MAX" = "infinity" ] || [ "$MEM_MAX" = "18446744073709551615" ]; then
    echo "CHECK_INFO MemoryMax não definido (ilimitado)"
else
    echo "CHECK_OK MemoryMax configurado: $MEM_MAX bytes"
fi
BIND_CACHE="/var/cache/bind"
if [ -d "$BIND_CACHE" ]; then
    PERMS=$(stat -c "%U:%G" "$BIND_CACHE")
    if [ "$PERMS" = "bind:bind" ] || [ "$PERMS" = "root:bind" ]; then
        echo "CHECK_OK Permissões $BIND_CACHE corretas ($PERMS)"
    else
        echo "CHECK_WARN Permissões $BIND_CACHE incomuns: $PERMS"
    fi
else
    echo "CHECK_INFO Diretório $BIND_CACHE não encontrado"
fi
echo "SUMMARY errors=$ERROR_COUNT"
"""

_DIG_TEST_SCRIPT = r"""#!/bin/bash
ERROR_COUNT=0
if ! command -v dig > /dev/null 2>&1; then
    echo "CHECK_FAIL dig não encontrado (instale dnsutils: apt install dnsutils)"
    echo "SUMMARY errors=1"
    exit 1
fi

DOMAINS="google.com cloudflare.com github.com"
RESOLVERS="127.0.0.1 8.8.8.8 1.1.1.1"

dig_query() {
    local resolver="$1" domain="$2"
    local out
    out=$(dig @"$resolver" "$domain" A +short +time=3 +tries=1 2>/dev/null)
    local rc=$?
    local latency
    latency=$(dig @"$resolver" "$domain" A +stats +time=3 +tries=1 2>/dev/null | grep "Query time:" | awk '{print $4}')
    if [ $rc -eq 0 ] && [ -n "$out" ]; then
        echo "CHECK_OK @${resolver} → ${domain} (${latency:-?}ms) → $(echo "$out" | head -1)"
    else
        echo "CHECK_FAIL @${resolver} → ${domain}: sem resposta ou timeout"
        ERROR_COUNT=$((ERROR_COUNT + 1))
    fi
}

echo "CHECK_INFO === Resolução via resolver local (127.0.0.1) ==="
for d in $DOMAINS; do dig_query "127.0.0.1" "$d"; done

echo "CHECK_INFO === Resolução via Google DNS (8.8.8.8) ==="
for d in $DOMAINS; do dig_query "8.8.8.8" "$d"; done

echo "CHECK_INFO === Resolução via Cloudflare (1.1.1.1) ==="
for d in $DOMAINS; do dig_query "1.1.1.1" "$d"; done

echo "CHECK_INFO === DNSSEC ==="
DNSSEC_OUT=$(dig @127.0.0.1 internetsociety.org A +dnssec +time=5 +tries=1 2>/dev/null)
if echo "$DNSSEC_OUT" | grep -q "flags:.*ad"; then
    echo "CHECK_OK DNSSEC ativo — flag AD presente (internetsociety.org)"
else
    SERVFAIL=$(dig @127.0.0.1 dnssec-failed.org A +time=5 +tries=1 2>/dev/null | grep -i "status:")
    if echo "$SERVFAIL" | grep -qi "SERVFAIL"; then
        echo "CHECK_OK DNSSEC ativo — dnssec-failed.org retornou SERVFAIL corretamente"
    else
        echo "CHECK_WARN DNSSEC pode não estar validando (flag AD ausente, SERVFAIL não retornado)"
    fi
fi

echo "CHECK_INFO === Reverso (PTR) do resolver local ==="
LOCAL_IP=$(dig @8.8.8.8 myip.opendns.com +short 2>/dev/null | head -1)
if [ -n "$LOCAL_IP" ]; then
    PTR=$(dig @127.0.0.1 -x "$LOCAL_IP" +short +time=3 2>/dev/null | head -1)
    if [ -n "$PTR" ]; then
        echo "CHECK_OK PTR de $LOCAL_IP → $PTR"
    else
        echo "CHECK_INFO PTR de $LOCAL_IP → sem registro reverso"
    fi
else
    echo "CHECK_INFO IP público não detectado"
fi

echo "CHECK_INFO === Tempo de resposta comparativo (google.com) ==="
for r in 127.0.0.1 8.8.8.8 1.1.1.1; do
    ms=$(dig @"$r" google.com A +stats +time=3 +tries=1 2>/dev/null | grep "Query time:" | awk '{print $4}')
    if [ -n "$ms" ]; then
        if [ "$ms" -lt 50 ] 2>/dev/null; then
            echo "CHECK_OK @${r} latência: ${ms}ms (excelente)"
        elif [ "$ms" -lt 200 ] 2>/dev/null; then
            echo "CHECK_INFO @${r} latência: ${ms}ms (normal)"
        else
            echo "CHECK_WARN @${r} latência: ${ms}ms (alta)"
        fi
    else
        echo "CHECK_FAIL @${r} sem resposta ao medir latência"
        ERROR_COUNT=$((ERROR_COUNT + 1))
    fi
done

echo "SUMMARY errors=$ERROR_COUNT"
"""

DIAGNOSTIC_SCRIPTS: dict[str, str] = {
    "bind9_validate": _BIND9_VALIDATE_SCRIPT,
    "dig_test":       _DIG_TEST_SCRIPT,
}


def _parse_diagnostic_output(script_id: str, raw: str) -> str:
    """
    Converte a saída do script de diagnóstico em JSON estruturado.
    Retorna uma string JSON.
    """
    checks = []
    error_count = 0
    summary = ""

    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("CHECK_OK "):
            checks.append({"status": "ok", "message": line[9:]})
        elif line.startswith("CHECK_FAIL "):
            checks.append({"status": "fail", "message": line[11:]})
            error_count += 1
        elif line.startswith("CHECK_SKIP "):
            checks.append({"status": "skip", "message": line[11:]})
        elif line.startswith("CHECK_INFO "):
            checks.append({"status": "info", "message": line[11:]})
        elif line.startswith("CHECK_WARN "):
            checks.append({"status": "warn", "message": line[11:]})
        elif line.startswith("SUMMARY errors="):
            try:
                error_count = int(line.split("=")[1])
            except ValueError:
                pass
            summary = "Saudável" if error_count == 0 else f"{error_count} problema(s) encontrado(s)"

    if not summary:
        summary = "Saudável" if error_count == 0 else f"{error_count} problema(s) encontrado(s)"

    return json.dumps({
        "script": script_id,
        "checks": checks,
        "error_count": error_count,
        "summary": summary,
    }, ensure_ascii=False)


def _run_dnstop(cfg: Config, logger: logging.Logger, params: str = None) -> tuple[str, str]:
    """
    Captura trafego DNS por N segundos e retorna JSON estruturado.
    Fluxo: tcpdump captura pcap → le com -r -nn → parse → JSON.
    Se dnstop disponivel, usa como analisador complementar.
    Resultado: {qps, packets, top_domains, top_clients, query_types, ...}
    """
    try:
        p = json.loads(params) if params and params.strip().startswith("{") else {}
    except (json.JSONDecodeError, ValueError):
        p = {}

    duration  = int(p.get("duration", params or 9))
    interface = p.get("interface", "any")
    duration  = max(3, min(duration, 30))
    pcap_path = tempfile.mktemp(suffix=".pcap")

    try:
        if not shutil.which("tcpdump"):
            return "failed", "tcpdump nao encontrado. Instale: apt install tcpdump"

        # ── Captura pcap ──
        subprocess.run(
            ["sudo", "-n", "tcpdump", "-i", interface, "-n", "-w", pcap_path,
             "-G", str(duration), "-W", "1", "port", "53"],
            capture_output=True, timeout=duration + 10,
        )

        if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) == 0:
            return "done", json.dumps({
                "duration": duration, "interface": interface,
                "packets": 0, "qps": 0, "top_domains": [],
                "top_clients": [], "query_types": {},
                "message": "Nenhum trafego DNS capturado",
            }, ensure_ascii=False)

        # ── Le pcap com tcpdump verbose ──
        rd = subprocess.run(
            ["sudo", "-n", "tcpdump", "-r", pcap_path, "-nn", "-v"],
            capture_output=True, text=True, timeout=30,
        )

        lines = rd.stdout.strip().split("\n")
        total = len([l for l in lines if l.strip()])

        domains = {}
        clients = {}
        qtypes  = {}
        queries = 0
        responses = 0

        for line in lines:
            parts = line.split()
            if len(parts) < 5:
                continue

            # Detecta queries: "IP src.port > dst.53: ... A? domain"
            # Detecta responses: "IP src.53 > dst.port: ..."
            is_query = False
            is_response = False

            for i, part in enumerate(parts):
                if part.endswith(".53:") or part.endswith(".53"):
                    # Trafego de/para porta 53
                    if i > 0 and parts[i-1] == ">":
                        is_query = True
                    elif i + 1 < len(parts) and parts[i+1] == ">":
                        is_response = True

            # Extrai tipo de query (A?, AAAA?, MX?, PTR?, etc.)
            for part in parts:
                if part.endswith("?") and len(part) <= 6:
                    qtype = part.rstrip("?")
                    qtypes[qtype] = qtypes.get(qtype, 0) + 1

            # Extrai dominio consultado
            for i, part in enumerate(parts):
                if part.endswith("?") and i > 0:
                    domain = parts[i - 1].rstrip(".").lower()
                    if domain and "." in domain and len(domain) > 2:
                        domains[domain] = domains.get(domain, 0) + 1

            # Extrai IP do cliente (origem da query)
            if is_query:
                queries += 1
                # IP source e o campo antes de "> dst.53:"
                for i, part in enumerate(parts):
                    if part == "IP":
                        if i + 1 < len(parts):
                            src = parts[i + 1]
                            # Remove .porta do final (ex: 192.168.1.10.45321)
                            ip_parts = src.split(".")
                            if len(ip_parts) >= 5:
                                client_ip = ".".join(ip_parts[:4])
                                clients[client_ip] = clients.get(client_ip, 0) + 1
                        break
            elif is_response:
                responses += 1

        qps = round(queries / duration, 1) if duration > 0 else 0
        top_domains = sorted(domains.items(), key=lambda x: -x[1])[:10]
        top_clients = sorted(clients.items(), key=lambda x: -x[1])[:10]

        result = {
            "duration": duration,
            "interface": interface,
            "packets": total,
            "queries": queries,
            "responses": responses,
            "qps": qps,
            "top_domains": [{"domain": d, "count": c} for d, c in top_domains],
            "top_clients": [{"ip": ip, "count": c} for ip, c in top_clients],
            "query_types": qtypes,
        }

        # ── Complementa com dnstop se disponivel ──
        if shutil.which("dnstop"):
            try:
                dt = subprocess.run(
                    ["dnstop", "-n", pcap_path],
                    capture_output=True, text=True, timeout=15,
                )
                if dt.stdout.strip():
                    result["dnstop_output"] = dt.stdout[:3000]
            except Exception:
                pass

        logger.info("dnstop: %d queries em %ds (%.1f qps), %d dominios, %d clientes",
                     queries, duration, qps, len(domains), len(clients))
        return "done", json.dumps(result, ensure_ascii=False)

    except subprocess.TimeoutExpired:
        return "failed", f"Timeout apos {duration + 10}s"
    except Exception as exc:
        return "failed", f"Erro: {exc}"
    finally:
        if os.path.exists(pcap_path):
            os.unlink(pcap_path)


COMMAND_HANDLERS = {
    "stop":    ["sudo", "-n", "systemctl", "stop"],
    "disable": ["sudo", "-n", "systemctl", "disable", "--now"],
    "enable":  ["sudo", "-n", "systemctl", "enable", "--now"],
    "restart": ["sudo", "-n", "systemctl", "restart"],
    "purge":   None,  # tratado separadamente
}


# Mapeamento de aliases para o nome real do serviço no systemctl.
# No Debian, 'bind9' é um alias — o serviço real é 'named'.
# O systemctl recusa operar em aliases com enable/disable.
SERVICE_ALIASES = {
    "bind9": "named",
}

def _get_dns_service_name(cfg: Config) -> str:
    """
    Retorna o nome real do serviço DNS para uso com systemctl.
    Resolve aliases — ex: bind9 → named no Debian.
    """
    svc = detect_dns_service()
    name = svc.get("name", "unbound")
    return SERVICE_ALIASES.get(name, name)


def _execute_update_agent(
    backend_url: str,
    auth_token: str,
    logger: logging.Logger,
) -> tuple[str, str]:
    """
    Baixa a versão mais recente do agente do backend, verifica o checksum,
    valida a sintaxe Python, substitui o arquivo atual e reinicia o processo.

    Retorna (status, result) — o restart ocorre ~3s após o retorno para dar
    tempo de reportar o resultado ao backend antes de encerrar.
    """
    import hashlib as _hashlib
    import py_compile
    import threading

    current_file = os.path.abspath(__file__)
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "User-Agent":    f"dns-agent/{AGENT_VERSION}",
    }

    # ── 1. Verificar versão disponível ───────────────────────────────────────
    try:
        ver_resp = requests.get(
            f"{backend_url}/api/v1/agent/version",
            headers=headers, timeout=10,
        )
        if ver_resp.status_code != 200:
            return "failed", f"Erro ao consultar versão: HTTP {ver_resp.status_code}"
        ver_data     = ver_resp.json()
        remote_ver   = ver_data.get("version", "?")
        remote_cksum = ver_data.get("checksum", "")
    except Exception as exc:
        return "failed", f"Erro ao consultar /agent/version: {exc}"

    if remote_ver == AGENT_VERSION:
        return "done", f"Agente já está na versão atual ({AGENT_VERSION}) — nenhuma ação necessária"

    logger.warning("update_agent: versão remota=%s local=%s — iniciando download",
                   remote_ver, AGENT_VERSION)

    # ── 2. Baixar novo arquivo ───────────────────────────────────────────────
    try:
        dl_resp = requests.get(
            f"{backend_url}/api/v1/agent/latest",
            headers=headers, timeout=60,
        )
        if dl_resp.status_code != 200:
            return "failed", f"Erro ao baixar agente: HTTP {dl_resp.status_code}"
        new_content = dl_resp.text
    except Exception as exc:
        return "failed", f"Erro ao baixar /agent/latest: {exc}"

    # ── 3. Verificar checksum ────────────────────────────────────────────────
    if remote_cksum:
        actual_cksum = _hashlib.sha256(new_content.encode()).hexdigest()
        if actual_cksum != remote_cksum:
            return "failed", (
                f"Checksum inválido — download corrompido ou adulterado. "
                f"Esperado: {remote_cksum[:16]}… Obtido: {actual_cksum[:16]}…"
            )

    # ── 4. Validar sintaxe Python ────────────────────────────────────────────
    tmp_path = current_file + ".update_tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        py_compile.compile(tmp_path, doraise=True)
    except py_compile.PyCompileError as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return "failed", f"Arquivo baixado tem erro de sintaxe Python — update cancelado: {exc}"
    except Exception as exc:
        return "failed", f"Erro ao validar arquivo: {exc}"

    # ── 5. Substituição atômica (com backup) ─────────────────────────────────
    backup_path = current_file + ".bak"
    try:
        shutil.copy2(current_file, backup_path)
        os.replace(tmp_path, current_file)
        os.chmod(current_file, 0o755)
    except Exception as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return "failed", f"Erro ao substituir arquivo: {exc}"

    result_msg = (
        f"Atualizado {AGENT_VERSION} → {remote_ver} com sucesso. "
        f"Backup em {backup_path}. Reiniciando em 3s…"
    )
    logger.warning("update_agent: %s", result_msg)

    # ── 6. Reiniciar processo após dar tempo para reportar o resultado ────────
    def _do_restart():
        time.sleep(3)
        logger.info("update_agent: reiniciando via os.execv")
        os.execv(sys.executable, [sys.executable] + sys.argv)

    threading.Thread(target=_do_restart, daemon=True).start()
    return "done", result_msg


def _run_dig_trace(domain: str, resolver: str, logger: logging.Logger) -> tuple[str, str]:
    """
    Executa dig +trace no domínio dado e devolve JSON estruturado com hops.
    Usado pelo comando run_script com params {"script":"dig_trace",...}.
    """
    import re as _re

    result: dict = {
        "script":          "dig_trace",
        "domain":          domain,
        "resolver":        resolver,
        "source_hostname": socket.gethostname(),
        "query":           None,
        "trace":           [],
        "error_count":     0,
        "summary":         "",
    }

    if not shutil.which("dig"):
        result["error_count"] = 1
        result["summary"] = "dig não encontrado — instale dnsutils: apt install dnsutils"
        return "failed", json.dumps(result, ensure_ascii=False)

    # ── Consulta direta (@resolver) ──────────────────────────────────────────
    try:
        proc = subprocess.run(
            ["dig", f"@{resolver}", domain, "A",
             "+noall", "+answer", "+stats", "+time=5", "+tries=1"],
            capture_output=True, text=True, timeout=15,
        )
        answers, latency_ms, query_status = [], None, "NOERROR"
        for line in proc.stdout.splitlines():
            ls = line.strip()
            m = _re.match(r'^(\S+)\s+(\d+)\s+IN\s+A\s+([\d.]+)', ls)
            if m:
                answers.append({"name": m.group(1).rstrip('.'),
                                 "ttl": int(m.group(2)), "value": m.group(3)})
            m2 = _re.search(r'Query time:\s*(\d+)\s*msec', ls)
            if m2:
                latency_ms = int(m2.group(1))
        for bad in ("SERVFAIL", "NXDOMAIN", "REFUSED"):
            if bad in proc.stdout:
                query_status = bad
                result["error_count"] += 1
                break
        if not answers and query_status == "NOERROR":
            query_status = "EMPTY"
            result["error_count"] += 1
        result["query"] = {"answers": answers, "latency_ms": latency_ms, "status": query_status}
    except subprocess.TimeoutExpired:
        result["query"] = {"error": "Timeout na consulta direta (15s)"}
        result["error_count"] += 1
    except Exception as exc:
        result["query"] = {"error": str(exc)[:300]}
        result["error_count"] += 1

    # ── dig +trace ───────────────────────────────────────────────────────────
    try:
        proc = subprocess.run(
            ["dig", "+trace", "+additional", "+time=5", "+tries=1", domain, "A"],
            capture_output=True, text=True, timeout=90,
        )

        hop_re = _re.compile(
            r'Received \d+ bytes from ([\d.a-fA-F:]+)#\d+\(([^)]*)\) in (\d+) ms'
        )
        ns_re = _re.compile(r'^(\S+)\s+\d+\s+IN\s+NS\s+(\S+)')
        a_re  = _re.compile(r'^(\S+)\s+\d+\s+IN\s+A\s+([\d.]+)')

        block: list[str] = []
        hops:  list[dict] = []

        for line in proc.stdout.splitlines():
            s = line.strip()
            if not s:
                continue
            block.append(s)
            m_hop = hop_re.search(s)
            if not m_hop:
                continue

            ns_list: list[str] = []
            a_list:  list[str] = []
            zone = None
            for bl in block:
                if bl.startswith(';'):
                    continue
                mn = ns_re.match(bl)
                if mn:
                    if zone is None:
                        zone = mn.group(1).rstrip('.')
                    ns_list.append(mn.group(2).rstrip('.'))
                ma = a_re.match(bl)
                if ma:
                    if zone is None:
                        zone = ma.group(1).rstrip('.')
                    a_list.append(ma.group(2))

            hops.append({
                "zone":        zone or "?",
                "server_ip":   m_hop.group(1),
                "server_name": m_hop.group(2),
                "latency_ms":  int(m_hop.group(3)),
                "ns_records":  list(dict.fromkeys(ns_list)),
                "a_records":   list(dict.fromkeys(a_list)),
            })
            block = []

        result["trace"] = hops
        if not hops:
            result["error_count"] += 1
            result["trace_error"] = "Trace retornou 0 hops"

    except subprocess.TimeoutExpired:
        result["trace_error"] = "Timeout no trace (90s)"
        result["error_count"] += 1
    except Exception as exc:
        result["trace_error"] = str(exc)[:300]
        result["error_count"] += 1

    ok = result["error_count"] == 0
    n  = len(result["trace"])
    result["summary"] = (
        f"Resolvido via {n} hop(s)" if ok
        else f"{result['error_count']} problema(s) na resolução"
    )
    logger.info("dig_trace: domain=%s resolver=%s hops=%d errors=%d",
                domain, resolver, n, result["error_count"])
    return "done", json.dumps(result, ensure_ascii=False)


def _execute_command(command: str, confirm_token: str, cfg: Config,
                     logger: logging.Logger, params: str = None) -> tuple[str, str]:
    """
    Executa um comando remoto no serviço DNS.
    Retorna (status, result) onde status é 'done' ou 'failed'.
    """
    service = _get_dns_service_name(cfg)

    if command == "update_agent":
        url        = cfg.get("backend", "url").rstrip("/")
        auth_token = cfg.get("agent", "auth_token")
        return _execute_update_agent(url, auth_token, logger)

    if command == "dnstop":
        return _run_dnstop(cfg, logger, params)

    if command == "run_script":
        params_str = (params or "").strip()
        # params pode ser JSON {"script": "...", "domain": "...", ...} ou nome simples
        try:
            params_obj = json.loads(params_str)
            script_id  = params_obj.get("script", "")
        except (json.JSONDecodeError, ValueError):
            params_obj = {}
            script_id  = params_str

        if not script_id:
            return "failed", "run_script exige params com o nome do script"

        # Handler especial para dig_trace (precisa de argumentos dinâmicos)
        if script_id == "dig_trace":
            domain   = params_obj.get("domain",   "google.com").strip()
            resolver = params_obj.get("resolver", "127.0.0.1").strip()
            return _run_dig_trace(domain, resolver, logger)

        script_content = DIAGNOSTIC_SCRIPTS.get(script_id)
        if script_content is None:
            return "failed", f"Script desconhecido: {script_id}. Disponíveis: {list(DIAGNOSTIC_SCRIPTS)}"
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".sh", delete=False, encoding="utf-8"
            ) as f:
                f.write(script_content)
                tmp = f.name
            os.chmod(tmp, 0o700)
            result = subprocess.run(
                ["bash", tmp],
                capture_output=True, text=True, timeout=60
            )
            raw_output = result.stdout + result.stderr
            logger.info("Diagnóstico '%s' executado (rc=%d)", script_id, result.returncode)
            return "done", _parse_diagnostic_output(script_id, raw_output)
        except subprocess.TimeoutExpired:
            return "failed", json.dumps({"script": script_id, "error": "Timeout ao executar diagnóstico (60s)"})
        except Exception as exc:
            return "failed", json.dumps({"script": script_id, "error": str(exc)})
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    if command == "purge":
        if not confirm_token:
            return "failed", "purge exige confirm_token — comando rejeitado por segurança"
        try:
            result = subprocess.run(
                ["sudo", "-n", "apt-get", "purge", "-y", service],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                logger.warning("COMANDO REMOTO: serviço '%s' removido (purge)", service)
                return "done", f"Serviço {service} removido com sucesso"
            return "failed", result.stderr[:500]
        except Exception as exc:
            return "failed", str(exc)[:500]

    handler = COMMAND_HANDLERS.get(command)
    if handler is None:
        return "failed", f"Comando desconhecido: {command}"

    cmd = handler + [service]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            logger.warning(
                "COMANDO REMOTO executado: %s %s", command, service
            )
            return "done", f"{command} {service}: OK"
        return "failed", (result.stderr or result.stdout)[:500]
    except subprocess.TimeoutExpired:
        return "failed", f"Timeout ao executar {command} {service}"
    except Exception as exc:
        return "failed", str(exc)[:500]


# ---------------------------------------------------------------------------
# Polling adaptativo — estado global
# Ativo: poll a cada 60s | Idle: após 2 polls vazios, espera idle_interval
# ---------------------------------------------------------------------------
_poll_empty_count: int   = 0
_poll_last_active: float = 0.0


def poll_commands(cfg, logger: logging.Logger) -> None:
    """
    Consulta o backend por comandos pendentes e os executa.
    Polling adaptativo: roda a cada 60s, mas pula quando em idle
    (2 polls consecutivos sem comandos) até idle_interval expirar.
    """
    global _poll_empty_count, _poll_last_active

    # ── Idle gate: pula se em idle e intervalo não expirou ───────────────
    idle_threshold = 2
    idle_interval = cfg.getint("schedule", "command_poll_idle_interval", fallback=600)

    if _poll_empty_count >= idle_threshold:
        elapsed = time.time() - _poll_last_active
        if elapsed < idle_interval:
            return          # ainda em idle — pula
        # idle expirou — faz poll de verificação

    # ── Poll efetivo ────────────────────────────────────────────────────
    url   = cfg.get("backend", "url").rstrip("/")
    token = cfg.get("agent", "auth_token")
    hostname = cfg.get("agent", "hostname", fallback=socket.gethostname())
    timeout  = cfg.getint("backend", "timeout", fallback=10)

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
        "User-Agent":    "dns-agent/1.0",
    }

    try:
        resp = requests.get(
            f"{url}/api/v1/commands/{hostname}",
            headers=headers, timeout=timeout
        )
        if resp.status_code == 401:
            logger.error("poll_commands: token inválido (401)")
            return
        if resp.status_code != 200:
            logger.warning("poll_commands: backend retornou %d", resp.status_code)
            return

        commands = resp.json()
        if not commands:
            _poll_empty_count += 1
            if _poll_empty_count >= idle_threshold:
                _poll_last_active = time.time()
                logger.debug("poll_commands: idle ativado após %d polls vazios", _poll_empty_count)
            else:
                logger.debug("poll_commands: nenhum comando pendente (%d/%d)", _poll_empty_count, idle_threshold)
            return

        # Comandos encontrados — reseta idle
        _poll_empty_count = 0
        _poll_last_active = time.time()
        logger.info("poll_commands: %d comando(s) recebido(s)", len(commands))

        for cmd in commands:
            cmd_id        = cmd["id"]
            command       = cmd["command"]
            confirm_token = cmd.get("confirm_token")
            params        = cmd.get("params")

            logger.warning(
                "Executando comando remoto id=%d: %s", cmd_id, command
            )

            status, result = _execute_command(command, confirm_token, cfg, logger, params)

            # Reportar resultado ao backend
            try:
                requests.post(
                    f"{url}/api/v1/commands/{cmd_id}/result",
                    json={"status": status, "result": result},
                    headers=headers, timeout=timeout
                )
            except Exception as exc:
                logger.error("Falha ao reportar resultado do comando %d: %s", cmd_id, exc)

    except requests.exceptions.ConnectionError:
        logger.debug("poll_commands: sem conexão com backend")
    except requests.exceptions.Timeout:
        logger.debug("poll_commands: timeout ao consultar comandos")
    except Exception as exc:
        logger.error("poll_commands: erro inesperado: %s", exc)


def setup_schedule(cfg: Config, logger: logging.Logger) -> None:
    """Configura os jobs agendados com base no agent.conf."""
    # Testes completos nos horários configurados
    times_raw = cfg.get("schedule", "check_times", fallback="00:00,02:00,04:00,06:00,08:00,10:00,12:00,14:00,16:00,18:00,20:00,22:00")
    check_times = [t.strip() for t in times_raw.split(",") if t.strip()]

    for t in check_times:
        schedule.every().day.at(t).do(run_full_check, cfg=cfg, logger=logger)
        logger.info("Agendado ciclo completo às %s", t)

    # Heartbeat periódico
    heartbeat_interval = cfg.getint("schedule", "heartbeat_interval", fallback=300)
    schedule.every(heartbeat_interval).seconds.do(run_heartbeat, cfg=cfg, logger=logger)
    logger.info("Heartbeat agendado a cada %ds", heartbeat_interval)

    # Quick Probe DNS — teste leve de alta frequência
    if cfg.getboolean("schedule", "quick_probe_enabled", fallback=True):
        probe_interval = max(10, cfg.getint("schedule", "quick_probe_interval", fallback=60))
        schedule.every(probe_interval).seconds.do(run_quick_probe, cfg=cfg, logger=logger)
        logger.info("Quick probe DNS agendado a cada %ds", probe_interval)

    # Polling de comandos remotos — adaptativo (60s ativo, idle após 2 vazios)
    cmd_interval = cfg.getint("schedule", "command_poll_interval", fallback=60)
    schedule.every(cmd_interval).seconds.do(poll_commands, cfg=cfg, logger=logger)
    logger.info("Polling de comandos agendado a cada %ds (adaptativo)", cmd_interval)


# ---------------------------------------------------------------------------
# NATS — conexao e subscribe de comandos (opcional)
# ---------------------------------------------------------------------------

_nats_connected = False

def _start_nats(cfg: Config, logger: logging.Logger) -> bool:
    """Conecta ao NATS e subscreve em comandos. Retorna True se sucesso."""
    global _nats_connected
    if not cfg.getboolean("nats", "enabled", fallback=False):
        logger.info("NATS desabilitado — usando HTTP polling")
        return False

    try:
        import asyncio
        import nats as nats_lib

        nats_url  = cfg.get("nats", "url", fallback="nats://localhost:4222")
        hostname  = cfg.get("agent", "hostname", fallback=socket.gethostname())
        token     = cfg.get("agent", "auth_token")
        backend_url = cfg.get("backend", "url").rstrip("/")
        timeout_s = cfg.getint("backend", "timeout", fallback=10)

        loop = asyncio.new_event_loop()

        nats_user = cfg.get("nats", "user", fallback="").strip()
        nats_pass = cfg.get("nats", "password", fallback="").strip()

        async def _run():
            connect_opts = dict(
                servers=nats_url, name=f"dns-agent-{hostname}",
                reconnect_time_wait=5, max_reconnect_attempts=-1,
            )
            if nats_user and nats_pass:
                connect_opts["user"] = nats_user
                connect_opts["password"] = nats_pass
            nc = await nats_lib.connect(**connect_opts)
            js = nc.jetstream()

            async def _on_command(msg):
                """Callback para comandos recebidos via NATS."""
                try:
                    data = __import__("json").loads(msg.data.decode())
                    cmd_id  = data.get("id")
                    command = data.get("command", "")
                    confirm = data.get("confirm_token")
                    params  = data.get("params")

                    logger.warning("NATS: comando recebido id=%s: %s", cmd_id, command)
                    status, result = _execute_command(command, confirm, cfg, logger, params)

                    # ACK via NATS
                    await js.publish(
                        f"dns.commands.{hostname}.ack",
                        __import__("json").dumps({
                            "command_id": cmd_id, "status": status, "result": result,
                        }).encode(),
                    )

                    # Tambem reporta via HTTP (redundancia)
                    try:
                        requests.post(
                            f"{backend_url}/api/v1/commands/{cmd_id}/result",
                            json={"status": status, "result": result},
                            headers={"Authorization": f"Bearer {token}"},
                            timeout=timeout_s,
                        )
                    except Exception:
                        pass  # NATS ACK ja chegou

                    await msg.ack()
                except Exception as exc:
                    logger.error("NATS command handler erro: %s", exc)

            await js.subscribe(
                f"dns.commands.{hostname}",
                durable=f"agent-{hostname}",
                cb=_on_command,
            )
            logger.info("NATS conectado: %s (subscribe: dns.commands.%s)", nats_url, hostname)
            return nc, loop

        nc, _ = loop.run_until_complete(_run())

        # Roda o event loop NATS numa thread separada
        import threading
        def _nats_loop():
            loop.run_forever()
        t = threading.Thread(target=_nats_loop, daemon=True, name="nats-listener")
        t.start()
        _nats_connected = True
        return True

    except Exception as exc:
        logger.warning("NATS falhou (%s) — fallback HTTP polling", exc)
        _nats_connected = False
        return False


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

    # Conecta NATS (opcional)
    nats_ok = _start_nats(cfg, logger)

    # Verifica comandos pendentes via HTTP (captura comandos emitidos durante downtime)
    poll_commands(cfg, logger)

    # Configura agenda (polling HTTP como fallback mesmo com NATS)
    setup_schedule(cfg, logger)

    logger.info("Scheduler ativo. NATS=%s. Aguardando próximos ciclos...",
                "conectado" if nats_ok else "off")
    while True:
        schedule.run_pending()
        time.sleep(10)


if __name__ == "__main__":
    main()