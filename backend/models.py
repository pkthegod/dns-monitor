"""
models.py — Modelos Pydantic para validacao de payloads do agente.
"""

from typing import Optional
from pydantic import BaseModel, Field


class DnsServiceModel(BaseModel):
    name:    Optional[str] = None
    active:  Optional[bool] = None
    version: Optional[str] = None

class DnsCheckModel(BaseModel):
    domain:       str
    resolver:     Optional[str] = None
    success:      bool
    latency_ms:   Optional[float] = None
    response_ips: Optional[list[str]] = Field(default_factory=list)
    error:        Optional[str] = None
    attempts:     Optional[int] = None

class CpuModel(BaseModel):
    percent:  Optional[float] = None
    count:    Optional[int]   = None
    freq_mhz: Optional[float] = None

class RamModel(BaseModel):
    percent:       Optional[float] = None
    used_mb:       Optional[float] = None
    total_mb:      Optional[float] = None
    swap_percent:  Optional[float] = None
    swap_used_mb:  Optional[float] = None
    swap_total_mb: Optional[float] = None

class DiskModel(BaseModel):
    mountpoint: Optional[str]   = None
    device:     Optional[str]   = None
    fstype:     Optional[str]   = None
    percent:    Optional[float] = None
    used_gb:    Optional[float] = None
    free_gb:    Optional[float] = None
    total_gb:   Optional[float] = None
    alert:      Optional[str]   = None

class IoModel(BaseModel):
    read_bytes:    Optional[int] = None
    write_bytes:   Optional[int] = None
    read_count:    Optional[int] = None
    write_count:   Optional[int] = None
    read_time_ms:  Optional[int] = None
    write_time_ms: Optional[int] = None

class LoadModel(BaseModel):
    load_1m:  Optional[float] = None
    load_5m:  Optional[float] = None
    load_15m: Optional[float] = None

class SystemModel(BaseModel):
    cpu:  Optional[CpuModel]        = None
    ram:  Optional[RamModel]        = None
    disk: Optional[list[DiskModel]] = Field(default_factory=list)
    io:   Optional[IoModel]         = None
    load: Optional[LoadModel]       = None

class AgentPayload(BaseModel):
    type:          str                       # "check" | "heartbeat"
    hostname:      str
    timestamp:     str
    agent_version: Optional[str]  = None
    fingerprint:   Optional[str]  = None     # SHA256 do hardware — detecta copias
    dns_service:   Optional[DnsServiceModel] = None
    dns_checks:    Optional[list[DnsCheckModel]] = Field(default_factory=list)
    system:        Optional[SystemModel]     = None

class AgentMetaUpdate(BaseModel):
    display_name: Optional[str]  = None
    location:     Optional[str]  = None
    notes:        Optional[str]  = None
    active:       Optional[bool] = None


# ---------------------------------------------------------------------------
# Speedtest — Domain SSL/Port checker (validacao de input)
# ---------------------------------------------------------------------------

class SpeedtestDomainModel(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)
    port: int = Field(default=8080, ge=1, le=65535)
    reachable: bool = False
    ssl_enabled: bool = False
    certificate_valid: bool = False
    certificate_expired: Optional[bool] = None
    days_until_expiry: Optional[int] = None
    expiry_date: Optional[str] = None
    issued_date: Optional[str] = None
    issuer: Optional[str] = Field(default=None, max_length=200)
    subject: Optional[str] = Field(default=None, max_length=253)
    tls_version: Optional[str] = Field(default=None, max_length=20)
    cipher_suite: Optional[str] = Field(default=None, max_length=100)
    response_time_ms: Optional[float] = None
    error_message: Optional[str] = Field(default=None, max_length=500)


class SpeedtestPayload(BaseModel):
    metadata: dict = Field(default_factory=dict)
    domains: list[SpeedtestDomainModel] = Field(..., min_length=1, max_length=5000)
    summary: dict = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# NATS payloads — Onda 2 SEC-2.1
# ---------------------------------------------------------------------------
# Antes, handlers NATS faziam json.loads(msg.data) e usavam dict cru — sem
# validacao, atacante NATS-autenticado podia injetar:
#   - command_id arbitrario em ack -> mark_command_done em comando alheio
#   - dns_stats com SERVFAIL inflado -> dispara alertas falsos + webhooks
#     pra clientes que monitoram aquele hostname
#
# Pydantic valida tipos + ranges + comprimentos. Schema explicito tambem
# documenta o contrato pra quem escrever consumer alternativo no futuro.


class CommandAckPayload(BaseModel):
    """Payload do agente reportando resultado de comando via NATS.

    Subject: dns.commands.<hostname>.ack
    Tambem usado em routes_agent.post_command_result (HTTP path).
    """
    command_id: int = Field(..., ge=1, description="ID do comando no DB")
    status: str = Field(default="done", pattern=r"^(done|failed)$")
    result: str = Field(default="", max_length=10_000)


class DnsStatsPayload(BaseModel):
    """Sample de stats DNS coletada pelo agente (RCODEs/QPS/cache).

    Subject NATS: dns.stats.<hostname> | HTTP: POST /api/v1/agents/{hostname}/dns-stats
    Counters sao deltas sobre period_seconds — agente calcula subtraindo
    snapshot anterior. Caps: 10 dias de uptime sem snapshot ainda fica
    abaixo do max_int aqui (~2_000_000_000 queries em 10 dias = 2300 qps).
    """
    ts: Optional[str] = Field(default=None, description="ISO 8601; default = agora UTC")
    period_seconds: int = Field(default=600, ge=1, le=86_400)
    source: str = Field(default="unknown", pattern=r"^(bind9|unbound|unknown)$")

    # RCODEs (todos contadores >= 0)
    noerror:  int = Field(default=0, ge=0, le=2_000_000_000)
    nxdomain: int = Field(default=0, ge=0, le=2_000_000_000)
    servfail: int = Field(default=0, ge=0, le=2_000_000_000)
    refused:  int = Field(default=0, ge=0, le=2_000_000_000)
    notimpl:  int = Field(default=0, ge=0, le=2_000_000_000)
    formerr:  int = Field(default=0, ge=0, le=2_000_000_000)
    other_rcode: int = Field(default=0, ge=0, le=2_000_000_000)

    # Tipos de query
    queries_a:     int = Field(default=0, ge=0, le=2_000_000_000)
    queries_aaaa:  int = Field(default=0, ge=0, le=2_000_000_000)
    queries_mx:    int = Field(default=0, ge=0, le=2_000_000_000)
    queries_ptr:   int = Field(default=0, ge=0, le=2_000_000_000)
    queries_other: int = Field(default=0, ge=0, le=2_000_000_000)
    queries_total: int = Field(default=0, ge=0, le=2_000_000_000)

    qps_avg: Optional[float] = Field(default=None, ge=0, le=10_000_000)

    # Cache (so Unbound expoe — Bind9 pode vir None)
    cache_hits:    Optional[int] = Field(default=None, ge=0, le=2_000_000_000)
    cache_misses:  Optional[int] = Field(default=None, ge=0, le=2_000_000_000)
    cache_hit_pct: Optional[float] = Field(default=None, ge=0, le=100)
