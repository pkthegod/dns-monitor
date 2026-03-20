#!/usr/bin/env python3
"""
test_payload.py — Envia um payload mínimo ao backend para diagnosticar o HTTP 500.
Usa apenas stdlib — sem dependências externas.

Uso:
    python3 test_payload.py <URL_BACKEND> <TOKEN>

Exemplo:
    python3 test_payload.py http://192.168.1.100:8000 meu_token_aqui
"""

import json
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
if len(sys.argv) < 3:
    print("Uso: python3 test_payload.py <URL_BACKEND> <TOKEN>")
    sys.exit(1)

BASE_URL = sys.argv[1].rstrip("/")
TOKEN    = sys.argv[2]

# ---------------------------------------------------------------------------
# Payload mínimo — espelha exatamente o contrato do dns_agent.py
# ---------------------------------------------------------------------------
payload = {
    "type":          "check",
    "hostname":      "test-diag-01",
    "timestamp":     datetime.now(timezone.utc).isoformat(),
    "agent_version": "1.0.0-test",
    "dns_service": {
        "name":    "unbound",
        "active":  True,
        "version": "unbound 1.17.0",
    },
    "dns_checks": [
        {
            "domain":       "google.com",
            "resolver":     "127.0.0.1",
            "success":      True,
            "latency_ms":   12.4,
            "response_ips": ["142.250.218.46"],
            "error":        None,
            "attempts":     1,
        }
    ],
    "system": {
        "cpu":  {"percent": 10.0, "count": 2, "freq_mhz": 2400.0},
        "ram":  {
            "percent": 40.0, "used_mb": 1024.0, "total_mb": 4096.0,
            "swap_percent": 0.0, "swap_used_mb": 0.0, "swap_total_mb": 512.0,
        },
        "disk": [
            {
                "mountpoint": "/", "device": "/dev/sda1", "fstype": "ext4",
                "percent": 50.0, "used_gb": 10.0, "free_gb": 10.0,
                "total_gb": 20.0, "alert": "ok",
            }
        ],
        "io": {
            "read_bytes": 102400, "write_bytes": 51200,
            "read_count": 100,    "write_count": 50,
            "read_time_ms": 20,   "write_time_ms": 10,
        },
        "load": {"load_1m": 0.1, "load_5m": 0.1, "load_15m": 0.1},
    },
}

# ---------------------------------------------------------------------------
# Envio
# ---------------------------------------------------------------------------
def post(url, data, token):
    body = json.dumps(data, default=str).encode()
    req  = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as exc:
        return None, str(exc)


print(f"Backend : {BASE_URL}")
print(f"Token   : {TOKEN[:8]}...")
print()

# 1. Healthcheck
print("1. Healthcheck...")
status, body = post(BASE_URL + "/health", {}, TOKEN)
req = urllib.request.Request(BASE_URL + "/health")
try:
    with urllib.request.urlopen(req, timeout=5) as r:
        print(f"   {r.status} {r.read().decode()}")
except Exception as e:
    print(f"   ERRO: {e}")

print()

# 2. Payload completo
print("2. Enviando payload check completo...")
status, body = post(BASE_URL + "/metrics", payload, TOKEN)
print(f"   HTTP {status}")
print(f"   {body}")

if status == 200:
    print()
    print("OK — payload aceito. Agente deve aparecer em /agents.")
elif status == 500:
    print()
    print("500 confirmado. Veja o detalhe do erro acima e os logs do backend:")
    print("   docker compose logs --tail=30 backend")
elif status == 401:
    print()
    print("401 — token incorreto. Verifique AGENT_TOKEN no .env do backend.")
elif status == 422:
    print()
    print("422 — payload rejeitado pelo Pydantic. Detalhe do erro acima.")

# 3. Se deu 500, tenta um payload ainda mais reduzido para isolar o campo problemático
if status == 500:
    print()
    print("3. Tentando payload mínimo (sem system, sem dns_checks)...")
    minimal = {
        "type":      "heartbeat",
        "hostname":  "test-diag-01",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    s2, b2 = post(BASE_URL + "/metrics", minimal, TOKEN)
    print(f"   HTTP {s2}")
    print(f"   {b2}")

    if s2 == 200:
        print()
        print("Heartbeat mínimo OK — o problema está em algum campo de 'system' ou 'dns_checks'.")
        print("Testando sem dns_checks...")
        no_dns = dict(payload)
        no_dns["dns_checks"] = []
        s3, b3 = post(BASE_URL + "/metrics", no_dns, TOKEN)
        print(f"   HTTP {s3} — {b3}")

        if s3 == 200:
            print("Sem dns_checks OK — problema isolado em dns_checks.")
        else:
            print("Ainda 500 sem dns_checks — problema em 'system'.")
            print("Testando sem system...")
            no_sys = {k: v for k, v in payload.items() if k != "system"}
            s4, b4 = post(BASE_URL + "/metrics", no_sys, TOKEN)
            print(f"   HTTP {s4} — {b4}")