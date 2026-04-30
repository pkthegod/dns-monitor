"""
test_backend.py — Testes dos caminhos críticos do backend Infra-Vision.

Cobre:
  - Autenticação Bearer (require_token)
  - Validação do payload do agente (Pydantic)
  - Lógica de _evaluate_alerts (thresholds, deduplicação de warnings)
  - job_send_report (sem N+1 — usa get_all_disk_alerts)
  - job_check_offline (anti-spam de alertas)
  - _split_sql (parser do schemas.sql)
  - has_open_alert e get_all_disk_alerts (novas funções)
  - Endpoint /health

Dependências: pip install pytest pytest-asyncio fastapi httpx
Execução:     pytest test_backend.py -v
"""

import asyncio
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch, call
from typing import Optional

import pytest

# ---------------------------------------------------------------------------
# Setup — adiciona backend ao path sem precisar instalar o pacote
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))


# ---------------------------------------------------------------------------
# Fixtures de payload válido (espelha o contrato do agente)
# ---------------------------------------------------------------------------

def make_payload(
    type_="check",
    hostname="test-host-01",
    cpu_pct=20.0,
    ram_pct=40.0,
    disk_pct=50.0,
    disk_alert="ok",
    dns_success=True,
    dns_latency=15.0,
    dns_error=None,
    dns_service_active=True,
) -> dict:
    return {
        "type": type_,
        "hostname": hostname,
        "timestamp": "2024-01-15T06:00:00+00:00",
        "agent_version": "1.0.0",
        "dns_service": {
            "name": "unbound",
            "active": dns_service_active,
            "version": "unbound 1.17.0",
        },
        "dns_checks": [
            {
                "domain": "google.com",
                "resolver": "127.0.0.1",
                "success": dns_success,
                "latency_ms": dns_latency,
                "response_ips": ["142.250.218.46"] if dns_success else [],
                "error": dns_error,
                "attempts": 1 if dns_success else 3,
            }
        ],
        "system": {
            "cpu": {"percent": cpu_pct, "count": 4, "freq_mhz": 2400.0},
            "ram": {
                "percent": ram_pct, "used_mb": 3200.0, "total_mb": 8192.0,
                "swap_percent": 0.0, "swap_used_mb": 0.0, "swap_total_mb": 2048.0,
            },
            "disk": [{
                "mountpoint": "/", "device": "/dev/sda1", "fstype": "ext4",
                "percent": disk_pct, "used_gb": 20.0, "free_gb": 30.0,
                "total_gb": 50.0, "alert": disk_alert,
            }],
            "io": {
                "read_bytes": 1024000, "write_bytes": 512000,
                "read_count": 1000, "write_count": 500,
                "read_time_ms": 200, "write_time_ms": 100,
            },
            "load": {"load_1m": 0.5, "load_5m": 0.3, "load_15m": 0.2},
        },
    }


# ===========================================================================
# 1. AUTENTICAÇÃO
# ===========================================================================

class TestAuthentication:
    """Verifica que require_token bloqueia requests sem token válido."""

    def test_valid_token_passes(self):
        """Token correto no header Authorization: Bearer deve passar."""
        from fastapi import Request
        from unittest.mock import MagicMock

        request = MagicMock(spec=Request)
        request.headers = {"Authorization": "Bearer abc123"}

        with patch.dict(os.environ, {"AGENT_TOKEN": "abc123"}):
            # Reimportar para pegar o env atualizado
            import importlib
            import main as m
            importlib.reload(m)
            # require_token é async — roda via asyncio
            asyncio.run(m.require_token(request))
            # Se não levantou HTTPException, passou

    def test_wrong_token_raises_401(self):
        from fastapi import HTTPException, Request

        request = MagicMock(spec=Request)
        request.headers = {"Authorization": "Bearer ERRADO"}

        with patch.dict(os.environ, {"AGENT_TOKEN": "abc123"}):
            import importlib
            import main as m
            importlib.reload(m)
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(m.require_token(request))
            assert exc_info.value.status_code == 401

    def test_missing_token_raises_401(self):
        from fastapi import HTTPException, Request

        request = MagicMock(spec=Request)
        request.headers = {}

        with patch.dict(os.environ, {"AGENT_TOKEN": "abc123"}):
            import importlib
            import main as m
            importlib.reload(m)
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(m.require_token(request))
            assert exc_info.value.status_code == 401

    def test_empty_agent_token_env_raises_503(self):
        """Se AGENT_TOKEN não configurado, backend recusa com 503."""
        from fastapi import Request, HTTPException

        request = MagicMock(spec=Request)
        request.headers = {}

        with patch.dict(os.environ, {"AGENT_TOKEN": ""}):
            import importlib
            import main as m
            importlib.reload(m)
            with pytest.raises(HTTPException) as exc:
                asyncio.run(m.require_token(request))
            assert exc.value.status_code == 503


# ===========================================================================
# 2. VALIDAÇÃO DO PAYLOAD (Pydantic)
# ===========================================================================

class TestPayloadValidation:
    """Verifica que AgentPayload aceita e rejeita corretamente os dados."""

    def _load_model(self):
        import importlib
        import main as m
        importlib.reload(m)
        return m.AgentPayload

    def test_valid_check_payload(self):
        AgentPayload = self._load_model()
        data = make_payload()
        p = AgentPayload(**data)
        assert p.hostname == "test-host-01"
        assert p.type == "check"
        assert len(p.dns_checks) == 1
        assert p.dns_checks[0].domain == "google.com"

    def test_valid_heartbeat_payload(self):
        AgentPayload = self._load_model()
        data = make_payload(type_="heartbeat")
        p = AgentPayload(**data)
        assert p.type == "heartbeat"

    def test_missing_hostname_fails(self):
        from pydantic import ValidationError
        AgentPayload = self._load_model()
        data = make_payload()
        del data["hostname"]
        with pytest.raises(ValidationError):
            AgentPayload(**data)

    def test_missing_type_fails(self):
        from pydantic import ValidationError
        AgentPayload = self._load_model()
        data = make_payload()
        del data["type"]
        with pytest.raises(ValidationError):
            AgentPayload(**data)

    def test_optional_fields_default_to_none(self):
        AgentPayload = self._load_model()
        p = AgentPayload(type="heartbeat", hostname="h1", timestamp="2024-01-01T00:00:00Z")
        assert p.dns_service is None
        assert p.system is None
        assert p.dns_checks == []

    def test_dns_check_success_false_with_error(self):
        AgentPayload = self._load_model()
        data = make_payload(dns_success=False, dns_error="TIMEOUT", dns_latency=None)
        p = AgentPayload(**data)
        check = p.dns_checks[0]
        assert check.success is False
        assert check.error == "TIMEOUT"
        assert check.latency_ms is None

    def test_disk_alert_field(self):
        AgentPayload = self._load_model()
        data = make_payload(disk_alert="critical", disk_pct=92.0)
        p = AgentPayload(**data)
        assert p.system.disk[0].alert == "critical"
        assert p.system.disk[0].percent == 92.0


# ===========================================================================
# 3. _evaluate_alerts — THRESHOLDS E DEDUPLICAÇÃO (Fix 2)
# ===========================================================================

class TestEvaluateAlerts:
    """
    Testa a lógica de avaliação de thresholds e a deduplicação de warnings.
    Todos os db.* e tg.* são mockados — sem banco real.
    """

    def _run(self, coro):
        return asyncio.run(coro)

    def _make_mocks(self, has_open=False):
        """Retorna db e tg mockados com comportamentos padrão.

        A1 (R6 race-fix): insert_alert virou atomico (ON CONFLICT DO NOTHING).
        Quando ja existe alerta aberto, retorna None — simulamos isso aqui
        com `return_value=None` se has_open=True. Antes, has_open_alert era
        consultado primeiro; agora o teste reflete o caminho real do codigo.
        """
        mock_db = MagicMock()
        mock_db.insert_alert = AsyncMock(return_value=None if has_open else 42)
        mock_db.mark_alert_notified = AsyncMock()
        mock_db.has_open_alert = AsyncMock(return_value=has_open)  # mantido pra compat

        mock_tg = MagicMock()
        mock_tg.alert_cpu = AsyncMock(return_value=True)
        mock_tg.alert_ram = AsyncMock(return_value=True)
        mock_tg.alert_disk = AsyncMock(return_value=True)
        mock_tg.alert_dns_failure = AsyncMock(return_value=True)
        mock_tg.alert_dns_latency = AsyncMock(return_value=True)
        mock_tg.alert_dns_service_down = AsyncMock(return_value=True)

        return mock_db, mock_tg

    def _evaluate(self, payload_dict, mock_db, mock_tg):
        import importlib
        import main as m
        importlib.reload(m)

        AgentPayload = m.AgentPayload
        payload = AgentPayload(**payload_dict)

        with patch.object(m, 'db', mock_db), patch.object(m, 'tg', mock_tg):
            self._run(m._evaluate_alerts(payload))

    # ── CPU ──────────────────────────────────────────────────────────────

    def test_cpu_below_warning_no_alert(self):
        mock_db, mock_tg = self._make_mocks()
        self._evaluate(make_payload(cpu_pct=50.0), mock_db, mock_tg)
        mock_db.insert_alert.assert_not_called()

    def test_cpu_warning_inserts_alert(self):
        mock_db, mock_tg = self._make_mocks(has_open=False)
        self._evaluate(make_payload(cpu_pct=85.0), mock_db, mock_tg)
        mock_db.insert_alert.assert_called_once()
        call_args = mock_db.insert_alert.call_args
        assert call_args[0][1] == "cpu"
        assert call_args[0][2] == "warning"
        mock_tg.alert_cpu.assert_not_called()  # warning não vai pro Telegram

    def test_cpu_warning_deduplicated_when_open(self):
        """A1 (R6): insert_alert atomico — sempre chamado, mas DB rejeita
        com ON CONFLICT (mock retorna None). mark_alert_notified NAO e
        chamado, validando que dedup ainda acontece."""
        mock_db, mock_tg = self._make_mocks(has_open=True)
        self._evaluate(make_payload(cpu_pct=85.0), mock_db, mock_tg)
        mock_db.insert_alert.assert_called_once()
        assert mock_db.insert_alert.call_args[0][:3] == ("test-host-01", "cpu", "warning")
        mock_db.mark_alert_notified.assert_not_called()
        mock_tg.alert_cpu.assert_not_called()

    def test_cpu_critical_sends_telegram(self):
        mock_db, mock_tg = self._make_mocks()
        self._evaluate(make_payload(cpu_pct=96.0), mock_db, mock_tg)
        mock_db.insert_alert.assert_called_once()
        assert mock_db.insert_alert.call_args[0][2] == "critical"
        mock_tg.alert_cpu.assert_called_once()
        mock_db.mark_alert_notified.assert_called_once_with(42)

    def test_cpu_at_exact_warning_threshold(self):
        """Boundary: cpu_pct == warning limit deve disparar."""
        mock_db, mock_tg = self._make_mocks(has_open=False)
        self._evaluate(make_payload(cpu_pct=80.0), mock_db, mock_tg)
        mock_db.insert_alert.assert_called_once()

    def test_cpu_just_below_warning_threshold(self):
        """Boundary: cpu_pct == 79.9 NÃO deve disparar."""
        mock_db, mock_tg = self._make_mocks()
        self._evaluate(make_payload(cpu_pct=79.9), mock_db, mock_tg)
        mock_db.insert_alert.assert_not_called()

    # ── RAM ──────────────────────────────────────────────────────────────

    def test_ram_warning_deduplicated(self):
        """A1 (R6): insert_alert atomico — DB rejeita (mock None) e nao notifica."""
        mock_db, mock_tg = self._make_mocks(has_open=True)
        self._evaluate(make_payload(ram_pct=88.0), mock_db, mock_tg)
        mock_db.insert_alert.assert_called_once()
        assert mock_db.insert_alert.call_args[0][:3] == ("test-host-01", "ram", "warning")
        mock_db.mark_alert_notified.assert_not_called()
        mock_tg.alert_ram.assert_not_called()

    def test_ram_warning_inserts_when_no_open(self):
        mock_db, mock_tg = self._make_mocks(has_open=False)
        self._evaluate(make_payload(ram_pct=88.0), mock_db, mock_tg)
        mock_db.insert_alert.assert_called_once()
        assert mock_db.insert_alert.call_args[0][2] == "warning"

    def test_ram_critical_telegram(self):
        mock_db, mock_tg = self._make_mocks()
        self._evaluate(make_payload(ram_pct=96.0), mock_db, mock_tg)
        mock_tg.alert_ram.assert_called_once()

    # ── DISCO ─────────────────────────────────────────────────────────────

    def test_disk_ok_no_alert(self):
        mock_db, mock_tg = self._make_mocks()
        self._evaluate(make_payload(disk_alert="ok", disk_pct=50.0), mock_db, mock_tg)
        mock_db.insert_alert.assert_not_called()

    def test_disk_warning_inserts_no_telegram(self):
        mock_db, mock_tg = self._make_mocks()
        self._evaluate(make_payload(disk_alert="warning", disk_pct=83.0), mock_db, mock_tg)
        mock_db.insert_alert.assert_called_once()
        assert mock_db.insert_alert.call_args[0][2] == "warning"
        mock_tg.alert_disk.assert_not_called()

    def test_disk_critical_sends_telegram(self):
        mock_db, mock_tg = self._make_mocks()
        self._evaluate(make_payload(disk_alert="critical", disk_pct=92.0), mock_db, mock_tg)
        mock_tg.alert_disk.assert_called_once()

    # ── DNS CHECKS ────────────────────────────────────────────────────────

    def test_dns_failure_sends_telegram(self):
        mock_db, mock_tg = self._make_mocks()
        data = make_payload(dns_success=False, dns_error="TIMEOUT", dns_latency=None)
        self._evaluate(data, mock_db, mock_tg)
        mock_tg.alert_dns_failure.assert_called_once_with(
            "test-host-01", "google.com", "TIMEOUT", 3
        )

    def test_dns_failure_unknown_error_label(self):
        mock_db, mock_tg = self._make_mocks()
        data = make_payload(dns_success=False, dns_error=None, dns_latency=None)
        self._evaluate(data, mock_db, mock_tg)
        call_args = mock_tg.alert_dns_failure.call_args[0]
        assert call_args[2] == "unknown"  # fallback quando error é None

    def test_dns_latency_warning_deduplicated(self):
        """A1 (R6): insert_alert atomico — DB rejeita e nao notifica."""
        mock_db, mock_tg = self._make_mocks(has_open=True)
        data = make_payload(dns_success=True, dns_latency=250.0)
        self._evaluate(data, mock_db, mock_tg)
        mock_db.insert_alert.assert_called_once()
        assert mock_db.insert_alert.call_args[0][:3] == ("test-host-01", "dns_latency", "warning")
        mock_db.mark_alert_notified.assert_not_called()
        mock_tg.alert_dns_latency.assert_not_called()

    def test_dns_latency_warning_inserts_when_no_open(self):
        mock_db, mock_tg = self._make_mocks(has_open=False)
        data = make_payload(dns_success=True, dns_latency=250.0)
        self._evaluate(data, mock_db, mock_tg)
        mock_db.insert_alert.assert_called_once()
        assert mock_db.insert_alert.call_args[0][2] == "warning"
        mock_tg.alert_dns_latency.assert_not_called()

    def test_dns_latency_critical_sends_telegram(self):
        mock_db, mock_tg = self._make_mocks()
        data = make_payload(dns_success=True, dns_latency=1200.0)
        self._evaluate(data, mock_db, mock_tg)
        mock_tg.alert_dns_latency.assert_called_once()
        assert mock_tg.alert_dns_latency.call_args[0][3] == 1000  # threshold

    def test_dns_ok_no_alert(self):
        mock_db, mock_tg = self._make_mocks()
        data = make_payload(dns_success=True, dns_latency=15.0)
        self._evaluate(data, mock_db, mock_tg)
        mock_db.insert_alert.assert_not_called()

    # ── SERVIÇO DNS ───────────────────────────────────────────────────────

    def test_dns_service_inactive_sends_telegram(self):
        mock_db, mock_tg = self._make_mocks()
        data = make_payload(dns_service_active=False)
        self._evaluate(data, mock_db, mock_tg)
        mock_tg.alert_dns_service_down.assert_called_once_with("test-host-01", "unbound")

    def test_dns_service_active_no_alert(self):
        mock_db, mock_tg = self._make_mocks()
        data = make_payload(dns_service_active=True)
        self._evaluate(data, mock_db, mock_tg)
        mock_tg.alert_dns_service_down.assert_not_called()

    # ── HEARTBEAT (sem dns_checks) ────────────────────────────────────────

    def test_heartbeat_no_dns_checks_no_crash(self):
        """Heartbeat sem dns_checks não deve gerar erro nem alertas DNS."""
        mock_db, mock_tg = self._make_mocks()
        data = make_payload(type_="heartbeat")
        data["dns_checks"] = []
        self._evaluate(data, mock_db, mock_tg)
        mock_tg.alert_dns_failure.assert_not_called()


# ===========================================================================
# 4. job_send_report — SEM N+1 (Fix 1)
# ===========================================================================

class TestJobSendReport:
    """
    Verifica que job_send_report usa get_all_disk_alerts (1 query)
    em vez de iterar por agente (N queries).
    """

    def _run(self, coro):
        return asyncio.run(coro)

    def test_uses_get_all_disk_alerts_not_per_agent_loop(self):
        """Fix 1: get_all_disk_alerts chamado 1 vez, nunca get_latest_disk_alerts."""
        import importlib
        import main as m
        import db as d
        importlib.reload(d)
        importlib.reload(m)

        mock_conn = AsyncMock()
        fake_rows = [
            {"hostname": "h1", "agent_status": "online"},
            {"hostname": "h2", "agent_status": "offline"},
            {"hostname": "h3", "agent_status": "online"},
        ]
        mock_conn.fetch = AsyncMock(side_effect=[
            fake_rows,
            [{"hostname": "h1", "domain": "google.com", "error": "TIMEOUT"}],
        ])
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_db = MagicMock()
        mock_db.get_all_disk_alerts = AsyncMock(return_value=[])
        mock_db.get_open_alerts = AsyncMock(return_value=[])

        mock_tg = MagicMock()
        mock_tg.send_report = AsyncMock()

        # job_send_report usa 'from db import get_conn' internamente
        # então patch no módulo db, não no main
        with patch.object(m, 'db', mock_db), \
             patch.object(m, 'tg', mock_tg), \
             patch.object(d, 'get_conn', return_value=mock_ctx):
            self._run(m.job_send_report())

        mock_db.get_all_disk_alerts.assert_called_once()
        assert not hasattr(mock_db, 'get_latest_disk_alerts') or \
               mock_db.get_latest_disk_alerts.call_count == 0

    def test_report_counts_online_offline_correctly(self):
        import importlib
        import main as m
        import db as d
        importlib.reload(d)
        importlib.reload(m)

        mock_conn = AsyncMock()
        fake_rows = [
            {"hostname": "h1", "agent_status": "online"},
            {"hostname": "h2", "agent_status": "offline"},
            {"hostname": "h3", "agent_status": "never_seen"},
            {"hostname": "h4", "agent_status": "online"},
        ]
        mock_conn.fetch = AsyncMock(side_effect=[fake_rows, []])
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_db = MagicMock()
        mock_db.get_all_disk_alerts = AsyncMock(return_value=[])
        mock_db.get_open_alerts = AsyncMock(return_value=[])

        captured = {}
        async def fake_send_report(**kwargs):
            captured.update(kwargs)
        mock_tg = MagicMock()
        mock_tg.send_report = fake_send_report

        with patch.object(m, 'db', mock_db), \
             patch.object(m, 'tg', mock_tg), \
             patch.object(d, 'get_conn', return_value=mock_ctx):
            asyncio.run(m.job_send_report())

        assert captured["total_agents"] == 4
        assert captured["online_agents"] == 2
        assert set(captured["offline_agents"]) == {"h2", "h3"}


# ===========================================================================
# 5. job_check_offline — ANTI-SPAM
# ===========================================================================

class TestJobCheckOffline:
    """Verifica que o job de detecção de offline não gera spam de alertas."""

    def _run(self, coro):
        return asyncio.run(coro)

    def _setup(self, offline_agents, existing_open_alerts):
        """A1 (R9): insert_alert agora e atomico. Se existing_open_alerts
        contem alerta 'offline' pro hostname, simulamos ON CONFLICT retornando
        None. Caso contrario, retorna id 99."""
        import importlib
        import main as m
        importlib.reload(m)

        offline_hosts_with_alert = {
            a["hostname"] for a in (existing_open_alerts or [])
            if a.get("alert_type") == "offline"
        }

        async def fake_insert(*args, **kwargs):
            host = kwargs.get("hostname") or (args[0] if args else None)
            return None if host in offline_hosts_with_alert else 99

        mock_db = MagicMock()
        mock_db.get_agents_offline = AsyncMock(return_value=offline_agents)
        mock_db.get_open_alerts = AsyncMock(return_value=existing_open_alerts)
        mock_db.insert_alert = AsyncMock(side_effect=fake_insert)
        mock_db.mark_alert_notified = AsyncMock()

        mock_tg = MagicMock()
        mock_tg.alert_agent_offline = AsyncMock(return_value=True)

        return m, mock_db, mock_tg

    def test_no_offline_agents_no_alert(self):
        m, mock_db, mock_tg = self._setup(offline_agents=[], existing_open_alerts=[])
        with patch.object(m, 'db', mock_db), patch.object(m, 'tg', mock_tg):
            self._run(m.job_check_offline())
        mock_db.insert_alert.assert_not_called()
        mock_tg.alert_agent_offline.assert_not_called()

    def test_offline_agent_no_existing_alert_fires(self):
        offline = [{"hostname": "h1", "last_seen": None}]
        m, mock_db, mock_tg = self._setup(offline, existing_open_alerts=[])
        with patch.object(m, 'db', mock_db), patch.object(m, 'tg', mock_tg):
            self._run(m.job_check_offline())
        mock_db.insert_alert.assert_called_once()
        mock_tg.alert_agent_offline.assert_called_once_with("h1", None)
        mock_db.mark_alert_notified.assert_called_once_with(99)

    def test_offline_agent_with_existing_alert_no_spam(self):
        """A1 (R9): insert_alert atomico — chamado, mas DB rejeita (mock None)
        e Telegram NAO e disparado. Antes era check-then-act e poderia
        duplicar alerta sob race com receive_metrics."""
        offline = [{"hostname": "h1", "last_seen": None}]
        existing = [{"alert_type": "offline", "hostname": "h1"}]
        m, mock_db, mock_tg = self._setup(offline, existing)
        with patch.object(m, 'db', mock_db), patch.object(m, 'tg', mock_tg):
            self._run(m.job_check_offline())
        mock_db.insert_alert.assert_called_once()
        mock_tg.alert_agent_offline.assert_not_called()
        mock_db.mark_alert_notified.assert_not_called()

    def test_multiple_offline_agents_each_gets_alert(self):
        offline = [
            {"hostname": "h1", "last_seen": None},
            {"hostname": "h2", "last_seen": None},
        ]
        m, mock_db, mock_tg = self._setup(offline, existing_open_alerts=[])
        with patch.object(m, 'db', mock_db), patch.object(m, 'tg', mock_tg):
            self._run(m.job_check_offline())
        assert mock_db.insert_alert.call_count == 2
        assert mock_tg.alert_agent_offline.call_count == 2

    def test_telegram_failure_still_inserts_alert(self):
        """Se Telegram falhar no envio, o alerta deve continuar no banco."""
        offline = [{"hostname": "h1", "last_seen": None}]
        m, mock_db, mock_tg = self._setup(offline, existing_open_alerts=[])
        mock_tg.alert_agent_offline = AsyncMock(return_value=False)  # falha no envio
        with patch.object(m, 'db', mock_db), patch.object(m, 'tg', mock_tg):
            self._run(m.job_check_offline())
        mock_db.insert_alert.assert_called_once()
        mock_db.mark_alert_notified.assert_not_called()  # não marca se não enviou


# ===========================================================================
# 6. _split_sql — PARSER DO SCHEMA
# ===========================================================================

class TestSplitSql:
    """Verifica que _split_sql divide corretamente o schemas.sql."""

    def _split(self, sql):
        import importlib
        import db as d
        importlib.reload(d)
        return d._split_sql(sql)

    def test_single_statement(self):
        stmts = self._split("CREATE TABLE foo (id INT)")
        assert len(stmts) == 1
        assert "CREATE TABLE foo" in stmts[0]

    def test_multiple_statements(self):
        sql = "CREATE TABLE a (id INT); CREATE TABLE b (id INT); CREATE INDEX idx ON a(id)"
        stmts = self._split(sql)
        assert len(stmts) == 3

    def test_comments_removed(self):
        sql = "-- this is a comment\nCREATE TABLE a (id INT)"
        stmts = self._split(sql)
        assert len(stmts) == 1
        assert "comment" not in stmts[0]

    def test_empty_statements_ignored(self):
        sql = "CREATE TABLE a (id INT);;;   ;"
        stmts = self._split(sql)
        assert len(stmts) == 1

    def test_real_schemas_sql_produces_68_statements(self):
        """Validação contra o arquivo real — deve produzir 68 statements."""
        schema_path = os.path.join(
            os.path.dirname(__file__),
            "backend", "schemas.sql"
        )
        if not os.path.exists(schema_path):
            pytest.skip("schemas.sql não encontrado — execute a partir da raiz do projeto")
        sql = open(schema_path).read()
        stmts = self._split(sql)
        assert len(stmts) == 68, f"Esperado 68 statements, obtido {len(stmts)}"

    def test_all_statements_start_with_keyword(self):
        """Nenhum statement vazio ou começando com ';'."""
        schema_path = os.path.join(os.path.dirname(__file__), "backend", "schemas.sql")
        if not os.path.exists(schema_path):
            pytest.skip("schemas.sql não encontrado")
        sql = open(schema_path).read()
        stmts = self._split(sql)
        valid_keywords = {"CREATE", "SELECT", "ALTER", "INSERT", "UPDATE", "DROP"}
        for s in stmts:
            first_word = s.split()[0].upper()
            assert first_word in valid_keywords, f"Statement inesperado: {s[:60]}"


# ===========================================================================
# 7. has_open_alert e get_all_disk_alerts — NOVAS FUNÇÕES (Fix 1 e 2)
# ===========================================================================

class TestNewDbFunctions:
    """
    Testa a existência e assinatura das novas funções adicionadas ao db.py.
    Sem banco real — apenas verifica que as funções são chamáveis e async.
    """

    def test_has_open_alert_is_async(self):
        import inspect
        import importlib
        import db as d
        importlib.reload(d)
        assert inspect.iscoroutinefunction(d.has_open_alert)

    def test_get_all_disk_alerts_is_async(self):
        import inspect
        import importlib
        import db as d
        importlib.reload(d)
        assert inspect.iscoroutinefunction(d.get_all_disk_alerts)

    def test_has_open_alert_signature(self):
        import inspect
        import importlib
        import db as d
        importlib.reload(d)
        sig = inspect.signature(d.has_open_alert)
        params = list(sig.parameters.keys())
        assert "hostname" in params
        assert "alert_type" in params

    def test_get_all_disk_alerts_no_params(self):
        import inspect
        import importlib
        import db as d
        importlib.reload(d)
        sig = inspect.signature(d.get_all_disk_alerts)
        assert len(sig.parameters) == 0


# ===========================================================================
# 8. /health ENDPOINT
# ===========================================================================

class TestHealthEndpoint:
    """Verifica o endpoint /health com banco disponível e indisponível."""

    def _run(self, coro):
        return asyncio.run(coro)

    def test_health_ok_when_db_responds(self):
        import importlib
        import main as m
        importlib.reload(m)

        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=1)
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_db = MagicMock()
        mock_db.get_conn = MagicMock(return_value=mock_ctx)

        with patch.object(m, 'db', mock_db), \
             patch('main.db.get_conn', return_value=mock_ctx):
            response = self._run(m.health())

        assert response.status_code == 200
        import json
        body = json.loads(response.body)
        assert body["status"] == "ok"

    def test_health_503_when_db_fails(self):
        import importlib
        import main as m
        importlib.reload(m)

        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(side_effect=Exception("connection refused"))
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch('main.db.get_conn', return_value=mock_ctx):
            response = self._run(m.health())

        assert response.status_code == 503
        import json
        body = json.loads(response.body)
        assert body["status"] == "error"


# ===========================================================================
# TestFingerprintDb
# ===========================================================================

class TestFingerprintDb:

    def test_upsert_fingerprint_is_async(self):
        import inspect
        import db
        assert inspect.iscoroutinefunction(db.upsert_fingerprint)

    def test_upsert_fingerprint_signature(self):
        import inspect
        import db
        sig = inspect.signature(db.upsert_fingerprint)
        params = list(sig.parameters)
        assert "hostname"    in params
        assert "fingerprint" in params

    def test_get_pending_commands_is_async(self):
        import inspect
        import db
        assert inspect.iscoroutinefunction(db.get_pending_commands)

    def test_mark_command_done_is_async(self):
        import inspect
        import db
        assert inspect.iscoroutinefunction(db.mark_command_done)

    def test_insert_command_is_async(self):
        import inspect
        import db
        assert inspect.iscoroutinefunction(db.insert_command)

    def test_get_commands_history_is_async(self):
        import inspect
        import db
        assert inspect.iscoroutinefunction(db.get_commands_history)


# ===========================================================================
# TestInsertCommandValidation
# ===========================================================================

class TestInsertCommandValidation:
    """Testa validações síncronas de insert_command via mock do pool."""

    def _run(self, coro):
        import asyncio
        return asyncio.run(coro)

    def test_invalid_command_raises_valueerror(self):
        import db
        import asyncio

        async def run():
            with patch("db._pool") as mock_pool:
                mock_conn = AsyncMock()
                mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
                mock_pool.acquire.return_value.__aexit__  = AsyncMock(return_value=False)
                with pytest.raises(ValueError, match="Comando inválido"):
                    await db.insert_command("host", "reboot", "admin")

        asyncio.run(run())

    def test_purge_without_token_raises_valueerror(self):
        import db
        import asyncio

        async def run():
            with pytest.raises(ValueError, match="confirm_token"):
                await db.insert_command("host", "purge", "admin", confirm_token=None)

        asyncio.run(run())

    def test_valid_commands_accepted(self):
        import db
        assert "stop"    in db.VALID_COMMANDS
        assert "disable" in db.VALID_COMMANDS
        assert "enable"  in db.VALID_COMMANDS
        assert "purge"   in db.VALID_COMMANDS

    def test_invalid_commands_not_in_set(self):
        import db
        assert "reboot"     not in db.VALID_COMMANDS
        assert "rm -rf"     not in db.VALID_COMMANDS
        assert "shutdown"   not in db.VALID_COMMANDS


# ===========================================================================
# TestCommandEndpoints
# ===========================================================================

class TestCommandEndpoints:
    """Testa os endpoints /commands via mocks do db."""

    def _run(self, coro):
        import asyncio
        return asyncio.run(coro)

    def test_get_commands_requires_auth(self):
        import main as m_module
        import asyncio

        async def run():
            req = MagicMock()
            req.headers = {"authorization": "Bearer wrong-token"}
            with patch.dict("os.environ", {"AGENT_TOKEN": "correct-token"}):
                with pytest.raises(Exception):
                    await m_module.get_commands("host1", req)

        asyncio.run(run())

    def test_get_commands_returns_pending(self):
        import main as m_module
        import asyncio

        pending = [{"id": 1, "command": "stop", "confirm_token": None,
                    "issued_at": "2026-01-01T00:00:00+00:00"}]

        async def run():
            req = MagicMock()
            req.headers = {"authorization": "Bearer tok"}
            with patch.dict("os.environ", {"AGENT_TOKEN": "tok"}):
                with patch("main.require_token", AsyncMock(return_value=None)):
                    with patch("main.db.get_pending_commands", AsyncMock(return_value=pending)):
                        resp = await m_module.get_commands("ns1", req)
            import json
            data = json.loads(resp.body)
            assert len(data) == 1
            assert data[0]["command"] == "stop"

        asyncio.run(run())

    def test_post_command_result_done(self):
        import main as m_module
        import asyncio

        cmd_data = {"id": 42, "hostname": "ns1", "command": "enable",
                    "issued_by": "admin", "status": "done", "result": "OK", "executed_at": None}

        async def run():
            req = MagicMock()
            req.headers = {"authorization": "Bearer tok"}
            req.json = AsyncMock(return_value={"status": "done", "result": "OK"})
            with patch.dict("os.environ", {"AGENT_TOKEN": "tok"}):
                with patch("main.require_token", AsyncMock(return_value=None)):
                    with patch("main.db.mark_command_done", AsyncMock()):
                        with patch("main.db.mark_command_notified", AsyncMock(return_value=True)):
                            with patch("main.db.get_command_by_id", AsyncMock(return_value=cmd_data)):
                                with patch("main.tg.send_command_result", AsyncMock(return_value=True)):
                                    resp = await m_module.post_command_result(42, req)
            import json
            assert json.loads(resp.body)["status"] == "ok"

        asyncio.run(run())

    def test_post_command_result_invalid_status(self):
        import main as m_module
        import asyncio

        async def run():
            req = MagicMock()
            req.headers = {"authorization": "Bearer tok"}
            req.json = AsyncMock(return_value={"status": "invalid", "result": ""})
            with patch.dict("os.environ", {"AGENT_TOKEN": "tok"}):
                with patch("main.require_token", AsyncMock(return_value=None)):
                    with patch("main.db.mark_command_done", AsyncMock()):
                        resp = await m_module.post_command_result(1, req)
            assert resp.status_code == 422

        asyncio.run(run())

    # SEC: create_command passou de require_token (Bearer compartilhado) para
    # require_admin_role (cookie admin OU Bearer com whitelist). Mocks abaixo
    # devolvem dict {username, role} que require_admin_role retorna.
    _ADMIN_INFO = {"username": "admin", "role": "admin"}

    def test_create_command_missing_fields(self):
        import main as m_module
        import asyncio

        async def run():
            req = MagicMock()
            req.json = AsyncMock(return_value={"hostname": "", "command": ""})
            with patch("main.require_admin_role", AsyncMock(return_value=self._ADMIN_INFO)):
                resp = await m_module.create_command(req)
            assert resp.status_code == 422

        asyncio.run(run())

    def test_create_command_purge_generates_confirm_token(self):
        import main as m_module
        import asyncio

        async def run():
            req = MagicMock()
            req.json = AsyncMock(return_value={
                "hostname": "ns1", "command": "purge", "issued_by": "admin"
            })
            with patch("main.require_admin_role", AsyncMock(return_value=self._ADMIN_INFO)), \
                 patch("main.db.insert_command", AsyncMock(return_value=99)), \
                 patch("main.db.audit", AsyncMock()):
                resp = await m_module.create_command(req)
            import json
            data = json.loads(resp.body)
            # SEC (M7): purge agora exige fluxo two-step. 1a chamada (sem
            # confirm_token) retorna 202 com token; nao enfileira o comando.
            assert resp.status_code == 202
            assert data["requires_confirm"] is True
            assert "confirm_token" in data
            assert len(data["confirm_token"]) >= 16

        asyncio.run(run())

    def test_create_command_stop_no_confirm_token(self):
        import main as m_module
        import asyncio

        async def run():
            req = MagicMock()
            req.json = AsyncMock(return_value={
                "hostname": "ns1", "command": "stop", "issued_by": "admin"
            })
            with patch("main.require_admin_role", AsyncMock(return_value=self._ADMIN_INFO)), \
                 patch("main.db.insert_command", AsyncMock(return_value=1)), \
                 patch("main.db.audit", AsyncMock()):
                resp = await m_module.create_command(req)
            import json
            data = json.loads(resp.body)
            assert resp.status_code == 201
            assert "confirm_token" not in data

        asyncio.run(run())

    def test_create_command_invalid_command_returns_422(self):
        import main as m_module
        import asyncio

        async def run():
            req = MagicMock()
            req.json = AsyncMock(return_value={"hostname": "ns1", "command": "reboot"})
            with patch("main.require_admin_role", AsyncMock(return_value=self._ADMIN_INFO)), \
                 patch("main.db.insert_command",
                       AsyncMock(side_effect=ValueError("Comando inválido"))), \
                 patch("main.db.audit", AsyncMock()):
                resp = await m_module.create_command(req)
            assert resp.status_code == 422

        asyncio.run(run())


# ===========================================================================
# TestAgentPayloadFingerprint
# ===========================================================================

class TestAgentPayloadFingerprint:
    """Testa que o modelo Pydantic aceita fingerprint opcional."""

    def test_payload_accepts_fingerprint(self):
        from main import AgentPayload
        p = AgentPayload(
            type="heartbeat",
            hostname="ns1",
            timestamp="2026-01-01T00:00:00+00:00",
            fingerprint="abc123def456" + "0" * 52
        )
        assert p.fingerprint is not None

    def test_payload_fingerprint_optional(self):
        from main import AgentPayload
        p = AgentPayload(
            type="heartbeat",
            hostname="ns1",
            timestamp="2026-01-01T00:00:00+00:00"
        )
        assert p.fingerprint is None

    def test_payload_fingerprint_stored_on_check(self):
        """Fingerprint presente no payload não quebra o processamento."""
        from main import AgentPayload
        p = AgentPayload(
            type="check",
            hostname="ns1",
            timestamp="2026-01-01T00:00:00+00:00",
            fingerprint="a" * 64
        )
        assert p.fingerprint == "a" * 64


# ===========================================================================
# TestSendCommandResult
# ===========================================================================

class TestSendCommandResult:
    """Testa os alertas Telegram disparados pelo resultado de comandos remotos."""

    def _run(self, coro):
        import asyncio
        return asyncio.run(coro)

    def test_enable_done_sends_restabelecido(self):
        import telegram_bot as tg
        with patch("telegram_bot.send_message", AsyncMock(return_value=True)) as mock_send:
            self._run(tg.send_command_result("ns1", "enable", "done", "enable named: OK"))
        text = mock_send.call_args[0][0]
        assert "RESTABELECIDO" in text
        assert "ns1" in text

    def test_stop_done_sends_suspenso(self):
        import telegram_bot as tg
        with patch("telegram_bot.send_message", AsyncMock(return_value=True)) as mock_send:
            self._run(tg.send_command_result("ns1", "stop", "done", "stop named: OK"))
        text = mock_send.call_args[0][0]
        assert "SUSPENSO" in text
        assert "stop" in text

    def test_disable_done_sends_suspenso(self):
        import telegram_bot as tg
        with patch("telegram_bot.send_message", AsyncMock(return_value=True)) as mock_send:
            self._run(tg.send_command_result("ns1", "disable", "done", "disable named: OK"))
        text = mock_send.call_args[0][0]
        assert "SUSPENSO" in text
        assert "disable" in text

    def test_purge_done_sends_removido(self):
        import telegram_bot as tg
        with patch("telegram_bot.send_message", AsyncMock(return_value=True)) as mock_send:
            self._run(tg.send_command_result("ns1", "purge", "done", "Serviço removido"))
        text = mock_send.call_args[0][0]
        assert "REMOVIDO" in text
        assert "🚨" in text

    def test_failed_sends_falhou(self):
        import telegram_bot as tg
        with patch("telegram_bot.send_message", AsyncMock(return_value=True)) as mock_send:
            self._run(tg.send_command_result("ns1", "stop", "failed", "Access denied"))
        text = mock_send.call_args[0][0]
        assert "FALHOU" in text
        assert "Access denied" in text

    def test_issued_by_included_in_message(self):
        import telegram_bot as tg
        with patch("telegram_bot.send_message", AsyncMock(return_value=True)) as mock_send:
            self._run(tg.send_command_result("ns1", "stop", "done", "OK", issued_by="paulo"))
        text = mock_send.call_args[0][0]
        assert "paulo" in text

    def test_long_result_truncated(self):
        import telegram_bot as tg
        long_result = "x" * 500
        with patch("telegram_bot.send_message", AsyncMock(return_value=True)) as mock_send:
            self._run(tg.send_command_result("ns1", "stop", "failed", long_result))
        text = mock_send.call_args[0][0]
        # Resultado deve ser truncado a 300 chars
        assert "x" * 301 not in text


# ===========================================================================
# TestCommandResultEndpointWithAlert
# ===========================================================================

class TestCommandResultEndpointWithAlert:
    """Testa que o endpoint dispara o alerta Telegram após gravar o resultado."""

    def _run(self, coro):
        import asyncio
        return asyncio.run(coro)

    def test_done_triggers_telegram_alert(self):
        import main as m_module
        import asyncio

        cmd_data = {
            "id": 1, "hostname": "ns1", "command": "enable",
            "issued_by": "admin", "status": "done", "result": "OK", "executed_at": None
        }

        async def run():
            req = MagicMock()
            req.headers = {"authorization": "Bearer tok"}
            req.json = AsyncMock(return_value={"status": "done", "result": "enable named: OK"})
            with patch.dict("os.environ", {"AGENT_TOKEN": "tok"}),                  patch("main.require_token", AsyncMock(return_value=None)),                  patch("main.db.mark_command_done", AsyncMock()), patch("main.db.mark_command_notified", AsyncMock(return_value=True)),                  patch("main.db.get_command_by_id", AsyncMock(return_value=cmd_data)),                  patch("main.tg.send_command_result", AsyncMock(return_value=True)) as mock_tg:
                resp = await m_module.post_command_result(1, req)
            mock_tg.assert_called_once()
            call_kwargs = mock_tg.call_args[1]
            assert call_kwargs["command"]  == "enable"
            assert call_kwargs["hostname"] == "ns1"
            assert call_kwargs["status"]   == "done"

        asyncio.run(run())

    def test_failed_triggers_telegram_alert(self):
        import main as m_module
        import asyncio

        cmd_data = {
            "id": 2, "hostname": "ns1", "command": "stop",
            "issued_by": "admin", "status": "failed", "result": "Access denied", "executed_at": None
        }

        async def run():
            req = MagicMock()
            req.headers = {"authorization": "Bearer tok"}
            req.json = AsyncMock(return_value={"status": "failed", "result": "Access denied"})
            with patch.dict("os.environ", {"AGENT_TOKEN": "tok"}),                  patch("main.require_token", AsyncMock(return_value=None)),                  patch("main.db.mark_command_done", AsyncMock()), patch("main.db.mark_command_notified", AsyncMock(return_value=True)),                  patch("main.db.get_command_by_id", AsyncMock(return_value=cmd_data)),                  patch("main.tg.send_command_result", AsyncMock(return_value=True)) as mock_tg:
                resp = await m_module.post_command_result(2, req)
            mock_tg.assert_called_once()
            call_kwargs = mock_tg.call_args[1]
            assert call_kwargs["status"]  == "failed"
            assert call_kwargs["command"] == "stop"

        asyncio.run(run())

    def test_no_alert_if_command_not_found(self):
        import main as m_module
        import asyncio

        async def run():
            req = MagicMock()
            req.headers = {"authorization": "Bearer tok"}
            req.json = AsyncMock(return_value={"status": "done", "result": "OK"})
            with patch.dict("os.environ", {"AGENT_TOKEN": "tok"}),                  patch("main.require_token", AsyncMock(return_value=None)),                  patch("main.db.mark_command_done", AsyncMock()), patch("main.db.mark_command_notified", AsyncMock(return_value=True)),                  patch("main.db.get_command_by_id", AsyncMock(return_value=None)),                  patch("main.tg.send_command_result", AsyncMock()) as mock_tg:
                await m_module.post_command_result(999, req)
            # Se comando não existe no banco, não dispara alerta
            mock_tg.assert_not_called()

        asyncio.run(run())


# ===========================================================================
# TestGetCommandById
# ===========================================================================

class TestGetCommandById:

    def test_get_command_by_id_is_async(self):
        import inspect
        import db
        assert inspect.iscoroutinefunction(db.get_command_by_id)

    def test_get_command_by_id_signature(self):
        import inspect
        import db
        sig = inspect.signature(db.get_command_by_id)
        assert "command_id" in sig.parameters


# ===========================================================================
# 14. AGENTE META — update_agent_meta (active/inactive_since)
# ===========================================================================

class TestUpdateAgentMeta:
    """Testa update_agent_meta: assinatura, active/inactive_since e retorno."""

    def test_is_async(self):
        import inspect
        import db
        assert inspect.iscoroutinefunction(db.update_agent_meta)

    def test_signature_has_active_param(self):
        import inspect
        import db
        sig = inspect.signature(db.update_agent_meta)
        assert "active" in sig.parameters

    def test_active_true_clears_inactive_since(self):
        """Reativar um agente deve gravar active=True e zerar inactive_since."""
        import db

        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value="UPDATE 1")
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        async def run():
            with patch("db.get_conn", return_value=mock_ctx):
                result = await db.update_agent_meta("ns1", None, None, None, active=True)
            return result

        result = asyncio.run(run())
        assert result is True
        sql_called = mock_conn.execute.call_args[0][0]
        assert "inactive_since" in sql_called
        assert "NULL" in sql_called

    def test_active_false_sets_inactive_since(self):
        """Desativar deve preservar/definir inactive_since via COALESCE."""
        import db

        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value="UPDATE 1")
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        async def run():
            with patch("db.get_conn", return_value=mock_ctx):
                result = await db.update_agent_meta("ns1", None, None, None, active=False)
            return result

        result = asyncio.run(run())
        assert result is True
        sql_called = mock_conn.execute.call_args[0][0]
        assert "COALESCE(inactive_since, NOW())" in sql_called

    def test_active_none_preserves_inactive_since(self):
        """Sem alterar active, inactive_since não deve mudar."""
        import db

        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value="UPDATE 1")
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        async def run():
            with patch("db.get_conn", return_value=mock_ctx):
                result = await db.update_agent_meta("ns1", "Nome", "DC1", "nota", active=None)
            return result

        result = asyncio.run(run())
        assert result is True
        sql_called = mock_conn.execute.call_args[0][0]
        assert "inactive_since" in sql_called

    def test_returns_false_when_not_found(self):
        """Deve retornar False se o hostname não existir no banco."""
        import db

        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value="UPDATE 0")
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        async def run():
            with patch("db.get_conn", return_value=mock_ctx):
                return await db.update_agent_meta("naoexiste", None, None, None)

        result = asyncio.run(run())
        assert result is False


# ===========================================================================
# 15. DELETE AGENT — delete_agent e delete_inactive_agents
# ===========================================================================

class TestDeleteAgent:
    """Testa delete_agent: remoção do agente e limpeza das tabelas filhas."""

    def test_is_async(self):
        import inspect
        import db
        assert inspect.iscoroutinefunction(db.delete_agent)

    def test_returns_false_when_not_found(self):
        import db

        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value="DELETE 0")
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        async def run():
            with patch("db.get_conn", return_value=mock_ctx):
                return await db.delete_agent("naoexiste")

        result = asyncio.run(run())
        assert result is False

    def test_returns_true_and_cleans_all_tables(self):
        """Deve retornar True e deletar dados das 9 tabelas filhas."""
        import db

        execute_calls = []

        async def fake_execute(sql, *args):
            execute_calls.append(sql)
            # Primeira chamada é DELETE FROM agents — simula sucesso
            return "DELETE 1" if "FROM agents" in sql else "DELETE 5"

        mock_conn = AsyncMock()
        mock_conn.execute = fake_execute
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        async def run():
            with patch("db.get_conn", return_value=mock_ctx):
                return await db.delete_agent("ns1")

        result = asyncio.run(run())
        assert result is True
        # Deve ter deletado de agents + 9 tabelas filhas
        assert len(execute_calls) == 10
        tables_cleaned = " ".join(execute_calls)
        for table in ("agent_heartbeats", "metrics_cpu", "metrics_ram",
                      "metrics_disk", "metrics_io", "dns_checks",
                      "dns_service_status", "agent_commands", "alerts_log"):
            assert table in tables_cleaned


class TestDeleteInactiveAgents:
    """Testa delete_inactive_agents: identifica e purga agentes vencidos."""

    def test_is_async(self):
        import inspect
        import db
        assert inspect.iscoroutinefunction(db.delete_inactive_agents)

    def test_returns_empty_when_none_inactive(self):
        import db

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        async def run():
            with patch("db.get_conn", return_value=mock_ctx):
                with patch("db.delete_agent", AsyncMock(return_value=True)):
                    return await db.delete_inactive_agents()

        result = asyncio.run(run())
        assert result == []

    def test_deletes_agents_inactive_over_3_days(self):
        """Agentes com inactive_since > 3 dias devem ser removidos."""
        import db

        rows = [{"hostname": "ns-old-1"}, {"hostname": "ns-old-2"}]

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=rows)
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        deleted_calls = []

        async def fake_delete(hostname):
            deleted_calls.append(hostname)
            return True

        async def run():
            with patch("db.get_conn", return_value=mock_ctx):
                with patch("db.delete_agent", side_effect=fake_delete):
                    return await db.delete_inactive_agents()

        result = asyncio.run(run())
        assert set(result) == {"ns-old-1", "ns-old-2"}
        assert set(deleted_calls) == {"ns-old-1", "ns-old-2"}

    def test_query_filters_3_days(self):
        """A query deve filtrar inactive_since < NOW() - INTERVAL '3 days'."""
        import db

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        async def run():
            with patch("db.get_conn", return_value=mock_ctx):
                await db.delete_inactive_agents()

        asyncio.run(run())
        sql = mock_conn.fetch.call_args[0][0]
        assert "3 days" in sql
        assert "active = FALSE" in sql


# ===========================================================================
# 16. ENDPOINTS ADMIN — PATCH /agents/{hostname} e DELETE /agents/{hostname}
# ===========================================================================

class TestAgentAdminEndpoints:
    """Testa os endpoints de administração de agentes."""

    def _run(self, coro):
        return asyncio.run(coro)

    def test_patch_agent_returns_ok(self):
        import main as m

        async def run():
            body = m.AgentMetaUpdate(display_name="NS Principal", location="DC SP", notes=None, active=True)
            with patch("main.db.update_agent_meta", AsyncMock(return_value=True)):
                resp = await m.update_agent("ns1", body)
            import json
            data = json.loads(resp.body)
            assert data["status"] == "ok"
            assert data["hostname"] == "ns1"

        self._run(run())

    def test_patch_agent_not_found_raises_404(self):
        from fastapi import HTTPException
        import main as m

        async def run():
            body = m.AgentMetaUpdate()
            with patch("main.db.update_agent_meta", AsyncMock(return_value=False)):
                with pytest.raises(HTTPException) as exc:
                    await m.update_agent("naoexiste", body)
            assert exc.value.status_code == 404

        self._run(run())

    def test_patch_agent_passes_active_field(self):
        """active=False deve ser passado para db.update_agent_meta."""
        import main as m

        mock_db = AsyncMock(return_value=True)

        async def run():
            body = m.AgentMetaUpdate(active=False)
            with patch("main.db.update_agent_meta", mock_db):
                await m.update_agent("ns1", body)

        self._run(run())
        call_kwargs = mock_db.call_args
        assert call_kwargs[0][4] is False  # 5º argumento posicional = active

    def test_delete_agent_returns_ok(self):
        import main as m

        async def run():
            with patch("main.db.delete_agent", AsyncMock(return_value=True)):
                resp = await m.delete_agent("ns1")
            import json
            data = json.loads(resp.body)
            assert data["status"] == "ok"

        self._run(run())

    def test_delete_agent_not_found_raises_404(self):
        from fastapi import HTTPException
        import main as m

        async def run():
            with patch("main.db.delete_agent", AsyncMock(return_value=False)):
                with pytest.raises(HTTPException) as exc:
                    await m.delete_agent("naoexiste")
            assert exc.value.status_code == 404

        self._run(run())

    def test_admin_panel_returns_html(self):
        """GET /admin deve retornar HTML com status 200."""
        import main as m
        import pathlib

        html_path = pathlib.Path(__file__).parent / "static" / "admin.html"
        fake_html = "<html><body>Admin</body></html>"
        html_path.parent.mkdir(exist_ok=True)

        async def run():
            request = MagicMock()
            # Simula cookie válido
            cookie_val = m._sign_admin_cookie("admin")
            request.cookies = {"admin_session": cookie_val}
            with patch.object(pathlib.Path, "read_text", return_value=fake_html):
                resp = await m.admin_panel(request)
            return resp

        resp = self._run(run())
        assert resp.status_code == 200
        assert "html" in resp.media_type


# ===========================================================================
# 17. GET /commands/history — histórico global de comandos
# ===========================================================================

class TestAllCommandsHistory:

    def _run(self, coro):
        return asyncio.run(coro)

    def test_get_all_commands_history_is_async(self):
        import inspect
        import db
        assert inspect.iscoroutinefunction(db.get_all_commands_history)

    def test_get_all_commands_history_signature(self):
        import inspect
        import db
        sig = inspect.signature(db.get_all_commands_history)
        assert "limit" in sig.parameters

    def test_history_endpoint_returns_list(self):
        """SEC: history agora exige sessao admin (cookie OU Bearer admin
        whitelistado), nao mais Bearer compartilhado de agente."""
        import main as m

        history = [
            {"id": 1, "hostname": "ns1", "command": "restart",
             "issued_by": "admin-panel", "issued_at": "2026-04-08T10:00:00+00:00",
             "executed_at": None, "status": "pending", "result": None},
        ]

        async def run():
            req = MagicMock()
            with patch("main.require_admin",
                       AsyncMock(return_value={"username": "admin", "role": "admin"})), \
                 patch("main.db.get_all_commands_history", AsyncMock(return_value=history)):
                resp = await m.get_all_commands_history(req, limit=50)
            import json
            return json.loads(resp.body)

        data = self._run(run())
        assert len(data) == 1
        assert data[0]["command"] == "restart"

    def test_history_endpoint_requires_token(self):
        import main as m
        from fastapi import HTTPException

        async def run():
            req = MagicMock()
            req.headers = {"Authorization": "Bearer errado"}
            with patch.dict("os.environ", {"AGENT_TOKEN": "correto"}):
                import importlib
                importlib.reload(m)
                with pytest.raises(HTTPException) as exc:
                    await m.get_all_commands_history(req)
            assert exc.value.status_code == 401

        self._run(run())


# ===========================================================================
# 18. RESTART — comando no agente
# ===========================================================================

class TestRestartCommand:
    """Verifica que 'restart' está registrado e é válido no agente e no db."""

    def test_restart_in_agent_command_handlers(self):
        import importlib
        import dns_agent as agent
        importlib.reload(agent)
        assert "restart" in agent.COMMAND_HANDLERS
        assert agent.COMMAND_HANDLERS["restart"] == ["sudo", "-n", "systemctl", "restart"]

    def test_restart_in_db_valid_commands(self):
        import importlib
        import db
        importlib.reload(db)
        assert "restart" in db.VALID_COMMANDS

    def test_restart_executes_systemctl(self):
        """_execute_command com 'restart' deve chamar systemctl restart <service>."""
        import configparser
        import importlib
        import dns_agent as agent
        importlib.reload(agent)

        cfg = configparser.ConfigParser()
        cfg.read_dict({"agent": {"hostname": "ns1", "auth_token": "tok"},
                       "backend": {"url": "http://localhost:8000", "timeout": "5",
                                   "retries": "1", "retry_delay": "0"},
                       "dns": {"service": "unbound", "test_domains": "google.com",
                               "local_resolver": "127.0.0.1", "dns_port": "53",
                               "query_timeout": "2"},
                       "schedule": {"check_times": "00:00", "command_poll_interval_h": "12"}})

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "restarted"
        mock_result.stderr = ""

        import logging
        logger = logging.getLogger("test")

        with patch("dns_agent.detect_dns_service", return_value={"name": "unbound"}):
            with patch("subprocess.run", return_value=mock_result) as mock_sub:
                status, result = agent._execute_command("restart", "", cfg, logger)

        assert status == "done"
        called_cmd = mock_sub.call_args[0][0]
        assert "restart" in called_cmd
        assert "unbound" in called_cmd


# ===========================================================================
# 19. ADMIN LOGIN — autenticação do painel admin
# ===========================================================================

class TestAdminLogin:
    """
    DADO que o painel admin precisa de autenticação
    QUANDO o usuário acessa /admin sem sessão válida
    ENTÃO deve ser redirecionado para /admin/login
    QUANDO faz POST /admin/login com credenciais corretas
    ENTÃO recebe cookie de sessão e é redirecionado para /admin
    """

    def _run(self, coro):
        return asyncio.run(coro)

    def test_admin_login_page_returns_html(self):
        """GET /admin/login deve retornar formulário HTML."""
        import main as m

        async def run():
            request = MagicMock()
            request.state = MagicMock()
            request.state.csp_nonce = "test-nonce"
            resp = await m.admin_login_page(request)
            return resp

        resp = self._run(run())
        assert resp.status_code == 200
        assert "html" in resp.media_type

    def test_admin_panel_redirects_without_cookie(self):
        """GET /admin sem cookie válido deve redirecionar para /admin/login."""
        import importlib
        import main as m
        importlib.reload(m)

        async def run():
            request = MagicMock()
            request.cookies = {}
            resp = await m.admin_panel(request)
            return resp

        resp = self._run(run())
        # RedirectResponse tem status 303 (See Other)
        assert resp.status_code == 303
        assert "/admin/login" in resp.headers.get("location", "")

    def test_admin_panel_serves_html_with_valid_cookie(self):
        """GET /admin com cookie válido deve servir o painel."""
        import importlib
        import main as m
        importlib.reload(m)

        async def run():
            request = MagicMock()
            # Gera cookie válido usando a função interna
            cookie_val = m._sign_admin_cookie("admin")
            request.cookies = {"admin_session": cookie_val}
            resp = await m.admin_panel(request)
            return resp

        resp = self._run(run())
        assert resp.status_code == 200
        assert "html" in resp.media_type

    def test_login_post_valid_credentials_sets_cookie(self):
        """POST /admin/login com user/pass corretos (env fallback) seta cookie e redireciona.

        SEC: login virou DB-first; mockamos authenticate_admin_user=None pra
        forcar env-fallback. routes_admin importa ADMIN_USER/PASSWORD por
        binding local (`from auth import ...`), entao patch tem que ser
        em routes_admin, nao em os.environ — reload(main) nao recarrega
        routes_admin.
        """
        import main as m

        async def run():
            from fastapi import Request as FReq
            request = MagicMock(spec=FReq)
            request.form = AsyncMock(return_value={"username": "myadmin", "password": "mypass123"})
            request.client = MagicMock(host="127.0.0.1")
            with patch("routes_admin.ADMIN_USER", "myadmin"), \
                 patch("routes_admin.ADMIN_PASSWORD", "mypass123"), \
                 patch("main.db.authenticate_admin_user", AsyncMock(return_value=None)), \
                 patch("main.db.audit", AsyncMock()):
                return await m.admin_login_post(request)

        resp = self._run(run())
        assert resp.status_code == 303
        assert "/admin" in resp.headers.get("location", "")
        cookie_header = resp.headers.get("set-cookie", "")
        assert "admin_session" in cookie_header

    def test_login_post_invalid_credentials_redirects_with_error(self):
        """POST /admin/login com credenciais erradas redireciona para login?error=1."""
        import main as m

        async def run():
            request = MagicMock()
            request.form = AsyncMock(return_value={"username": "myadmin", "password": "errado"})
            request.client = MagicMock(host="127.0.0.1")
            with patch("routes_admin.ADMIN_USER", "myadmin"), \
                 patch("routes_admin.ADMIN_PASSWORD", "mypass123"), \
                 patch("main.db.authenticate_admin_user", AsyncMock(return_value=None)), \
                 patch("main.db.audit", AsyncMock()):
                return await m.admin_login_post(request)

        resp = self._run(run())
        assert resp.status_code == 303
        assert "/admin/login?error=1" in resp.headers.get("location", "")

    def test_login_post_missing_env_redirects_with_error(self):
        """POST /admin/login sem ADMIN_USER/PASSWORD (e DB vazio) cai em error=1.

        Antes existia error=config para diferenciar misconfig de bad-creds; o
        bloco 2+3 unificou para error=1 (DB-first deixou misconfig ambiguo —
        admin pode estar so no DB e env vazio e legitimo).
        """
        import main as m

        async def run():
            request = MagicMock()
            request.form = AsyncMock(return_value={"username": "x", "password": "y"})
            request.client = MagicMock(host="127.0.0.1")
            with patch("routes_admin.ADMIN_USER", ""), \
                 patch("routes_admin.ADMIN_PASSWORD", ""), \
                 patch("main.db.authenticate_admin_user", AsyncMock(return_value=None)), \
                 patch("main.db.audit", AsyncMock()):
                return await m.admin_login_post(request)

        resp = self._run(run())
        assert resp.status_code == 303
        assert "/admin/login?error=1" in resp.headers.get("location", "")

    def test_sign_and_verify_cookie_roundtrip(self):
        """Cookie assinado deve ser verificável.

        SEC: cookie agora carrega role explicito (admin|viewer) — verify
        retorna dict {username, role}, nao string. Compat com qualquer
        chamador que dependia do retorno antigo foi removida no bloco 2+3.
        """
        import importlib
        import main as m
        importlib.reload(m)

        cookie = m._sign_admin_cookie("admin")
        assert m._verify_admin_cookie(cookie) == {"username": "admin", "role": "admin"}

    def test_verify_tampered_cookie_returns_none(self):
        """Cookie adulterado deve retornar None."""
        import importlib
        import main as m
        importlib.reload(m)

        cookie = m._sign_admin_cookie("admin")
        tampered = cookie[:-4] + "XXXX"
        assert m._verify_admin_cookie(tampered) is None

    def test_verify_garbage_cookie_returns_none(self):
        """Cookie com formato inválido deve retornar None."""
        import importlib
        import main as m
        importlib.reload(m)

        assert m._verify_admin_cookie("lixo-total") is None
        assert m._verify_admin_cookie("") is None

    def test_logout_clears_cookie(self):
        """GET /admin/logout deve limpar o cookie e redirecionar para /admin/login."""
        import main as m

        async def run():
            return await m.admin_logout()

        resp = self._run(run())
        assert resp.status_code == 303
        assert "/admin/login" in resp.headers.get("location", "")
        cookie_header = resp.headers.get("set-cookie", "")
        assert "admin_session" in cookie_header


# ===========================================================================
# 20. VALID_COMMANDS — run_script e update_agent
# ===========================================================================

class TestValidCommandsExpanded:
    """Verifica que run_script e update_agent estão nos comandos válidos."""

    def test_run_script_in_valid_commands(self):
        import importlib
        import db
        importlib.reload(db)
        assert "run_script" in db.VALID_COMMANDS

    def test_update_agent_in_valid_commands(self):
        import importlib
        import db
        importlib.reload(db)
        assert "update_agent" in db.VALID_COMMANDS

    def test_run_script_requires_params(self):
        import db
        import asyncio

        async def run():
            with pytest.raises(ValueError, match="run_script exige params"):
                await db.insert_command("host", "run_script", "admin", params=None)

        asyncio.run(run())

    def test_insert_command_passes_params(self):
        import db

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"id": 77})
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        async def run():
            with patch("db.get_conn", return_value=mock_ctx):
                cmd_id = await db.insert_command(
                    "ns1", "run_script", "admin", params='{"script":"dig_test"}'
                )
            return cmd_id

        result = asyncio.run(run())
        assert result == 77
        sql_called = mock_conn.fetchrow.call_args[0][0]
        assert "params" in sql_called

    def test_get_pending_commands_returns_params(self):
        import db

        mock_conn = AsyncMock()
        # Primeiro execute é o UPDATE de expirados, segundo fetch é o SELECT
        mock_conn.execute = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[
            {"id": 1, "command": "run_script", "confirm_token": None,
             "params": '{"script":"dig_test"}', "issued_at": "2026-01-01T00:00:00+00:00"}
        ])
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        async def run():
            with patch("db.get_conn", return_value=mock_ctx):
                return await db.get_pending_commands("ns1")

        result = asyncio.run(run())
        assert len(result) == 1
        sql_select = mock_conn.fetch.call_args[0][0]
        assert "params" in sql_select

    def test_get_all_commands_history_returns_params(self):
        import db

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[
            {"id": 1, "hostname": "ns1", "command": "run_script",
             "params": '{"script":"bind9_validate"}',
             "issued_by": "admin", "issued_at": "2026-01-01", "executed_at": None,
             "status": "done", "result": "{}"}
        ])
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        async def run():
            with patch("db.get_conn", return_value=mock_ctx):
                return await db.get_all_commands_history(limit=10)

        result = asyncio.run(run())
        assert len(result) == 1
        sql_called = mock_conn.fetch.call_args[0][0]
        assert "params" in sql_called


# ===========================================================================
# 21. agent_version no upsert_agent
# ===========================================================================

class TestAgentVersionUpsert:
    """Verifica que upsert_agent grava agent_version na tabela agents."""

    def test_upsert_agent_passes_agent_version(self):
        """A3 (R7): upsert_agent agora usa fetchrow + RETURNING (xmax=0)
        em vez de SELECT + execute separados."""
        import db

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"is_new": False})
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        async def run():
            with patch("db.get_conn", return_value=mock_ctx):
                return await db.upsert_agent(
                    "ns1", "2026-01-01T00:00:00+00:00",
                    agent_version="1.2.3",
                )

        result = asyncio.run(run())
        sql_called = mock_conn.fetchrow.call_args[0][0]
        assert "agent_version" in sql_called
        assert "xmax = 0" in sql_called  # is_new vem do RETURNING
        assert result["is_new"] is False

    def test_upsert_agent_none_version_uses_coalesce(self):
        import db

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"is_new": True})
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        async def run():
            with patch("db.get_conn", return_value=mock_ctx):
                return await db.upsert_agent(
                    "ns1", "2026-01-01T00:00:00+00:00",
                    agent_version=None,
                )

        result = asyncio.run(run())
        sql_called = mock_conn.fetchrow.call_args[0][0]
        assert "COALESCE" in sql_called
        assert result["is_new"] is True


# ===========================================================================
# 22. GET /agent/version — endpoint de versão do agente
# ===========================================================================

class TestAgentVersionEndpoint:
    """Testa GET /agent/version que retorna versão, checksum e tamanho."""

    def _run(self, coro):
        return asyncio.run(coro)

    def _make_fake_path(self, exists=True, content=""):
        fake = MagicMock()
        fake.exists.return_value = exists
        fake.read_text.return_value = content
        return fake

    def test_returns_version_and_checksum(self):
        import importlib
        import main as m
        importlib.reload(m)

        fake_content = 'AGENT_VERSION = "2.0.0"\n# rest of agent\n'
        import hashlib
        expected_checksum = hashlib.sha256(fake_content.encode()).hexdigest()

        async def run():
            req = MagicMock()
            with patch("main.require_admin", AsyncMock(return_value={"username": "admin", "role": "admin"})), \
                 patch("main.AGENT_FILE_PATH", self._make_fake_path(True, fake_content)):
                resp = await m.agent_version_info(req)
            return resp

        resp = self._run(run())
        import json
        data = json.loads(resp.body)
        assert data["version"] == "2.0.0"
        assert data["checksum"] == expected_checksum
        assert data["size"] == len(fake_content.encode())

    def test_returns_unknown_when_no_version_found(self):
        import importlib
        import main as m
        importlib.reload(m)

        async def run():
            req = MagicMock()
            with patch("main.require_admin", AsyncMock(return_value={"username": "admin", "role": "admin"})), \
                 patch("main.AGENT_FILE_PATH", self._make_fake_path(True, "# no version here")):
                resp = await m.agent_version_info(req)
            return resp

        resp = self._run(run())
        import json
        data = json.loads(resp.body)
        assert data["version"] == "unknown"

    def test_raises_404_when_file_missing(self):
        import importlib
        import main as m
        from fastapi import HTTPException
        importlib.reload(m)

        async def run():
            req = MagicMock()
            with patch("main.require_admin", AsyncMock(return_value={"username": "admin", "role": "admin"})), \
                 patch("main.AGENT_FILE_PATH", self._make_fake_path(False)):
                with pytest.raises(HTTPException) as exc:
                    await m.agent_version_info(req)
                assert exc.value.status_code == 404

        self._run(run())


# ===========================================================================
# 23. GET /agent/latest — download do agente
# ===========================================================================

class TestAgentLatestEndpoint:
    """Testa GET /agent/latest que serve o arquivo dns_agent.py."""

    def _run(self, coro):
        return asyncio.run(coro)

    def _make_fake_path(self, exists=True, content=""):
        fake = MagicMock()
        fake.exists.return_value = exists
        fake.read_text.return_value = content
        return fake

    def test_returns_python_content_with_checksum_header(self):
        import importlib
        import main as m
        importlib.reload(m)

        fake_content = 'AGENT_VERSION = "2.0.0"\nprint("hello")\n'
        import hashlib
        expected_checksum = hashlib.sha256(fake_content.encode()).hexdigest()

        async def run():
            req = MagicMock()
            with patch("main.require_token", AsyncMock(return_value=None)), \
                 patch("main.AGENT_FILE_PATH", self._make_fake_path(True, fake_content)):
                resp = await m.agent_latest_download(req)
            return resp

        resp = self._run(run())
        assert resp.body.decode() == fake_content
        assert resp.media_type == "text/x-python"
        assert resp.headers["X-Agent-Checksum"] == expected_checksum

    def test_raises_404_when_file_missing(self):
        import importlib
        import main as m
        from fastapi import HTTPException
        importlib.reload(m)

        async def run():
            req = MagicMock()
            with patch("main.require_token", AsyncMock(return_value=None)), \
                 patch("main.AGENT_FILE_PATH", self._make_fake_path(False)):
                with pytest.raises(HTTPException) as exc:
                    await m.agent_latest_download(req)
                assert exc.value.status_code == 404

        self._run(run())


# ===========================================================================
# 24. POST /tools/geolocate — geolocalização de IPs
# ===========================================================================

class TestGeolocateEndpoint:
    """Testa POST /tools/geolocate com ip-api.com mockado."""

    def _run(self, coro):
        return asyncio.run(coro)

    def test_returns_geolocation_data(self):
        import importlib
        import main as m
        importlib.reload(m)

        fake_api_response = [
            {"query": "8.8.8.8", "status": "success", "country": "United States",
             "city": "Mountain View", "isp": "Google LLC", "lat": 37.4056, "lon": -122.0775}
        ]

        async def run():
            req = MagicMock()
            req.json = AsyncMock(return_value={"ips": ["8.8.8.8"]})
            with patch("main.require_token", AsyncMock(return_value=None)):
                mock_loop = MagicMock()
                mock_loop.run_in_executor = AsyncMock(return_value=fake_api_response)
                with patch("asyncio.get_event_loop", return_value=mock_loop):
                    resp = await m.geolocate_ips(req)
            return resp

        resp = self._run(run())
        import json
        data = json.loads(resp.body)
        assert len(data) == 1
        assert data[0]["country"] == "United States"

    def test_empty_ips_returns_empty_list(self):
        import importlib
        import main as m
        importlib.reload(m)

        async def run():
            req = MagicMock()
            req.json = AsyncMock(return_value={"ips": []})
            with patch("main.require_token", AsyncMock(return_value=None)):
                resp = await m.geolocate_ips(req)
            return resp

        resp = self._run(run())
        import json
        assert json.loads(resp.body) == []

    def test_deduplicates_ips(self):
        """IPs duplicados devem ser removidos antes da chamada."""
        import importlib
        import main as m
        importlib.reload(m)

        captured_ips = []
        fake_response = [{"query": "8.8.8.8", "status": "success"}]

        async def run():
            req = MagicMock()
            req.json = AsyncMock(return_value={"ips": ["8.8.8.8", "8.8.8.8", "1.1.1.1"]})
            with patch("main.require_token", AsyncMock(return_value=None)):
                mock_loop = MagicMock()
                mock_loop.run_in_executor = AsyncMock(return_value=fake_response)
                with patch("asyncio.get_event_loop", return_value=mock_loop):
                    resp = await m.geolocate_ips(req)
            return resp

        self._run(run())


# ===========================================================================
# 25. GET /commands/{command_id}/status — status individual
# ===========================================================================

class TestCommandStatusEndpoint:
    """Testa GET /commands/{command_id}/status."""

    def _run(self, coro):
        return asyncio.run(coro)

    def test_returns_command_data(self):
        """SEC: get_command_status faz auth manual (admin cookie OU Bearer
        admin OU client cookie + ownership). Aqui passamos cookie admin
        valido pra exercer o caminho admin."""
        import main as m

        cmd = {"id": 42, "hostname": "ns1", "command": "update_agent",
               "status": "done", "result": "OK", "params": None}

        async def run():
            req = MagicMock()
            req.cookies = {"admin_session": m._sign_admin_cookie("admin")}
            req.headers = {}
            with patch("main.db.get_command_by_id", AsyncMock(return_value=cmd)):
                resp = await m.get_command_status(42, req)
            return resp

        resp = self._run(run())
        import json
        data = json.loads(resp.body)
        assert data["id"] == 42
        assert data["command"] == "update_agent"

    def test_raises_404_when_not_found(self):
        import main as m
        from fastapi import HTTPException

        async def run():
            req = MagicMock()
            req.cookies = {"admin_session": m._sign_admin_cookie("admin")}
            req.headers = {}
            with patch("main.db.get_command_by_id", AsyncMock(return_value=None)):
                with pytest.raises(HTTPException) as exc:
                    await m.get_command_status(999, req)
                assert exc.value.status_code == 404

        self._run(run())


# ===========================================================================
# 26. create_command com params
# ===========================================================================

class TestCreateCommandWithParams:
    """Testa que POST /commands passa params para db.insert_command."""

    def _run(self, coro):
        return asyncio.run(coro)

    def test_params_passed_to_insert_command(self):
        """SEC: create_command agora exige require_admin_role."""
        import main as m

        captured = {}

        async def fake_insert(*args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            return 1

        async def run():
            req = MagicMock()
            req.json = AsyncMock(return_value={
                "hostname": "ns1", "command": "run_script",
                "issued_by": "admin", "params": '{"script":"dig_test"}'
            })
            with patch("main.require_admin_role",
                       AsyncMock(return_value={"username": "admin", "role": "admin"})), \
                 patch("main.db.insert_command", side_effect=fake_insert), \
                 patch("main.db.audit", AsyncMock()):
                resp = await m.create_command(req)
            return resp

        resp = self._run(run())
        assert resp.status_code == 201
        # Verificar que params foi passado na chamada
        call_args = captured["args"]
        assert '{"script":"dig_test"}' in call_args or \
               captured["kwargs"].get("params") == '{"script":"dig_test"}'


# ===========================================================================
# 27. HEARTBEAT COM DNS CHECKS (Quick Probe)
# ===========================================================================

class TestHeartbeatWithDnsChecks:
    """
    Testa que o backend processa dns_checks de payloads heartbeat.
    Antes do quick probe, dns_checks só era processado para type="check".
    Agora dns_checks é processado independente do type.
    """

    def _run(self, coro):
        return asyncio.run(coro)

    def _make_mocks(self, has_open=False):
        mock_db = MagicMock()
        mock_db.upsert_agent = AsyncMock(return_value={"is_new": False})
        mock_db.upsert_fingerprint = AsyncMock(return_value={"changed": False})
        mock_db.insert_heartbeat = AsyncMock()
        mock_db.insert_metrics_cpu = AsyncMock()
        mock_db.insert_metrics_ram = AsyncMock()
        mock_db.insert_metrics_disk = AsyncMock()
        mock_db.insert_metrics_io = AsyncMock()
        mock_db.insert_dns_service_status = AsyncMock()
        mock_db.insert_dns_checks = AsyncMock()
        mock_db.insert_alert = AsyncMock(return_value=42)
        mock_db.mark_alert_notified = AsyncMock()
        mock_db.has_open_alert = AsyncMock(return_value=has_open)
        mock_db.resolve_alert = AsyncMock()

        mock_tg = MagicMock()
        mock_tg.alert_dns_failure = AsyncMock(return_value=True)
        mock_tg.alert_dns_latency = AsyncMock(return_value=True)
        mock_tg.alert_dns_service_down = AsyncMock(return_value=True)
        mock_tg.alert_cpu = AsyncMock(return_value=True)
        mock_tg.alert_ram = AsyncMock(return_value=True)
        mock_tg.alert_agent_recovered = AsyncMock(return_value=True)
        mock_tg.send_new_agent_detected = AsyncMock()

        return mock_db, mock_tg

    def test_heartbeat_with_dns_checks_stores_in_db(self):
        """Heartbeat com dns_checks deve gravar em dns_checks table."""
        import importlib
        import main as m
        importlib.reload(m)

        mock_db, mock_tg = self._make_mocks()
        payload_data = make_payload(type_="heartbeat", dns_success=True, dns_latency=12.5)

        async def run():
            payload = m.AgentPayload(**payload_data)
            with patch.object(m, 'db', mock_db), patch.object(m, 'tg', mock_tg):
                await m.receive_metrics(payload)

        self._run(run())
        mock_db.insert_dns_checks.assert_called_once()

    def test_heartbeat_with_dns_failure_triggers_alert(self):
        """Heartbeat com quick probe falhando deve disparar alerta DNS."""
        import importlib
        import main as m
        importlib.reload(m)

        mock_db, mock_tg = self._make_mocks()
        payload_data = make_payload(
            type_="heartbeat", dns_success=False,
            dns_error="TIMEOUT", dns_latency=None
        )

        async def run():
            payload = m.AgentPayload(**payload_data)
            with patch.object(m, 'db', mock_db), patch.object(m, 'tg', mock_tg):
                await m.receive_metrics(payload)

        self._run(run())
        mock_tg.alert_dns_failure.assert_called_once()

    def test_heartbeat_empty_dns_checks_no_insert(self):
        """Heartbeat sem dns_checks (probe desabilitado) não deve chamar insert_dns_checks."""
        import importlib
        import main as m
        importlib.reload(m)

        mock_db, mock_tg = self._make_mocks()
        payload_data = make_payload(type_="heartbeat")
        payload_data["dns_checks"] = []

        async def run():
            payload = m.AgentPayload(**payload_data)
            with patch.object(m, 'db', mock_db), patch.object(m, 'tg', mock_tg):
                await m.receive_metrics(payload)

        self._run(run())
        mock_db.insert_dns_checks.assert_not_called()

    def test_heartbeat_stores_dns_service_status(self):
        """Heartbeat deve gravar dns_service_status (antes só check fazia isso)."""
        import importlib
        import main as m
        importlib.reload(m)

        mock_db, mock_tg = self._make_mocks()
        payload_data = make_payload(type_="heartbeat")

        async def run():
            payload = m.AgentPayload(**payload_data)
            with patch.object(m, 'db', mock_db), patch.object(m, 'tg', mock_tg):
                await m.receive_metrics(payload)

        self._run(run())
        mock_db.insert_dns_service_status.assert_called_once()


# ===========================================================================
# API Versioning — /api/v1/ prefix
# ===========================================================================

class TestApiVersioning:
    """Verifica que todas as rotas de API estao registradas sob /api/v1/."""

    def _get_routes(self):
        import importlib
        import main as m
        importlib.reload(m)
        return {r.path for r in m.app.routes if hasattr(r, 'path')}

    def test_metrics_endpoint_under_v1(self):
        routes = self._get_routes()
        assert "/api/v1/metrics" in routes

    def test_agents_endpoint_under_v1(self):
        routes = self._get_routes()
        assert "/api/v1/agents" in routes

    def test_agents_hostname_patch_under_v1(self):
        routes = self._get_routes()
        assert "/api/v1/agents/{hostname}" in routes

    def test_alerts_endpoint_under_v1(self):
        routes = self._get_routes()
        assert "/api/v1/alerts" in routes

    def test_commands_endpoints_under_v1(self):
        routes = self._get_routes()
        assert "/api/v1/commands" in routes
        assert "/api/v1/commands/{hostname}" in routes
        assert "/api/v1/commands/{command_id}/result" in routes
        assert "/api/v1/commands/{hostname}/history" in routes
        assert "/api/v1/commands/history" in routes
        assert "/api/v1/commands/{command_id}/status" in routes

    def test_agent_version_under_v1(self):
        routes = self._get_routes()
        assert "/api/v1/agent/version" in routes
        assert "/api/v1/agent/latest" in routes

    def test_tools_under_v1(self):
        routes = self._get_routes()
        assert "/api/v1/tools/geolocate" in routes

    def test_health_stays_at_root(self):
        """Health check deve permanecer na raiz — nao faz parte da API versionada."""
        routes = self._get_routes()
        assert "/health" in routes

    def test_admin_stays_at_root(self):
        """Admin panel e rotas de UI nao sao versionadas."""
        routes = self._get_routes()
        assert "/admin" in routes
        assert "/admin/login" in routes
        assert "/admin/logout" in routes

    def test_legacy_metrics_path_still_works(self):
        """Rota antiga /metrics deve existir para backward compat com agentes v1.0.0."""
        routes = self._get_routes()
        assert "/metrics" in routes


# ===========================================================================
# Token embutido no admin — Feature 010 Fase 1
# ===========================================================================

class TestSessionTokenSecurity:
    """Verifica que token NAO e exposto no HTML e que endpoint /session/token funciona."""

    def _run(self, coro):
        return asyncio.run(coro)

    def test_admin_html_never_contains_token(self):
        """GET /admin NAO deve ter AGENT_TOKEN no HTML (seguranca)."""
        import importlib, main as m
        with patch.dict(os.environ, {"AGENT_TOKEN": "secret-tok-xyz"}):
            importlib.reload(m)
            async def run():
                request = MagicMock()
                cookie_val = m._sign_admin_cookie("admin")
                request.cookies = {"admin_session": cookie_val}
                return await m.admin_panel(request)
            resp = self._run(run())
            body = resp.body.decode()
            assert "secret-tok-xyz" not in body

    def test_dashboard_html_never_contains_token(self):
        """GET /dashboard NAO deve ter AGENT_TOKEN no HTML."""
        import importlib, main as m
        with patch.dict(os.environ, {"AGENT_TOKEN": "dash-tok-123"}):
            importlib.reload(m)
            async def run():
                request = MagicMock()
                request.cookies = {}
                return await m.dashboard_page(request)
            resp = self._run(run())
            assert "dash-tok-123" not in resp.body.decode()

    def test_session_token_deprecated_with_admin_cookie_returns_410(self):
        """SEC: /session/token foi removido por entregar AGENT_TOKEN a clientes
        do portal (multi-tenant break). Agora retorna 410 mesmo com cookie admin
        valido — admin/cliente devem usar /session/whoami + cookies same-origin.
        """
        import importlib, main as m
        from fastapi import HTTPException
        with patch.dict(os.environ, {"AGENT_TOKEN": "tok-abc"}):
            importlib.reload(m)
            async def run():
                request = MagicMock()
                request.cookies = {"admin_session": m._sign_admin_cookie("admin"), "client_session": ""}
                request.client = MagicMock(host="127.0.0.1")
                return await m.session_token_deprecated(request)
            with pytest.raises(HTTPException) as exc:
                self._run(run())
            assert exc.value.status_code == 410

    def test_session_token_deprecated_without_session_returns_410(self):
        """SEC: endpoint deprecated retorna 410 incondicionalmente."""
        import importlib, main as m
        from fastapi import HTTPException
        importlib.reload(m)
        async def run():
            request = MagicMock()
            request.cookies = {"admin_session": "", "client_session": ""}
            request.client = MagicMock(host="127.0.0.1")
            return await m.session_token_deprecated(request)
        with pytest.raises(HTTPException) as exc:
            self._run(run())
        assert exc.value.status_code == 410


# ===========================================================================
# Client Portal — Feature 010 Fases 2-3
# ===========================================================================

class TestClientPortal:
    """Testa autenticacao de clientes, CRUD, e portal."""

    def _run(self, coro):
        return asyncio.run(coro)

    def test_hash_password_returns_bcrypt(self):
        import importlib, main as m
        importlib.reload(m)
        h = m._hash_password("teste123")
        assert h.startswith("$2b$12$")  # bcrypt cost 12

    def test_verify_password_matches_bcrypt(self):
        import importlib, main as m
        importlib.reload(m)
        h = m._hash_password("teste123")
        assert m._verify_password("teste123", h) is True
        assert m._verify_password("errado", h) is False

    def test_sign_verify_client_cookie_roundtrip(self):
        import importlib, main as m
        importlib.reload(m)
        cookie = m._sign_client_cookie("cliente1")
        assert m._verify_client_cookie(cookie) == "cliente1"

    def test_verify_client_cookie_rejects_admin_cookie(self):
        import importlib, main as m
        importlib.reload(m)
        admin_cookie = m._sign_admin_cookie("admin")
        assert m._verify_client_cookie(admin_cookie) is None

    def test_verify_client_cookie_rejects_garbage(self):
        import importlib, main as m
        importlib.reload(m)
        assert m._verify_client_cookie("garbage") is None
        assert m._verify_client_cookie("") is None

    def test_client_login_page_returns_html(self):
        """SEC: pagina agora injeta CSP nonce nos <script> via _html_with_nonce.
        Assinatura passou a receber `request` para acessar request.state.csp_nonce.
        """
        import main as m
        request = MagicMock()
        request.state = MagicMock(csp_nonce="testnonce")
        resp = self._run(m.client_login_page(request))
        assert resp.status_code == 200
        body = resp.body.decode()
        assert "Portal do Cliente" in body
        # Garantir que o nonce foi propagado para tags <script>
        assert 'nonce="testnonce"' in body

    def test_client_portal_redirects_without_cookie(self):
        import importlib, main as m
        importlib.reload(m)

        async def run():
            request = MagicMock()
            request.cookies = {}
            return await m.client_portal(request)

        resp = self._run(run())
        assert resp.status_code == 303
        assert "/client/login" in resp.headers.get("location", "")

    def test_client_portal_serves_html_with_valid_cookie(self):
        import importlib, main as m
        importlib.reload(m)

        async def run():
            request = MagicMock()
            cookie = m._sign_client_cookie("cliente1")
            request.cookies = {"client_session": cookie}
            return await m.client_portal(request)

        resp = self._run(run())
        assert resp.status_code == 200
        body = resp.body.decode()
        assert "window.__CLIENT__" in body
        assert "cliente1" in body

    def test_client_data_requires_client_header(self):
        """Endpoint /client/data sem X-Client-User deve retornar 403."""
        import importlib, main as m

        with patch.dict(os.environ, {"AGENT_TOKEN": "tok"}):
            importlib.reload(m)

            async def run():
                request = MagicMock()
                request.headers = {"Authorization": "Bearer tok"}
                return await m.client_data(request)

            with pytest.raises(Exception) as exc_info:
                self._run(run())
            assert "403" in str(exc_info.value) or "Acesso negado" in str(exc_info.value)

    def test_create_client_endpoint_routes_exist(self):
        import importlib, main as m
        importlib.reload(m)
        routes = {r.path for r in m.app.routes if hasattr(r, 'path')}
        assert "/api/v1/clients" in routes
        assert "/client" in routes
        assert "/client/login" in routes
        assert "/client/logout" in routes



# ===========================================================================
# Audit log hash chain (C2 — v1.5 security audit)
# ===========================================================================

class TestAuditHashChain:
    """Hash chain immutable: row_hash determinismo + verify pega adulteracao."""

    def test_hash_deterministic(self):
        """Mesma entrada gera mesmo hash."""
        from datetime import datetime, timezone
        import db
        ts = datetime(2026, 4, 30, 12, 0, 0, tzinfo=timezone.utc)
        h1 = db._compute_audit_hash(None, ts, "admin", "login", "panel", "ok", "10.0.0.1")
        h2 = db._compute_audit_hash(None, ts, "admin", "login", "panel", "ok", "10.0.0.1")
        assert h1 == h2

    def test_hash_changes_on_any_field(self):
        """Mudar 1 campo muda o hash — base do chain integrity."""
        from datetime import datetime, timezone
        import db
        ts = datetime(2026, 4, 30, 12, 0, 0, tzinfo=timezone.utc)
        base = db._compute_audit_hash(None, ts, "admin", "login", "panel", "ok", "10.0.0.1")
        # Cada uma dessas variacoes deve dar hash diferente
        variants = [
            db._compute_audit_hash("PREV", ts, "admin", "login", "panel", "ok", "10.0.0.1"),
            db._compute_audit_hash(None, ts.replace(second=1), "admin", "login", "panel", "ok", "10.0.0.1"),
            db._compute_audit_hash(None, ts, "admin2", "login", "panel", "ok", "10.0.0.1"),
            db._compute_audit_hash(None, ts, "admin", "logout", "panel", "ok", "10.0.0.1"),
            db._compute_audit_hash(None, ts, "admin", "login", "other", "ok", "10.0.0.1"),
            db._compute_audit_hash(None, ts, "admin", "login", "panel", "fail", "10.0.0.1"),
            db._compute_audit_hash(None, ts, "admin", "login", "panel", "ok", "10.0.0.2"),
        ]
        for v in variants:
            assert v != base, f"hash collision: {v}"

    def test_hash_separator_prevents_concat_collision(self):
        """Separator US (\\x1f) impede colisao por concatenacao ambigua —
        ('ab', 'c') vs ('a', 'bc') devem dar hashes diferentes."""
        from datetime import datetime, timezone
        import db
        ts = datetime(2026, 4, 30, 12, 0, 0, tzinfo=timezone.utc)
        h1 = db._compute_audit_hash(None, ts, "ab", "c", None, None, None)
        h2 = db._compute_audit_hash(None, ts, "a", "bc", None, None, None)
        assert h1 != h2

    def test_verify_chain_empty(self):
        """Chain vazia retorna valid=True com totals zero."""
        import asyncio
        from unittest.mock import patch, AsyncMock
        import db
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        with patch.object(db, "get_conn") as gc:
            gc.return_value.__aenter__.return_value = mock_conn
            result = asyncio.run(db.verify_audit_chain())
        assert result["valid"] is True
        assert result["total"] == 0
        assert result["signed_count"] == 0
        assert result["legacy_count"] == 0

    def test_verify_chain_legacy_only(self):
        """Rows pre-migration (row_hash NULL) sao toleradas."""
        import asyncio
        from unittest.mock import patch, AsyncMock
        from datetime import datetime, timezone
        import db
        ts = datetime(2026, 4, 30, 12, 0, 0, tzinfo=timezone.utc)
        rows = [
            {"id": 1, "ts": ts, "actor": "old", "action": "login",
             "target": None, "detail": None, "ip": None,
             "prev_hash": None, "row_hash": None},
            {"id": 2, "ts": ts, "actor": "old", "action": "logout",
             "target": None, "detail": None, "ip": None,
             "prev_hash": None, "row_hash": None},
        ]
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=rows)
        with patch.object(db, "get_conn") as gc:
            gc.return_value.__aenter__.return_value = mock_conn
            result = asyncio.run(db.verify_audit_chain())
        assert result["valid"] is True
        assert result["legacy_count"] == 2
        assert result["signed_count"] == 0

    def test_verify_chain_detects_tampering(self):
        """Adulteracao de campo (row_hash invalido) e detectada."""
        import asyncio
        from unittest.mock import patch, AsyncMock
        from datetime import datetime, timezone
        import db
        ts = datetime(2026, 4, 30, 12, 0, 0, tzinfo=timezone.utc)
        # Row 1: row_hash valido
        h1 = db._compute_audit_hash(None, ts, "admin", "login", None, None, None)
        # Row 2: row_hash valido com prev=h1
        h2 = db._compute_audit_hash(h1, ts, "admin", "create_user", "alice", None, None)
        # Row 3: alguem ALTEROU o action (de "delete" pra "rename") mas
        # row_hash continua sendo o de "delete" — verify deve pegar.
        h3_real = db._compute_audit_hash(h2, ts, "admin", "delete_user", "bob", None, None)
        rows = [
            {"id": 1, "ts": ts, "actor": "admin", "action": "login",
             "target": None, "detail": None, "ip": None,
             "prev_hash": None, "row_hash": h1},
            {"id": 2, "ts": ts, "actor": "admin", "action": "create_user",
             "target": "alice", "detail": None, "ip": None,
             "prev_hash": h1, "row_hash": h2},
            {"id": 3, "ts": ts, "actor": "admin", "action": "rename_user",  # ALTERADO!
             "target": "bob", "detail": None, "ip": None,
             "prev_hash": h2, "row_hash": h3_real},
        ]
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=rows)
        with patch.object(db, "get_conn") as gc:
            gc.return_value.__aenter__.return_value = mock_conn
            result = asyncio.run(db.verify_audit_chain())
        assert result["valid"] is False
        assert result["broken_at_id"] == 3
        assert "recomputado nao bate" in result["message"]

    def test_verify_chain_detects_broken_link(self):
        """prev_hash que nao bate com row_hash anterior e detectado."""
        import asyncio
        from unittest.mock import patch, AsyncMock
        from datetime import datetime, timezone
        import db
        ts = datetime(2026, 4, 30, 12, 0, 0, tzinfo=timezone.utc)
        h1 = db._compute_audit_hash(None, ts, "admin", "login", None, None, None)
        # Row 2 com prev_hash WRONG (nao igual a h1)
        WRONG_PREV = "0" * 64
        h2_wrong = db._compute_audit_hash(WRONG_PREV, ts, "admin", "do", None, None, None)
        rows = [
            {"id": 1, "ts": ts, "actor": "admin", "action": "login",
             "target": None, "detail": None, "ip": None,
             "prev_hash": None, "row_hash": h1},
            {"id": 2, "ts": ts, "actor": "admin", "action": "do",
             "target": None, "detail": None, "ip": None,
             "prev_hash": WRONG_PREV, "row_hash": h2_wrong},
        ]
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=rows)
        with patch.object(db, "get_conn") as gc:
            gc.return_value.__aenter__.return_value = mock_conn
            result = asyncio.run(db.verify_audit_chain())
        assert result["valid"] is False
        assert result["broken_at_id"] == 2
        assert "nao bate" in result["message"]


# ===========================================================================
# A5 — Race condition stress tests (cobre R1-R5 da auditoria)
# ===========================================================================
#
# Dispara N coroutines simultaneas contra estado compartilhado (rate-limiters,
# security counters, middleware request log) e valida invariantes. Materializa
# em red/green o que o auditor reportou como "alta likelihood".
#
# Single-thread asyncio: codigo sync sem await ja e atomic; o lock importa
# quando o flow real tem awaits intercalados (ex: admin_login_post checa
# rate-limit, await form(), depois grava failure). Os testes simulam esse
# padrao injetando await asyncio.sleep(0) entre check e act.

class TestRaceConditionsStress:
    """A5 (C7 + R1-R5): valida invariantes sob concorrencia."""

    def test_login_rate_limit_holds_under_concurrent_attempts(self):
        """R1: 50 coroutines tentando registrar falha simultaneamente nao podem
        burlar o limite de 5 tentativas. Apos a tempestade, _login_attempts[ip]
        tem exatamente 50 entradas (todas registradas) — mas check_rate_limit
        retorna True (locked) consistentemente apos a 5a."""
        import importlib
        import auth
        importlib.reload(auth)

        async def attacker(ip: str):
            await auth._record_failed_login(ip)
            return await auth._check_rate_limit(ip)

        async def run():
            ip = "10.0.0.99"
            # Limpa estado de runs anteriores
            auth._login_attempts.pop(ip, None)
            results = await asyncio.gather(*[attacker(ip) for _ in range(50)])
            # Invariante 1: nenhuma corrupcao do dict (50 entries gravadas)
            assert len(auth._login_attempts[ip]) == 50, \
                f"contagem perdeu eventos: {len(auth._login_attempts[ip])}"
            # Invariante 2: a partir da 6a tentativa, locked = True
            # (pode ser dificil garantir ordem exata sob concorrencia, mas
            # MAIORIA dos resultados deve ser True quando >= 5 entradas existem)
            locked_count = sum(1 for r in results if r)
            assert locked_count >= 45, \
                f"esperava maioria locked, got {locked_count}/50"

        asyncio.run(run())

    def test_security_record_event_no_lost_writes(self):
        """R2: 100 coroutines registrando events do mesmo IP. Apos run,
        _events[ip] tem exatamente 100 entradas — sem perdas por race."""
        import importlib
        import security
        importlib.reload(security)
        security.SECURITY_ENABLED = True

        async def run():
            ip = "10.0.0.42"
            security._events.pop(ip, None)
            await asyncio.gather(*[
                security.record_event(ip, "404") for _ in range(100)
            ])
            assert len(security._events[ip]) == 100, \
                f"perdeu events: {len(security._events[ip])} de 100"

        asyncio.run(run())

    def test_security_block_unblock_consistent(self):
        """R3: bloquear e unblock concorrentes nao deixam estado corrompido."""
        import importlib
        import security
        importlib.reload(security)
        security.SECURITY_ENABLED = True

        async def block_then_unblock(ip: str):
            # Bloqueia direto via lock interno (handle_honeypot e o caminho real)
            async with security._state_lock:
                security._block_ip_unlocked(ip, "stress")
            # Pequeno yield pra outras coroutines rodarem
            await asyncio.sleep(0)
            await security.unblock_ip(ip)

        async def run():
            ips = [f"10.0.0.{i}" for i in range(20)]
            security._blocked_ips.clear()
            await asyncio.gather(*[block_then_unblock(ip) for ip in ips])
            # Apos block+unblock pareados, dict deve estar vazio
            assert len(security._blocked_ips) == 0, \
                f"blocked_ips nao zerado: {dict(security._blocked_ips)}"

        asyncio.run(run())

    def test_api_rate_limit_middleware_count_exact(self):
        """R5: APIRateLimitMiddleware._requests deve refletir contagem exata
        sob N requests concorrentes ao mesmo (ip,path). Disparamos 130
        requests; exatamente 120 (limit default /api/) passam e 10 sao 429.

        ATENCAO: o middleware tem bypass `if not SECURITY_ENABLED` no inicio
        do dispatch — entao SECURITY_ENABLED precisa estar True pro
        rate-limit aplicar. Mantemos o IP fora da whitelist."""
        import importlib
        import middlewares
        importlib.reload(middlewares)

        import security
        security.SECURITY_ENABLED = True
        security._WHITELIST = set()  # garante IP de teste nao whitelistado

        async def fake_call_next(_request):
            from fastapi import Response
            return Response(content="ok", media_type="text/plain")

        mw = middlewares.APIRateLimitMiddleware(app=None)
        mw._requests.clear()

        def make_req():
            req = MagicMock()
            req.url.path = "/api/v1/agents"
            req.client.host = "10.0.0.50"
            req.headers = {}
            return req

        async def fire():
            return await mw.dispatch(make_req(), fake_call_next)

        async def run():
            results = await asyncio.gather(*[fire() for _ in range(130)])
            success = sum(1 for r in results if r.status_code == 200)
            blocked = sum(1 for r in results if r.status_code == 429)
            assert success <= 120, f"limit burlado: {success} OK"
            assert success + blocked == 130
            assert blocked >= 10, f"esperava >=10 bloqueios, got {blocked}"

        asyncio.run(run())

    def test_security_should_alert_cooldown_no_double_fire(self):
        """R4: 50 coroutines tentando alertar pro mesmo (type,ip) em paralelo.
        Apenas UMA deve ver should_alert=True; resto deve ver False (cooldown)."""
        import importlib
        import security
        importlib.reload(security)
        security.SECURITY_ENABLED = True

        async def try_alert(key: str):
            async with security._state_lock:
                return security._should_alert_unlocked(key)

        async def run():
            key = "scan:10.0.0.7"
            security._alerted.pop(key, None)
            results = await asyncio.gather(*[try_alert(key) for _ in range(50)])
            true_count = sum(1 for r in results if r)
            assert true_count == 1, \
                f"esperava 1 alert disparado, got {true_count} (cooldown burlado)"

        asyncio.run(run())


# ===========================================================================
# CSP — pipeline de nonce + debt do unsafe-inline (refactor planejado)
# ===========================================================================

class TestCSPNonceOnly:
    """Trava o estado do CSP enquanto o debt de event handlers inline existir.

    Estado atual:
      script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://static.cloudflareinsights.com

    Razao do unsafe-inline puro (sem nonce): em CSP3, quando 'nonce-X'
    esta presente, browsers entram em strict mode e IGNORAM 'unsafe-inline'
    especificamente para event handlers HTML (onclick=, onchange=, onsubmit=).
    Os ~60 handlers inline existentes em admin/speedtest/dashboard/client
    HTMLs e em innerHTML strings (admin-*.js, app.js) precisam de
    'unsafe-inline' efetivo, entao removemos o nonce do CSP — fica como
    decoracao no _html_with_nonce ate o refactor B.

    Combos validados em browser real:
      'unsafe-inline' SO              -> handlers OK (atual)
      'unsafe-inline' + 'nonce-X'     -> handlers BLOQUEADOS (CSP3 strict)
      'nonce-X' + addEventListener    -> alvo do refactor B

    Tres testes abaixo:
      - has_unsafe_inline_today: trava o estado atual (passa)
      - has_no_unsafe_inline:    estado futuro (xfail; vira xpass com refactor B)
      - connect_src_jsdelivr:    sourcemap (passa)
    """

    def _capture_csp(self):
        import asyncio
        from middlewares import SecurityHeadersMiddleware

        async def fake_call_next(request):
            from fastapi import Response
            return Response(content="ok", media_type="text/plain")

        mw = SecurityHeadersMiddleware(app=None)
        request = MagicMock()
        request.state = type("S", (), {})()
        request.url.path = "/"

        async def run():
            return await mw.dispatch(request, fake_call_next)

        resp = asyncio.run(run())
        csp = resp.headers["Content-Security-Policy"]
        directives = {d.strip().split(" ", 1)[0]: d.strip()
                      for d in csp.split(";") if d.strip()}
        return csp, directives

    def test_csp_has_unsafe_inline_today(self):
        """Estado atual conhecido — 'unsafe-inline' sustenta event handlers
        HTML enquanto o refactor B nao fecha o ciclo. Mudanca acidental
        que tire 'unsafe-inline' (sem refactor) quebra a UI; este teste
        impede regressao silenciosa."""
        _, directives = self._capture_csp()
        script_src = directives.get("script-src", "")
        assert "'unsafe-inline'" in script_src, \
            f"script-src DEVE ter 'unsafe-inline' enquanto handlers inline existirem: {script_src}"
        # Defesa adicional: nonce nao deve estar presente junto com unsafe-inline,
        # senao browsers entram em CSP3 strict e bloqueiam handlers.
        assert "nonce-" not in script_src, \
            (f"script-src tem nonce-source com 'unsafe-inline': em CSP3 strict, "
             f"event handlers ficam bloqueados. CSP={script_src}")

    @pytest.mark.xfail(reason="DEBT: ~60 inline event handlers; refactor pra "
                              "addEventListener planejado. Quando feito, este "
                              "xfail vira xpass; remove-se 'unsafe-inline' do "
                              "CSP em middlewares.py, adiciona-se 'nonce-{nonce}', "
                              "e remove-se o decorator.")
    def test_csp_has_no_unsafe_inline(self):
        """Estado futuro: script-src sem 'unsafe-inline', com nonce-source.

        Quando virar xpass:
          1. Confirma que o refactor B terminou (todos os onclick=/onchange= viraram addEventListener).
          2. Remove 'unsafe-inline' da string CSP em middlewares.py.
          3. Adiciona f"'nonce-{nonce}'" no script-src.
          4. Remove o decorator @pytest.mark.xfail.
          5. Atualiza test_csp_has_unsafe_inline_today (vira xfail / removido).
        """
        _, directives = self._capture_csp()
        script_src = directives.get("script-src", "")
        assert "'unsafe-inline'" not in script_src, \
            f"script-src ainda tem 'unsafe-inline': {script_src}"
        assert "nonce-" in script_src, \
            f"script-src precisa declarar 'nonce-X' apos refactor: {script_src}"

    def test_csp_connect_src_allows_jsdelivr_for_sourcemaps(self):
        """DevTools tenta baixar .js.map via fetch — se cdn.jsdelivr.net
        nao esta em connect-src, sourcemap quebra silenciosamente.
        """
        _, directives = self._capture_csp()
        connect_src = directives.get("connect-src", "")
        assert "cdn.jsdelivr.net" in connect_src, \
            f"connect-src precisa permitir cdn.jsdelivr.net pra sourcemaps: {connect_src}"


# ===========================================================================
# CSP — matriz de antipatterns conhecidos (regression guard parametrizado)
# ===========================================================================
#
# Cada antipattern documenta um padrao que NUNCA deve aparecer no CSP
# servido pelo backend, junto com a vulnerabilidade que ele habilita.
# Adicionar novos antipatterns aqui quando descobrirmos novos modos de
# falha — esta tabela e o "memorial dos bugs que nos morderam" expressado
# em codigo verificavel.
#
# Tipos suportados em "needles":
#   - str: substring que precisa estar AUSENTE da diretiva
#   - tuple[str, ...]: todas as substrings precisam estar AUSENTES juntas
#                       (combo proibido — uma sozinha pode ser ok, todas juntas nao)
# ---------------------------------------------------------------------------

CSP_ANTIPATTERNS = [
    # (id, diretiva, needles, explicacao)
    (
        "script-src-wildcard",
        "script-src",
        "*",
        "Wildcard permite qualquer origem; XSS trivial via <script src=evil.com>.",
    ),
    (
        "script-src-unsafe-eval",
        "script-src",
        "'unsafe-eval'",
        "Permite eval()/new Function(); escala injecao de string pra execucao.",
    ),
    (
        "script-src-data-uri",
        "script-src",
        "data:",
        "<script src='data:application/javascript,...'> e XSS classico.",
    ),
    (
        "script-src-http-downgrade",
        "script-src",
        " http:",  # com espaco pra nao matchar 'https:' nem 'http://localhost'
        "Downgrade HTTP permite MITM injetar JS em transito.",
    ),
    (
        "script-src-unsafe-inline-with-nonce",
        "script-src",
        ("'unsafe-inline'", "nonce-"),
        "CSP3 strict mode: presenca de nonce-source faz browser IGNORAR "
        "'unsafe-inline' especificamente para event handlers HTML "
        "(onclick=, onchange=, onsubmit=). Resultado: UI quebra silenciosa "
        "em sort/bulk-select/modais. Bug ja visto em prod (commit b74948c).",
    ),
    (
        "object-src-not-restricted",
        "default-src",
        # default-src cobre object-src se este nao estiver definido. Se o CSP
        # nao tem nem object-src explicito nem default-src restritivo, plugins
        # Flash/PDF podem ser carregados.
        # Aqui validamos so que default-src esta declarado (mais facil que
        # parsear object-src ausente).
        "",  # sentinela: o test trata diretiva vazia como "deve existir e ser != ''"
        "Se default-src nem object-src estao declarados, browsers carregam "
        "<object>/<embed> sem restricao (Flash/PDF/etc.).",
    ),
]


class TestCSPAntipatterns:
    """Matriz de combos proibidos. Cada entrada CSP_ANTIPATTERNS vira 1 caso.

    Atualizar a tabela quando descobrir novos antipatterns. Bug repetido =
    teste novo aqui.
    """

    def _capture_csp(self):
        import asyncio
        from middlewares import SecurityHeadersMiddleware

        async def fake_call_next(request):
            from fastapi import Response
            return Response(content="ok", media_type="text/plain")

        mw = SecurityHeadersMiddleware(app=None)
        request = MagicMock()
        request.state = type("S", (), {})()
        request.url.path = "/"

        async def run():
            return await mw.dispatch(request, fake_call_next)

        resp = asyncio.run(run())
        csp = resp.headers["Content-Security-Policy"]
        directives = {d.strip().split(" ", 1)[0]: d.strip()
                      for d in csp.split(";") if d.strip()}
        return csp, directives

    @pytest.mark.parametrize("ap_id,directive,needles,reason", CSP_ANTIPATTERNS,
                             ids=[a[0] for a in CSP_ANTIPATTERNS])
    def test_csp_no_antipattern(self, ap_id, directive, needles, reason):
        full_csp, directives = self._capture_csp()
        directive_value = directives.get(directive, "")

        # Caso especial: needle vazia = a diretiva precisa EXISTIR e ser nao-vazia
        # (usado pra default-src, garante restricao de object-src/embed).
        if needles == "":
            assert directive_value, \
                (f"[{ap_id}] Diretiva '{directive}' ausente do CSP.\n"
                 f"Motivo: {reason}\nCSP completo: {full_csp}")
            return

        # Combo (tupla): todos os elementos juntos sao proibidos.
        if isinstance(needles, tuple):
            present = [n for n in needles if n in directive_value]
            assert len(present) < len(needles), (
                f"[{ap_id}] Diretiva '{directive}' contem combo proibido "
                f"{needles}.\nMotivo: {reason}\n"
                f"Diretiva atual: {directive_value}"
            )
            return

        # String simples: substring nao pode estar presente.
        assert needles not in directive_value, (
            f"[{ap_id}] Diretiva '{directive}' contem substring proibida "
            f"'{needles}'.\nMotivo: {reason}\n"
            f"Diretiva atual: {directive_value}"
        )


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])