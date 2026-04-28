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
        """Retorna db e tg mockados com comportamentos padrão."""
        mock_db = MagicMock()
        mock_db.insert_alert = AsyncMock(return_value=42)
        mock_db.mark_alert_notified = AsyncMock()
        mock_db.has_open_alert = AsyncMock(return_value=has_open)

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
        """Fix 2: warning não insere se já há alerta aberto."""
        mock_db, mock_tg = self._make_mocks(has_open=True)
        self._evaluate(make_payload(cpu_pct=85.0), mock_db, mock_tg)
        mock_db.has_open_alert.assert_called_with("test-host-01", "cpu")
        mock_db.insert_alert.assert_not_called()

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
        """Fix 2: RAM warning deduplicado."""
        mock_db, mock_tg = self._make_mocks(has_open=True)
        self._evaluate(make_payload(ram_pct=88.0), mock_db, mock_tg)
        mock_db.has_open_alert.assert_called_with("test-host-01", "ram")
        mock_db.insert_alert.assert_not_called()

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
        """Fix 2: DNS latency warning deduplicado."""
        mock_db, mock_tg = self._make_mocks(has_open=True)
        data = make_payload(dns_success=True, dns_latency=250.0)
        self._evaluate(data, mock_db, mock_tg)
        mock_db.has_open_alert.assert_called_with("test-host-01", "dns_latency")
        mock_db.insert_alert.assert_not_called()

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
        import importlib
        import main as m
        importlib.reload(m)

        mock_db = MagicMock()
        mock_db.get_agents_offline = AsyncMock(return_value=offline_agents)
        mock_db.get_open_alerts = AsyncMock(return_value=existing_open_alerts)
        mock_db.insert_alert = AsyncMock(return_value=99)
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
        """Anti-spam: agente já tem alerta offline aberto, não cria outro."""
        offline = [{"hostname": "h1", "last_seen": None}]
        existing = [{"alert_type": "offline", "hostname": "h1"}]
        m, mock_db, mock_tg = self._setup(offline, existing)
        with patch.object(m, 'db', mock_db), patch.object(m, 'tg', mock_tg):
            self._run(m.job_check_offline())
        mock_db.insert_alert.assert_not_called()
        mock_tg.alert_agent_offline.assert_not_called()

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

    def test_create_command_missing_fields(self):
        import main as m_module
        import asyncio

        async def run():
            req = MagicMock()
            req.headers = {"authorization": "Bearer tok"}
            req.json = AsyncMock(return_value={"hostname": "", "command": ""})
            with patch.dict("os.environ", {"AGENT_TOKEN": "tok"}):
                with patch("main.require_token", AsyncMock(return_value=None)):
                    resp = await m_module.create_command(req)
            assert resp.status_code == 422

        asyncio.run(run())

    def test_create_command_purge_generates_confirm_token(self):
        import main as m_module
        import asyncio

        async def run():
            req = MagicMock()
            req.headers = {"authorization": "Bearer tok"}
            req.json = AsyncMock(return_value={
                "hostname": "ns1", "command": "purge", "issued_by": "admin"
            })
            with patch.dict("os.environ", {"AGENT_TOKEN": "tok"}):
                with patch("main.require_token", AsyncMock(return_value=None)):
                    with patch("main.db.insert_command", AsyncMock(return_value=99)):
                        resp = await m_module.create_command(req)
            import json
            data = json.loads(resp.body)
            assert resp.status_code == 201
            assert "confirm_token" in data
            assert "warning" in data
            assert len(data["confirm_token"]) == 16

        asyncio.run(run())

    def test_create_command_stop_no_confirm_token(self):
        import main as m_module
        import asyncio

        async def run():
            req = MagicMock()
            req.headers = {"authorization": "Bearer tok"}
            req.json = AsyncMock(return_value={
                "hostname": "ns1", "command": "stop", "issued_by": "admin"
            })
            with patch.dict("os.environ", {"AGENT_TOKEN": "tok"}):
                with patch("main.require_token", AsyncMock(return_value=None)):
                    with patch("main.db.insert_command", AsyncMock(return_value=1)):
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
            req.headers = {"authorization": "Bearer tok"}
            req.json = AsyncMock(return_value={"hostname": "ns1", "command": "reboot"})
            with patch.dict("os.environ", {"AGENT_TOKEN": "tok"}):
                with patch("main.require_token", AsyncMock(return_value=None)):
                    with patch("main.db.insert_command",
                               AsyncMock(side_effect=ValueError("Comando inválido"))):
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
        import main as m

        history = [
            {"id": 1, "hostname": "ns1", "command": "restart",
             "issued_by": "admin-panel", "issued_at": "2026-04-08T10:00:00+00:00",
             "executed_at": None, "status": "pending", "result": None},
        ]

        async def run():
            req = MagicMock()
            req.headers = {"Authorization": "Bearer tok"}
            with patch("main.require_token", AsyncMock(return_value=None)):
                with patch("main.db.get_all_commands_history", AsyncMock(return_value=history)):
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
        """POST /admin/login com user/pass corretos deve setar cookie e redirecionar."""
        import importlib
        import main as m

        with patch.dict(os.environ, {"ADMIN_USER": "myadmin", "ADMIN_PASSWORD": "mypass123"}):
            importlib.reload(m)

            async def run():
                from fastapi import Request as FReq
                request = MagicMock(spec=FReq)
                request.form = AsyncMock(return_value={"username": "myadmin", "password": "mypass123"})
                resp = await m.admin_login_post(request)
                return resp

            resp = self._run(run())
            assert resp.status_code == 303
            assert "/admin" in resp.headers.get("location", "")
            # Cookie deve estar no response
            cookie_header = resp.headers.get("set-cookie", "")
            assert "admin_session" in cookie_header

    def test_login_post_invalid_credentials_redirects_with_error(self):
        """POST /admin/login com credenciais erradas deve redirecionar para login?error=1."""
        import importlib
        import main as m

        with patch.dict(os.environ, {"ADMIN_USER": "myadmin", "ADMIN_PASSWORD": "mypass123"}):
            importlib.reload(m)

            async def run():
                request = MagicMock()
                request.form = AsyncMock(return_value={"username": "myadmin", "password": "errado"})
                resp = await m.admin_login_post(request)
                return resp

            resp = self._run(run())
            assert resp.status_code == 303
            assert "/admin/login?error=1" in resp.headers.get("location", "")

    def test_login_post_missing_env_redirects_with_config_error(self):
        """POST /admin/login sem ADMIN_USER/PASSWORD deve redirecionar para login?error=config."""
        import importlib
        import main as m

        with patch.dict(os.environ, {"ADMIN_USER": "", "ADMIN_PASSWORD": ""}, clear=False):
            importlib.reload(m)

            async def run():
                request = MagicMock()
                request.form = AsyncMock(return_value={"username": "x", "password": "y"})
                resp = await m.admin_login_post(request)
                return resp

            resp = self._run(run())
            assert resp.status_code == 303
            assert "/admin/login?error=config" in resp.headers.get("location", "")

    def test_sign_and_verify_cookie_roundtrip(self):
        """Cookie assinado deve ser verificável."""
        import importlib
        import main as m
        importlib.reload(m)

        cookie = m._sign_admin_cookie("admin")
        assert m._verify_admin_cookie(cookie) == "admin"

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
        import db

        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=0)  # não é novo
        mock_conn.execute = AsyncMock()
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        async def run():
            with patch("db.get_conn", return_value=mock_ctx):
                return await db.upsert_agent(
                    "ns1", "2026-01-01T00:00:00+00:00",
                    agent_version="1.2.3",
                )

        asyncio.run(run())
        sql_called = mock_conn.execute.call_args[0][0]
        assert "agent_version" in sql_called

    def test_upsert_agent_none_version_uses_coalesce(self):
        import db

        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=0)
        mock_conn.execute = AsyncMock()
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        async def run():
            with patch("db.get_conn", return_value=mock_ctx):
                return await db.upsert_agent(
                    "ns1", "2026-01-01T00:00:00+00:00",
                    agent_version=None,
                )

        asyncio.run(run())
        sql_called = mock_conn.execute.call_args[0][0]
        assert "COALESCE" in sql_called


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
        import main as m

        cmd = {"id": 42, "hostname": "ns1", "command": "update_agent",
               "status": "done", "result": "OK", "params": None}

        async def run():
            req = MagicMock()
            with patch("main.require_token", AsyncMock(return_value=None)), \
                 patch("main.db.get_command_by_id", AsyncMock(return_value=cmd)):
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
            with patch("main.require_token", AsyncMock(return_value=None)), \
                 patch("main.db.get_command_by_id", AsyncMock(return_value=None)):
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
            with patch("main.require_token", AsyncMock(return_value=None)), \
                 patch("main.db.insert_command", side_effect=fake_insert):
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

    def test_session_token_returns_token_with_admin_cookie(self):
        """GET /session/token com sessao admin retorna token."""
        import importlib, main as m
        with patch.dict(os.environ, {"AGENT_TOKEN": "tok-abc"}):
            importlib.reload(m)
            async def run():
                request = MagicMock()
                request.cookies = {"admin_session": m._sign_admin_cookie("admin"), "client_session": ""}
                return await m.session_token(request)
            resp = self._run(run())
            import json
            body = json.loads(resp.body)
            assert body["token"] == "tok-abc"

    def test_session_token_rejects_without_session(self):
        """GET /session/token sem sessao retorna 401."""
        import importlib, main as m
        importlib.reload(m)
        async def run():
            request = MagicMock()
            request.cookies = {"admin_session": "", "client_session": ""}
            return await m.session_token(request)
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            self._run(run())
        assert exc.value.status_code == 401


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
        import main as m
        resp = self._run(m.client_login_page())
        assert resp.status_code == 200
        assert "Portal do Cliente" in resp.body.decode()

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
# Entry point
# ===========================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])