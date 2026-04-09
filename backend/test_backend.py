"""
test_backend.py — Testes dos caminhos críticos do backend DNS Monitor.

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

    def test_real_schemas_sql_produces_51_statements(self):
        """Validação contra o arquivo real — deve produzir 51 statements."""
        schema_path = os.path.join(
            os.path.dirname(__file__),
            "backend", "schemas.sql"
        )
        if not os.path.exists(schema_path):
            pytest.skip("schemas.sql não encontrado — execute a partir da raiz do projeto")
        sql = open(schema_path).read()
        stmts = self._split(sql)
        assert len(stmts) == 51, f"Esperado 51 statements, obtido {len(stmts)}"

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
        # Resultado deve ser truncado a 200 chars
        assert "x" * 201 not in text


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
            with patch.dict("os.environ", {"AGENT_TOKEN": "tok"}),                  patch("main.require_token", AsyncMock(return_value=None)),                  patch("main.db.mark_command_done", AsyncMock()),                  patch("main.db.get_command_by_id", AsyncMock(return_value=cmd_data)),                  patch("main.tg.send_command_result", AsyncMock(return_value=True)) as mock_tg:
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
            with patch.dict("os.environ", {"AGENT_TOKEN": "tok"}),                  patch("main.require_token", AsyncMock(return_value=None)),                  patch("main.db.mark_command_done", AsyncMock()),                  patch("main.db.get_command_by_id", AsyncMock(return_value=cmd_data)),                  patch("main.tg.send_command_result", AsyncMock(return_value=True)) as mock_tg:
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
            with patch.dict("os.environ", {"AGENT_TOKEN": "tok"}),                  patch("main.require_token", AsyncMock(return_value=None)),                  patch("main.db.mark_command_done", AsyncMock()),                  patch("main.db.get_command_by_id", AsyncMock(return_value=None)),                  patch("main.tg.send_command_result", AsyncMock()) as mock_tg:
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
            with patch.object(pathlib.Path, "read_text", return_value=fake_html):
                resp = await m.admin_panel()
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
# Entry point
# ===========================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])