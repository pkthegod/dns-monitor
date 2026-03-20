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
            asyncio.get_event_loop().run_until_complete(m.require_token(request))
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
                asyncio.get_event_loop().run_until_complete(m.require_token(request))
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
                asyncio.get_event_loop().run_until_complete(m.require_token(request))
            assert exc_info.value.status_code == 401

    def test_empty_agent_token_env_skips_auth(self):
        """Se AGENT_TOKEN não configurado, auth é pulada (com warning)."""
        from fastapi import Request

        request = MagicMock(spec=Request)
        request.headers = {}

        with patch.dict(os.environ, {"AGENT_TOKEN": ""}):
            import importlib
            import main as m
            importlib.reload(m)
            # Não deve levantar exceção
            asyncio.get_event_loop().run_until_complete(m.require_token(request))


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
        return asyncio.get_event_loop().run_until_complete(coro)

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
        return asyncio.get_event_loop().run_until_complete(coro)

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
            asyncio.get_event_loop().run_until_complete(m.job_send_report())

        assert captured["total_agents"] == 4
        assert captured["online_agents"] == 2
        assert set(captured["offline_agents"]) == {"h2", "h3"}


# ===========================================================================
# 5. job_check_offline — ANTI-SPAM
# ===========================================================================

class TestJobCheckOffline:
    """Verifica que o job de detecção de offline não gera spam de alertas."""

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

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
        return asyncio.get_event_loop().run_until_complete(coro)

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
# Entry point
# ===========================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])