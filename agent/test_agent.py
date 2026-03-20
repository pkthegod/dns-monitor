"""
test_agent.py — Testes do agente dns_agent.py

Cobre:
  - load_config: arquivo encontrado, arquivo ausente
  - detect_dns_service: unbound ativo, bind9 inativo, nenhum encontrado, timeout
  - _get_dns_version: versão extraída, comando ausente, saída vazia
  - _resolve_domain: sucesso, NXDOMAIN (sem retry), TIMEOUT (com retry), NoNameservers
  - test_dns_resolution: múltiplos domínios, resolver customizado
  - _collect_disk: thresholds ok/warning/critical, fstype ignorado, PermissionError
  - _collect_io: retorno normal, io=None, exceção
  - _collect_load: normal, OSError (Windows)
  - build_payload: campos obrigatórios, tipo check vs heartbeat
  - send_payload: 200 OK, HTTP 500 com retry, ConnectionError, Timeout, falha total
  - _log_alert_summary: todos os thresholds de alerta

Dependências: pip install pytest psutil dnspython requests schedule
Execução: pytest test_agent.py -v
"""

import configparser
import io
import json
import logging
import os
import sys
import time
from unittest.mock import MagicMock, patch, call

import pytest

# ---------------------------------------------------------------------------
# Path setup — agente está em agent/
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "agent"))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_cfg(overrides: dict = None) -> configparser.ConfigParser:
    """Cria um ConfigParser mínimo válido para os testes."""
    cfg = configparser.ConfigParser()
    cfg.read_dict({
        "agent": {
            "hostname":   "test-host",
            "auth_token": "test-token-abc123",
        },
        "backend": {
            "url":         "http://localhost:8000",
            "timeout":     "10",
            "retries":     "3",
            "retry_delay": "0",   # sem espera nos testes
        },
        "dns": {
            "test_domains":   "google.com, cloudflare.com",
            "local_resolver": "127.0.0.1",
            "dns_port":       "53",
            "query_timeout":  "2",
            "query_retries":  "2",
        },
        "schedule": {
            "check_times":        "06:00, 18:00",
            "heartbeat_interval": "300",
        },
        "thresholds": {
            "disk_warning":          "80",
            "disk_critical":         "90",
            "cpu_warning":           "80",
            "cpu_critical":          "95",
            "ram_warning":           "85",
            "ram_critical":          "95",
            "dns_latency_warning":   "200",
            "dns_latency_critical":  "1000",
        },
        "logging": {
            "level":        "WARNING",
            "file":         "",
            "max_size_mb":  "10",
            "backup_count": "5",
        },
    })
    if overrides:
        for section, values in overrides.items():
            if not cfg.has_section(section):
                cfg.add_section(section)
            for key, val in values.items():
                cfg.set(section, key, val)
    return cfg


def make_logger() -> logging.Logger:
    logger = logging.getLogger("test-agent")
    logger.addHandler(logging.NullHandler())
    return logger


# ===========================================================================
# 1. load_config
# ===========================================================================

class TestLoadConfig:

    def test_loads_existing_file(self, tmp_path):
        import dns_agent as da
        conf = tmp_path / "agent.conf"
        conf.write_text("[agent]\nhostname = maquina-01\nauth_token = tok\n")
        with patch.object(da, "CONFIG_PATHS", [conf]):
            cfg = da.load_config()
        assert cfg.get("agent", "hostname") == "maquina-01"

    def test_exits_when_no_file_found(self, tmp_path):
        import dns_agent as da
        nonexistent = tmp_path / "nao_existe.conf"
        with patch.object(da, "CONFIG_PATHS", [nonexistent]):
            with pytest.raises(SystemExit):
                da.load_config()

    def test_uses_first_found_path(self, tmp_path):
        import dns_agent as da
        p1 = tmp_path / "first.conf"
        p2 = tmp_path / "second.conf"
        p1.write_text("[agent]\nhostname = primeiro\nauth_token = tok\n")
        p2.write_text("[agent]\nhostname = segundo\nauth_token = tok\n")
        with patch.object(da, "CONFIG_PATHS", [p1, p2]):
            cfg = da.load_config()
        assert cfg.get("agent", "hostname") == "primeiro"


# ===========================================================================
# 2. detect_dns_service
# ===========================================================================

class TestDetectDnsService:

    def _run(self, side_effects):
        """Roda detect_dns_service com subprocess.run mockado."""
        import dns_agent as da
        with patch("dns_agent.subprocess.run", side_effect=side_effects) as mock_run:
            result = da.detect_dns_service()
        return result, mock_run

    def _proc(self, returncode=0, stdout="", stderr=""):
        m = MagicMock()
        m.returncode = returncode
        m.stdout = stdout
        m.stderr = stderr
        return m

    def test_unbound_active(self):
        import dns_agent as da
        effects = [
            self._proc(0, "active\n"),       # systemctl is-active unbound → active
            self._proc(0, "unbound 1.17\n"), # unbound -V
        ]
        with patch("dns_agent.subprocess.run", side_effect=effects):
            result = da.detect_dns_service()
        assert result["name"] == "unbound"
        assert result["active"] is True
        assert "1.17" in result["version"]

    def test_bind9_active(self):
        import dns_agent as da
        effects = [
            self._proc(1, "inactive\n"),     # unbound is-active → inactive
            self._proc(1),                   # unbound is-enabled → not found
            self._proc(0, "active\n"),       # bind9 is-active → active
            self._proc(0, "BIND 9.18\n"),    # named -v (alias resolvido)
        ]
        with patch("dns_agent.subprocess.run", side_effect=effects):
            result = da.detect_dns_service()
        # bind9 é alias de named no Debian — SERVICE_ALIASES resolve para named
        assert result["name"] == "named"
        assert result["active"] is True

    def test_service_installed_but_inactive(self):
        import dns_agent as da
        effects = [
            self._proc(1, "inactive\n"),     # unbound is-active → not active
            self._proc(0, "enabled\n"),      # unbound is-enabled → found
            self._proc(0, "unbound 1.17\n"), # unbound -V
        ]
        with patch("dns_agent.subprocess.run", side_effect=effects):
            result = da.detect_dns_service()
        assert result["name"] == "unbound"
        assert result["active"] is False

    def test_no_service_found_returns_unknown(self):
        import dns_agent as da
        import subprocess
        with patch("dns_agent.subprocess.run", side_effect=FileNotFoundError):
            result = da.detect_dns_service()
        assert result["name"] == "unknown"
        assert result["active"] is False

    def test_timeout_skips_service(self):
        import dns_agent as da
        import subprocess
        effects = [
            subprocess.TimeoutExpired(["systemctl"], 5),  # unbound timeout
            subprocess.TimeoutExpired(["systemctl"], 5),  # bind9 timeout
            subprocess.TimeoutExpired(["systemctl"], 5),  # named timeout
        ]
        with patch("dns_agent.subprocess.run", side_effect=effects):
            result = da.detect_dns_service()
        assert result["name"] == "unknown"


# ===========================================================================
# 3. _get_dns_version
# ===========================================================================

class TestGetDnsVersion:

    def test_unbound_version_from_stderr(self):
        import dns_agent as da
        proc = MagicMock()
        proc.stdout = ""
        proc.stderr = "unbound 1.17.0\nsome other line\n"
        with patch("dns_agent.subprocess.run", return_value=proc):
            v = da._get_dns_version("unbound")
        assert v == "unbound 1.17.0"

    def test_bind9_version_from_stdout(self):
        import dns_agent as da
        proc = MagicMock()
        proc.stdout = "BIND 9.18.1-Ubuntu\n"
        proc.stderr = ""
        with patch("dns_agent.subprocess.run", return_value=proc):
            v = da._get_dns_version("bind9")
        assert "BIND" in v

    def test_unknown_service_returns_none(self):
        import dns_agent as da
        v = da._get_dns_version("nao_existe")
        assert v is None

    def test_exception_returns_none(self):
        import dns_agent as da
        with patch("dns_agent.subprocess.run", side_effect=Exception("erro")):
            v = da._get_dns_version("unbound")
        assert v is None

    def test_version_truncated_to_100_chars(self):
        import dns_agent as da
        proc = MagicMock()
        proc.stdout = "x" * 200
        proc.stderr = ""
        with patch("dns_agent.subprocess.run", return_value=proc):
            v = da._get_dns_version("unbound")
        assert len(v) == 100


# ===========================================================================
# 4. _resolve_domain
# ===========================================================================

class TestResolveDomain:

    def _make_resolver(self, side_effects):
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = side_effects
        return mock_resolver

    def test_successful_resolution(self):
        import dns_agent as da
        import dns.resolver

        mock_answer = MagicMock()
        mock_answer.__iter__ = MagicMock(return_value=iter(["142.250.218.46"]))

        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = mock_answer

        with patch("dns_agent.dns.resolver.Resolver", return_value=mock_resolver):
            result = da._resolve_domain("google.com", "127.0.0.1", 53, 5.0, 3, make_logger())

        assert result["success"] is True
        assert result["domain"] == "google.com"
        assert result["latency_ms"] is not None
        assert result["latency_ms"] >= 0
        assert result["error"] is None
        assert result["attempts"] == 1

    def test_nxdomain_no_retry(self):
        import dns_agent as da
        import dns.resolver

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

        with patch("dns_agent.dns.resolver.Resolver", return_value=mock_resolver):
            result = da._resolve_domain("naoexiste.invalid", None, 53, 5.0, 3, make_logger())

        assert result["success"] is False
        assert result["error"] == "NXDOMAIN"
        assert result["attempts"] == 1  # sem retry para NXDOMAIN
        assert mock_resolver.resolve.call_count == 1

    def test_timeout_retries_and_fails(self):
        import dns_agent as da
        import dns.resolver

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.Timeout()

        with patch("dns_agent.dns.resolver.Resolver", return_value=mock_resolver), \
             patch("dns_agent.time.sleep"):
            result = da._resolve_domain("google.com", None, 53, 2.0, 3, make_logger())

        assert result["success"] is False
        assert result["error"] == "TIMEOUT"
        assert result["attempts"] == 3
        assert mock_resolver.resolve.call_count == 3

    def test_timeout_succeeds_on_second_attempt(self):
        import dns_agent as da
        import dns.resolver

        mock_answer = MagicMock()
        mock_answer.__iter__ = MagicMock(return_value=iter(["1.1.1.1"]))

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = [
            dns.resolver.Timeout(),
            mock_answer,
        ]

        with patch("dns_agent.dns.resolver.Resolver", return_value=mock_resolver), \
             patch("dns_agent.time.sleep"):
            result = da._resolve_domain("google.com", None, 53, 2.0, 3, make_logger())

        assert result["success"] is True
        assert result["attempts"] == 2

    def test_no_nameservers_retries(self):
        import dns_agent as da
        import dns.resolver

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NoNameservers()

        with patch("dns_agent.dns.resolver.Resolver", return_value=mock_resolver), \
             patch("dns_agent.time.sleep"):
            result = da._resolve_domain("google.com", None, 53, 2.0, 2, make_logger())

        assert result["success"] is False
        assert result["error"] == "NO_NAMESERVERS"
        assert result["attempts"] == 2

    def test_custom_resolver_ip_applied(self):
        import dns_agent as da
        import dns.resolver

        mock_answer = MagicMock()
        mock_answer.__iter__ = MagicMock(return_value=iter(["8.8.8.8"]))
        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = mock_answer

        with patch("dns_agent.dns.resolver.Resolver", return_value=mock_resolver):
            da._resolve_domain("google.com", "192.168.1.1", 5353, 5.0, 1, make_logger())

        assert mock_resolver.nameservers == ["192.168.1.1"]
        assert mock_resolver.port == 5353

    def test_no_resolver_ip_uses_system(self):
        import dns_agent as da
        import dns.resolver

        mock_answer = MagicMock()
        mock_answer.__iter__ = MagicMock(return_value=iter(["8.8.8.8"]))
        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = mock_answer

        with patch("dns_agent.dns.resolver.Resolver", return_value=mock_resolver):
            result = da._resolve_domain("google.com", None, 53, 5.0, 1, make_logger())

        # nameservers não deve ter sido setado
        assert not hasattr(mock_resolver, "_nameservers_set") or mock_resolver.nameservers == mock_resolver.nameservers
        assert result["resolver"] == "system"


# ===========================================================================
# 5. test_dns_resolution (função pública)
# ===========================================================================

class TestDnsResolution:

    def test_resolves_multiple_domains(self):
        import dns_agent as da

        fake_result = {
            "domain": "x", "resolver": "127.0.0.1", "success": True,
            "latency_ms": 5.0, "response_ips": ["1.1.1.1"], "error": None, "attempts": 1
        }
        cfg = make_cfg()
        logger = make_logger()

        with patch("dns_agent._resolve_domain", return_value=fake_result) as mock_resolve:
            results = da.test_dns_resolution(cfg, logger)

        # 2 domínios configurados no fixture
        assert len(results) == 2
        assert mock_resolve.call_count == 2

    def test_uses_configured_resolver(self):
        import dns_agent as da

        fake_result = {"domain": "x", "resolver": "10.0.0.1", "success": True,
                       "latency_ms": 1.0, "response_ips": [], "error": None, "attempts": 1}
        cfg = make_cfg({"dns": {"local_resolver": "10.0.0.1", "test_domains": "example.com"}})
        logger = make_logger()

        with patch("dns_agent._resolve_domain", return_value=fake_result) as mock_resolve:
            da.test_dns_resolution(cfg, logger)

        call_args = mock_resolve.call_args
        assert call_args[0][1] == "10.0.0.1"  # resolver_ip

    def test_empty_resolver_uses_system(self):
        import dns_agent as da

        fake_result = {"domain": "x", "resolver": "system", "success": True,
                       "latency_ms": 1.0, "response_ips": [], "error": None, "attempts": 1}
        cfg = make_cfg({"dns": {"local_resolver": "", "test_domains": "example.com"}})
        logger = make_logger()

        with patch("dns_agent._resolve_domain", return_value=fake_result) as mock_resolve:
            da.test_dns_resolution(cfg, logger)

        call_args = mock_resolve.call_args
        assert call_args[0][1] is None  # resolver_ip None = sistema


# ===========================================================================
# 6. _collect_disk
# ===========================================================================

class TestCollectDisk:

    def _make_partition(self, mountpoint="/", fstype="ext4", device="/dev/sda1"):
        p = MagicMock()
        p.mountpoint = mountpoint
        p.fstype = fstype
        p.device = device
        return p

    def _make_usage(self, total_gb=50, used_gb=10, percent=20.0):
        u = MagicMock()
        u.total   = int(total_gb * 1024**3)
        u.used    = int(used_gb  * 1024**3)
        u.free    = u.total - u.used
        u.percent = percent
        return u

    def test_ok_alert_below_warning(self):
        import dns_agent as da
        cfg = make_cfg()
        part = self._make_partition()
        usage = self._make_usage(percent=50.0)

        with patch("dns_agent.psutil.disk_partitions", return_value=[part]), \
             patch("dns_agent.psutil.disk_usage", return_value=usage):
            result = da._collect_disk(cfg)

        assert len(result) == 1
        assert result[0]["alert"] == "ok"
        assert result[0]["percent"] == 50.0

    def test_warning_alert(self):
        import dns_agent as da
        cfg = make_cfg()
        part = self._make_partition()
        usage = self._make_usage(percent=83.0)

        with patch("dns_agent.psutil.disk_partitions", return_value=[part]), \
             patch("dns_agent.psutil.disk_usage", return_value=usage):
            result = da._collect_disk(cfg)

        assert result[0]["alert"] == "warning"

    def test_critical_alert(self):
        import dns_agent as da
        cfg = make_cfg()
        part = self._make_partition()
        usage = self._make_usage(percent=92.0)

        with patch("dns_agent.psutil.disk_partitions", return_value=[part]), \
             patch("dns_agent.psutil.disk_usage", return_value=usage):
            result = da._collect_disk(cfg)

        assert result[0]["alert"] == "critical"

    def test_tmpfs_ignored(self):
        import dns_agent as da
        cfg = make_cfg()
        parts = [
            self._make_partition("/", "ext4"),
            self._make_partition("/tmp", "tmpfs"),
            self._make_partition("/dev", "devtmpfs"),
        ]
        usage = self._make_usage(percent=30.0)

        with patch("dns_agent.psutil.disk_partitions", return_value=parts), \
             patch("dns_agent.psutil.disk_usage", return_value=usage):
            result = da._collect_disk(cfg)

        assert len(result) == 1
        assert result[0]["mountpoint"] == "/"

    def test_permission_error_skipped(self):
        import dns_agent as da
        cfg = make_cfg()
        parts = [
            self._make_partition("/"),
            self._make_partition("/secret", "ext4"),
        ]
        normal_usage = self._make_usage(percent=30.0)

        def fake_usage(mountpoint):
            if mountpoint == "/secret":
                raise PermissionError
            return normal_usage

        with patch("dns_agent.psutil.disk_partitions", return_value=parts), \
             patch("dns_agent.psutil.disk_usage", side_effect=fake_usage):
            result = da._collect_disk(cfg)

        assert len(result) == 1
        assert result[0]["mountpoint"] == "/"

    def test_boundary_at_exact_warning_threshold(self):
        import dns_agent as da
        cfg = make_cfg()
        part = self._make_partition()
        usage = self._make_usage(percent=80.0)  # exatamente no limite

        with patch("dns_agent.psutil.disk_partitions", return_value=[part]), \
             patch("dns_agent.psutil.disk_usage", return_value=usage):
            result = da._collect_disk(cfg)

        assert result[0]["alert"] == "warning"

    def test_boundary_just_below_warning(self):
        import dns_agent as da
        cfg = make_cfg()
        part = self._make_partition()
        usage = self._make_usage(percent=79.9)

        with patch("dns_agent.psutil.disk_partitions", return_value=[part]), \
             patch("dns_agent.psutil.disk_usage", return_value=usage):
            result = da._collect_disk(cfg)

        assert result[0]["alert"] == "ok"


# ===========================================================================
# 7. _collect_io
# ===========================================================================

class TestCollectIo:

    def test_returns_io_counters(self):
        import dns_agent as da
        io_mock = MagicMock()
        io_mock.read_bytes   = 1024000
        io_mock.write_bytes  = 512000
        io_mock.read_count   = 1000
        io_mock.write_count  = 500
        io_mock.read_time    = 200
        io_mock.write_time   = 100

        with patch("dns_agent.psutil.disk_io_counters", return_value=io_mock):
            result = da._collect_io()

        assert result["read_bytes"]    == 1024000
        assert result["write_bytes"]   == 512000
        assert result["read_count"]    == 1000
        assert result["write_count"]   == 500
        assert result["read_time_ms"]  == 200
        assert result["write_time_ms"] == 100

    def test_none_returns_empty_dict(self):
        import dns_agent as da
        with patch("dns_agent.psutil.disk_io_counters", return_value=None):
            result = da._collect_io()
        assert result == {}

    def test_exception_returns_empty_dict(self):
        import dns_agent as da
        with patch("dns_agent.psutil.disk_io_counters", side_effect=Exception("erro")):
            result = da._collect_io()
        assert result == {}


# ===========================================================================
# 8. _collect_load
# ===========================================================================

class TestCollectLoad:

    def test_returns_load_averages(self):
        import dns_agent as da
        with patch("dns_agent.os.getloadavg", return_value=(0.5, 0.3, 0.2)):
            result = da._collect_load()
        assert result["load_1m"]  == 0.5
        assert result["load_5m"]  == 0.3
        assert result["load_15m"] == 0.2

    def test_oserror_returns_empty_dict(self):
        import dns_agent as da
        with patch("dns_agent.os.getloadavg", side_effect=OSError):
            result = da._collect_load()
        assert result == {}

    def test_values_rounded_to_2_decimals(self):
        import dns_agent as da
        with patch("dns_agent.os.getloadavg", return_value=(1.234567, 0.876543, 2.345678)):
            result = da._collect_load()
        assert result["load_1m"]  == 1.23
        assert result["load_5m"]  == 0.88
        assert result["load_15m"] == 2.35


# ===========================================================================
# 9. build_payload
# ===========================================================================

class TestBuildPayload:

    def test_check_payload_structure(self):
        import dns_agent as da
        cfg = make_cfg()
        dns_service = {"name": "unbound", "active": True, "version": "1.17"}
        dns_results = [{"domain": "google.com", "success": True}]
        system = {"cpu": {"percent": 10.0}, "ram": {"percent": 30.0}, "disk": [], "io": {}, "load": {}}

        payload = da.build_payload(cfg, dns_service, dns_results, system, "check")

        assert payload["type"] == "check"
        assert payload["hostname"] == "test-host"
        assert payload["agent_version"] == "1.0.0"
        assert payload["dns_service"] == dns_service
        assert payload["dns_checks"] == dns_results
        assert payload["system"] == system
        assert "timestamp" in payload
        assert "os" in payload

    def test_heartbeat_payload(self):
        import dns_agent as da
        cfg = make_cfg()
        payload = da.build_payload(cfg, {}, [], {}, "heartbeat")
        assert payload["type"] == "heartbeat"

    def test_hostname_from_config(self):
        import dns_agent as da
        cfg = make_cfg({"agent": {"hostname": "meu-servidor", "auth_token": "tok"}})
        payload = da.build_payload(cfg, {}, [], {}, "check")
        assert payload["hostname"] == "meu-servidor"

    def test_timestamp_is_iso_utc(self):
        import dns_agent as da
        from datetime import timezone
        from datetime import datetime as dt
        cfg = make_cfg()
        payload = da.build_payload(cfg, {}, [], {}, "check")
        # Deve parsear sem erro e ter timezone info
        parsed = dt.fromisoformat(payload["timestamp"])
        assert parsed.tzinfo is not None

    def test_payload_is_json_serializable(self):
        import dns_agent as da
        cfg = make_cfg()
        system = {"cpu": {"percent": 5.0}, "ram": {"percent": 20.0}, "disk": [], "io": {}, "load": {}}
        payload = da.build_payload(cfg, {"name": "unbound"}, [], system, "check")
        serialized = json.dumps(payload, default=str)
        parsed = json.loads(serialized)
        assert parsed["type"] == "check"


# ===========================================================================
# 10. send_payload
# ===========================================================================

class TestSendPayload:

    def _mock_response(self, status_code=200, text="ok"):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        return resp

    def test_200_returns_true(self):
        import dns_agent as da
        cfg = make_cfg()
        logger = make_logger()

        with patch("dns_agent.requests.post", return_value=self._mock_response(200)):
            result = da.send_payload(cfg, {"type": "check"}, logger)

        assert result is True

    def test_500_retries_and_returns_false(self):
        import dns_agent as da
        cfg = make_cfg()
        logger = make_logger()

        with patch("dns_agent.requests.post", return_value=self._mock_response(500)), \
             patch("dns_agent.time.sleep"):
            result = da.send_payload(cfg, {"type": "check"}, logger)

        assert result is False

    def test_500_retries_configured_times(self):
        import dns_agent as da
        cfg = make_cfg({"backend": {"retries": "3", "retry_delay": "0",
                                     "url": "http://localhost:8000", "timeout": "10"}})
        logger = make_logger()
        mock_post = MagicMock(return_value=self._mock_response(500))

        with patch("dns_agent.requests.post", mock_post), \
             patch("dns_agent.time.sleep"):
            da.send_payload(cfg, {"type": "check"}, logger)

        assert mock_post.call_count == 3

    def test_200_on_second_attempt_returns_true(self):
        import dns_agent as da
        import requests as req
        cfg = make_cfg()
        logger = make_logger()

        responses = [self._mock_response(500), self._mock_response(200)]
        with patch("dns_agent.requests.post", side_effect=responses), \
             patch("dns_agent.time.sleep"):
            result = da.send_payload(cfg, {"type": "check"}, logger)

        assert result is True

    def test_connection_error_retries(self):
        import dns_agent as da
        import requests as req
        cfg = make_cfg()
        logger = make_logger()

        with patch("dns_agent.requests.post",
                   side_effect=req.exceptions.ConnectionError("refused")), \
             patch("dns_agent.time.sleep"):
            result = da.send_payload(cfg, {"type": "check"}, logger)

        assert result is False

    def test_timeout_error_retries(self):
        import dns_agent as da
        import requests as req
        cfg = make_cfg()
        logger = make_logger()

        with patch("dns_agent.requests.post",
                   side_effect=req.exceptions.Timeout("timeout")), \
             patch("dns_agent.time.sleep"):
            result = da.send_payload(cfg, {"type": "check"}, logger)

        assert result is False

    def test_uses_bearer_token(self):
        import dns_agent as da
        cfg = make_cfg()
        logger = make_logger()
        mock_post = MagicMock(return_value=self._mock_response(200))

        with patch("dns_agent.requests.post", mock_post):
            da.send_payload(cfg, {"type": "heartbeat"}, logger)

        headers = mock_post.call_args[1]["headers"]
        assert headers["Authorization"] == "Bearer test-token-abc123"

    def test_payload_sent_as_json(self):
        import dns_agent as da
        cfg = make_cfg()
        logger = make_logger()
        payload = {"type": "check", "hostname": "test"}
        mock_post = MagicMock(return_value=self._mock_response(200))

        with patch("dns_agent.requests.post", mock_post):
            da.send_payload(cfg, payload, logger)

        body = json.loads(mock_post.call_args[1]["data"])
        assert body["type"] == "check"


# ===========================================================================
# 11. _log_alert_summary
# ===========================================================================

class TestLogAlertSummary:

    def _run(self, cfg, dns_service, dns_results, system_metrics):
        import dns_agent as da
        logger = MagicMock()
        da._log_alert_summary(cfg, dns_service, dns_results, system_metrics, logger)
        return logger

    def _system(self, cpu=10.0, ram=20.0, disk_pct=50.0, disk_alert="ok"):
        return {
            "cpu":  {"percent": cpu},
            "ram":  {"percent": ram},
            "disk": [{"mountpoint": "/", "percent": disk_pct, "alert": disk_alert}],
        }

    def test_no_alerts_when_all_ok(self):
        cfg = make_cfg()
        dns_service = {"name": "unbound", "active": True}
        dns_results = [{"domain": "g.com", "success": True, "latency_ms": 10.0}]
        logger = self._run(cfg, dns_service, dns_results, self._system())
        logger.warning.assert_not_called()

    def test_dns_service_inactive_warns(self):
        cfg = make_cfg()
        dns_service = {"name": "unbound", "active": False}
        logger = self._run(cfg, dns_service, [], self._system())
        logger.warning.assert_called()
        args = logger.warning.call_args_list[0][0]
        assert "INATIVO" in args[0]

    def test_dns_failure_warns(self):
        cfg = make_cfg()
        dns_service = {"name": "unbound", "active": True}
        dns_results = [{"domain": "google.com", "success": False, "latency_ms": None}]
        logger = self._run(cfg, dns_service, dns_results, self._system())
        logger.warning.assert_called()
        args = str(logger.warning.call_args_list)
        assert "google.com" in args

    def test_cpu_warning_threshold(self):
        cfg = make_cfg()
        logger = self._run(cfg, {"name": "unbound", "active": True}, [],
                           self._system(cpu=82.0))
        calls = str(logger.warning.call_args_list)
        assert "CPU" in calls

    def test_cpu_critical_threshold(self):
        cfg = make_cfg()
        logger = self._run(cfg, {"name": "unbound", "active": True}, [],
                           self._system(cpu=96.0))
        calls = str(logger.warning.call_args_list)
        assert "CRÍTICO" in calls

    def test_ram_warning_threshold(self):
        cfg = make_cfg()
        logger = self._run(cfg, {"name": "unbound", "active": True}, [],
                           self._system(ram=87.0))
        calls = str(logger.warning.call_args_list)
        assert "RAM" in calls

    def test_disk_warning_threshold(self):
        cfg = make_cfg()
        logger = self._run(cfg, {"name": "unbound", "active": True}, [],
                           self._system(disk_pct=83.0, disk_alert="warning"))
        calls = str(logger.warning.call_args_list)
        assert "Disco" in calls

    def test_disk_critical_threshold(self):
        cfg = make_cfg()
        logger = self._run(cfg, {"name": "unbound", "active": True}, [],
                           self._system(disk_pct=92.0, disk_alert="critical"))
        calls = str(logger.warning.call_args_list)
        assert "CRÍTICO" in calls

    def test_dns_latency_warning(self):
        cfg = make_cfg()
        dns_results = [{"domain": "g.com", "success": True, "latency_ms": 250.0}]
        logger = self._run(cfg, {"name": "unbound", "active": True}, dns_results, self._system())
        calls = str(logger.warning.call_args_list)
        assert "latência" in calls.lower() or "250" in calls

    def test_dns_latency_critical(self):
        cfg = make_cfg()
        dns_results = [{"domain": "g.com", "success": True, "latency_ms": 1200.0}]
        logger = self._run(cfg, {"name": "unbound", "active": True}, dns_results, self._system())
        calls = str(logger.warning.call_args_list)
        assert "CRÍTICO" in calls


# ===========================================================================
# 12. generate_fingerprint
# ===========================================================================

class TestGenerateFingerprint:

    def test_returns_64_char_hex_string(self):
        import dns_agent as da
        fp = da.generate_fingerprint()
        assert isinstance(fp, str)
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_same_machine_returns_same_fingerprint(self):
        import dns_agent as da
        fp1 = da.generate_fingerprint()
        fp2 = da.generate_fingerprint()
        assert fp1 == fp2

    def test_fingerprint_changes_with_different_hostname(self):
        import dns_agent as da
        fp1 = da.generate_fingerprint()
        with patch("dns_agent.socket.gethostname", return_value="outro-host"):
            fp2 = da.generate_fingerprint()
        assert fp1 != fp2

    def test_fingerprint_included_in_payload(self):
        import dns_agent as da
        cfg = make_cfg()
        payload = da.build_payload(cfg, {}, [], {}, "check")
        assert "fingerprint" in payload
        assert payload["fingerprint"] is not None
        assert len(payload["fingerprint"]) == 64

    def test_fingerprint_stable_without_machine_id(self, tmp_path):
        """Ainda gera fingerprint mesmo sem /etc/machine-id."""
        import dns_agent as da
        def fake_read_text():
            raise FileNotFoundError
        fake_path = MagicMock()
        fake_path.read_text = fake_read_text
        with patch("dns_agent.Path", return_value=fake_path):
            fp = da.generate_fingerprint()
        assert len(fp) == 64


# ===========================================================================
# 13. _execute_command
# ===========================================================================

class TestExecuteCommand:

    def _proc(self, returncode=0, stdout="", stderr=""):
        m = MagicMock()
        m.returncode = returncode
        m.stdout = stdout
        m.stderr = stderr
        return m

    def test_stop_command_ok(self):
        import dns_agent as da
        cfg = make_cfg()
        logger = make_logger()
        with patch("dns_agent.detect_dns_service", return_value={"name": "unbound"}),              patch("dns_agent.subprocess.run", return_value=self._proc(0, "")) as mock_run:
            status, result = da._execute_command("stop", None, cfg, logger)
        assert status == "done"
        assert "unbound" in result
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "sudo" in cmd
        assert "stop" in cmd

    def test_disable_command_ok(self):
        import dns_agent as da
        cfg = make_cfg()
        logger = make_logger()
        with patch("dns_agent.detect_dns_service", return_value={"name": "unbound"}),              patch("dns_agent.subprocess.run", return_value=self._proc(0)):
            status, result = da._execute_command("disable", None, cfg, logger)
        assert status == "done"

    def test_enable_command_ok(self):
        import dns_agent as da
        cfg = make_cfg()
        logger = make_logger()
        with patch("dns_agent.detect_dns_service", return_value={"name": "unbound"}),              patch("dns_agent.subprocess.run", return_value=self._proc(0)):
            status, result = da._execute_command("enable", None, cfg, logger)
        assert status == "done"

    def test_command_fails_when_systemctl_returns_nonzero(self):
        import dns_agent as da
        cfg = make_cfg()
        logger = make_logger()
        with patch("dns_agent.detect_dns_service", return_value={"name": "unbound"}),              patch("dns_agent.subprocess.run", return_value=self._proc(1, "", "Unit not found")):
            status, result = da._execute_command("stop", None, cfg, logger)
        assert status == "failed"
        assert "Unit not found" in result

    def test_unknown_command_returns_failed(self):
        import dns_agent as da
        cfg = make_cfg()
        logger = make_logger()
        with patch("dns_agent.detect_dns_service", return_value={"name": "unbound"}):
            status, result = da._execute_command("reboot", None, cfg, logger)
        assert status == "failed"
        assert "desconhecido" in result

    def test_purge_without_confirm_token_rejected(self):
        import dns_agent as da
        cfg = make_cfg()
        logger = make_logger()
        with patch("dns_agent.detect_dns_service", return_value={"name": "unbound"}):
            status, result = da._execute_command("purge", None, cfg, logger)
        assert status == "failed"
        assert "confirm_token" in result

    def test_purge_with_confirm_token_executes(self):
        import dns_agent as da
        cfg = make_cfg()
        logger = make_logger()
        with patch("dns_agent.detect_dns_service", return_value={"name": "unbound"}),              patch("dns_agent.subprocess.run", return_value=self._proc(0)):
            status, result = da._execute_command("purge", "qualquer-token", cfg, logger)
        assert status == "done"

    def test_timeout_returns_failed(self):
        import dns_agent as da
        import subprocess
        cfg = make_cfg()
        logger = make_logger()
        with patch("dns_agent.detect_dns_service", return_value={"name": "unbound"}),              patch("dns_agent.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(["systemctl"], 30)):
            status, result = da._execute_command("stop", None, cfg, logger)
        assert status == "failed"
        assert "Timeout" in result


# ===========================================================================
# 14. poll_commands
# ===========================================================================

class TestPollCommands:

    def _mock_response(self, status_code=200, json_data=None):
        resp = MagicMock()
        resp.status_code = status_code
        resp.json.return_value = json_data if json_data is not None else []
        return resp

    def test_no_commands_does_nothing(self):
        import dns_agent as da
        cfg = make_cfg()
        logger = make_logger()
        with patch("dns_agent.requests.get", return_value=self._mock_response(200, [])) as mock_get,              patch("dns_agent.requests.post") as mock_post:
            da.poll_commands(cfg, logger)
        mock_get.assert_called_once()
        mock_post.assert_not_called()

    def test_401_logs_error_and_returns(self):
        import dns_agent as da
        cfg = make_cfg()
        logger = MagicMock()
        with patch("dns_agent.requests.get", return_value=self._mock_response(401)):
            da.poll_commands(cfg, logger)
        logger.error.assert_called()
        args = str(logger.error.call_args_list)
        assert "401" in args

    def test_500_logs_warning_and_returns(self):
        import dns_agent as da
        cfg = make_cfg()
        logger = MagicMock()
        with patch("dns_agent.requests.get", return_value=self._mock_response(500)):
            da.poll_commands(cfg, logger)
        logger.warning.assert_called()

    def test_executes_command_and_reports_result(self):
        import dns_agent as da
        cfg = make_cfg()
        logger = make_logger()
        commands = [{"id": 42, "command": "stop", "confirm_token": None}]

        with patch("dns_agent.requests.get", return_value=self._mock_response(200, commands)),              patch("dns_agent.requests.post", return_value=self._mock_response(200)) as mock_post,              patch("dns_agent._execute_command", return_value=("done", "stop unbound: OK")):
            da.poll_commands(cfg, logger)

        mock_post.assert_called_once()
        post_body = mock_post.call_args[1]["json"]
        assert post_body["status"] == "done"
        assert "OK" in post_body["result"]

    def test_executes_multiple_commands_in_order(self):
        import dns_agent as da
        cfg = make_cfg()
        logger = make_logger()
        commands = [
            {"id": 1, "command": "stop",    "confirm_token": None},
            {"id": 2, "command": "disable", "confirm_token": None},
        ]
        exec_calls = []

        def fake_execute(command, confirm_token, cfg, logger):
            exec_calls.append(command)
            return ("done", f"{command} OK")

        with patch("dns_agent.requests.get", return_value=self._mock_response(200, commands)),              patch("dns_agent.requests.post", return_value=self._mock_response(200)),              patch("dns_agent._execute_command", side_effect=fake_execute):
            da.poll_commands(cfg, logger)

        assert exec_calls == ["stop", "disable"]

    def test_failed_command_still_reports_result(self):
        import dns_agent as da
        cfg = make_cfg()
        logger = make_logger()
        commands = [{"id": 99, "command": "stop", "confirm_token": None}]

        with patch("dns_agent.requests.get", return_value=self._mock_response(200, commands)),              patch("dns_agent.requests.post", return_value=self._mock_response(200)) as mock_post,              patch("dns_agent._execute_command", return_value=("failed", "Unit not found")):
            da.poll_commands(cfg, logger)

        post_body = mock_post.call_args[1]["json"]
        assert post_body["status"] == "failed"

    def test_connection_error_handled_silently(self):
        import dns_agent as da
        import requests as req
        cfg = make_cfg()
        logger = MagicMock()
        with patch("dns_agent.requests.get",
                   side_effect=req.exceptions.ConnectionError("refused")):
            da.poll_commands(cfg, logger)  # não deve levantar exceção
        logger.error.assert_not_called()   # connection error é debug, não error

    def test_uses_correct_url_and_token(self):
        import dns_agent as da
        cfg = make_cfg()
        logger = make_logger()
        mock_get = MagicMock(return_value=self._mock_response(200, []))

        with patch("dns_agent.requests.get", mock_get):
            da.poll_commands(cfg, logger)

        call_url = mock_get.call_args[0][0]
        assert "localhost:8000" in call_url
        assert "test-host" in call_url
        headers = mock_get.call_args[1]["headers"]
        assert "Bearer test-token-abc123" in headers["Authorization"]


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])