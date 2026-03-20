"""
test_grafana.py — Validação dos dashboards Grafana do DNS Monitor.

Cobre:
  - Estrutura obrigatória dos dashboards (uid, title, timezone, refresh)
  - Datasource uid consistente em todos os painéis
  - Presença e IDs de todos os painéis esperados
  - Queries SQL sintaticamente válidas (sem parênteses/aspas abertas)
  - Variável $hostname no host-detail (template variable)
  - Campos de configuração críticos (thresholds, units, format)
  - Provisioning YAML (datasource e provider)
  - Consistência entre overview e host-detail (sem painéis duplicados)
  - Queries de série temporal usam time_bucket (TimescaleDB)
  - Todas as queries referenciam tabelas existentes no schema

Execução: pytest test_grafana.py -v
"""

import json
import os
import re
import sys

import pytest
import yaml

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE = os.path.join(os.path.dirname(__file__), "grafana")
BACKEND = os.path.join(os.path.dirname(__file__), "backend")

OVERVIEW_PATH     = os.path.join(BASE, "dashboards", "overview.json")
HOST_DETAIL_PATH  = os.path.join(BASE, "dashboards", "host-detail.json")
DATASOURCE_PATH   = os.path.join(BASE, "provisioning", "datasources", "timescaledb.yaml")
PROVIDER_PATH     = os.path.join(BASE, "provisioning", "dashboards", "provider.yaml")
SCHEMA_PATH       = os.path.join(BACKEND, "schemas.sql")

DATASOURCE_UID = "timescaledb-dns"

# Tabelas/views definidas no schema
KNOWN_TABLES = {
    "agent_heartbeats", "metrics_cpu", "metrics_ram", "metrics_disk",
    "metrics_io", "dns_checks", "dns_service_status", "alerts_log",
    "agents", "v_agent_current_status",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def load_yaml(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)

def get_panels(dashboard: dict) -> list:
    return dashboard.get("panels", [])

def get_all_sql(dashboard: dict) -> list[str]:
    """Extrai todas as rawSql de todos os painéis."""
    sqls = []
    for panel in get_panels(dashboard):
        for target in panel.get("targets", []):
            sql = target.get("rawSql", "").strip()
            if sql:
                sqls.append(sql)
    return sqls


# ===========================================================================
# 1. ARQUIVOS EXISTEM
# ===========================================================================

class TestFilesExist:

    def test_overview_json_exists(self):
        assert os.path.exists(OVERVIEW_PATH), f"Não encontrado: {OVERVIEW_PATH}"

    def test_host_detail_json_exists(self):
        assert os.path.exists(HOST_DETAIL_PATH), f"Não encontrado: {HOST_DETAIL_PATH}"

    def test_datasource_yaml_exists(self):
        assert os.path.exists(DATASOURCE_PATH), f"Não encontrado: {DATASOURCE_PATH}"

    def test_provider_yaml_exists(self):
        assert os.path.exists(PROVIDER_PATH), f"Não encontrado: {PROVIDER_PATH}"

    def test_overview_is_valid_json(self):
        d = load_json(OVERVIEW_PATH)
        assert isinstance(d, dict)

    def test_host_detail_is_valid_json(self):
        d = load_json(HOST_DETAIL_PATH)
        assert isinstance(d, dict)

    def test_datasource_is_valid_yaml(self):
        d = load_yaml(DATASOURCE_PATH)
        assert isinstance(d, dict)

    def test_provider_is_valid_yaml(self):
        d = load_yaml(PROVIDER_PATH)
        assert isinstance(d, dict)


# ===========================================================================
# 2. ESTRUTURA DOS DASHBOARDS
# ===========================================================================

class TestDashboardStructure:

    @pytest.fixture(scope="class")
    def overview(self):
        return load_json(OVERVIEW_PATH)

    @pytest.fixture(scope="class")
    def host_detail(self):
        return load_json(HOST_DETAIL_PATH)

    # Overview
    def test_overview_has_uid(self, overview):
        assert overview.get("uid") == "dns-overview"

    def test_overview_has_title(self, overview):
        assert "DNS Monitor" in overview.get("title", "")

    def test_overview_has_timezone(self, overview):
        assert overview.get("timezone") == "America/Sao_Paulo"

    def test_overview_has_refresh(self, overview):
        assert overview.get("refresh") == "1m"

    def test_overview_has_panels(self, overview):
        panels = get_panels(overview)
        assert len(panels) > 0

    def test_overview_has_8_panels(self, overview):
        assert len(get_panels(overview)) == 8

    # Host Detail
    def test_host_detail_has_uid(self, host_detail):
        assert host_detail.get("uid") == "dns-host-detail"

    def test_host_detail_has_title(self, host_detail):
        assert "DNS Monitor" in host_detail.get("title", "")

    def test_host_detail_has_timezone(self, host_detail):
        assert host_detail.get("timezone") == "America/Sao_Paulo"

    def test_host_detail_has_refresh(self, host_detail):
        assert host_detail.get("refresh") == "1m"

    def test_host_detail_has_12_panels(self, host_detail):
        assert len(get_panels(host_detail)) == 12

    def test_host_detail_has_hostname_template_variable(self, host_detail):
        variables = host_detail.get("templating", {}).get("list", [])
        names = [v["name"] for v in variables]
        assert "hostname" in names

    def test_hostname_variable_queries_agents_table(self, host_detail):
        variables = host_detail.get("templating", {}).get("list", [])
        hv = next((v for v in variables if v["name"] == "hostname"), None)
        assert hv is not None
        assert "agents" in hv.get("query", "").lower()

    def test_hostname_variable_uses_correct_datasource(self, host_detail):
        variables = host_detail.get("templating", {}).get("list", [])
        hv = next((v for v in variables if v["name"] == "hostname"), None)
        ds = hv.get("datasource", {})
        assert ds.get("uid") == DATASOURCE_UID


# ===========================================================================
# 3. DATASOURCE UID CONSISTENTE
# ===========================================================================

class TestDatasourceConsistency:

    def _check_all_panels(self, dashboard_path):
        d = load_json(dashboard_path)
        errors = []
        for panel in get_panels(d):
            ds = panel.get("datasource", {})
            uid = ds.get("uid") if isinstance(ds, dict) else ds
            if uid and uid != DATASOURCE_UID:
                errors.append(f"Panel {panel['id']} '{panel['title']}': uid='{uid}'")
        return errors

    def test_overview_all_panels_use_correct_datasource(self):
        errors = self._check_all_panels(OVERVIEW_PATH)
        assert errors == [], f"UIDs incorretos: {errors}"

    def test_host_detail_all_panels_use_correct_datasource(self):
        errors = self._check_all_panels(HOST_DETAIL_PATH)
        assert errors == [], f"UIDs incorretos: {errors}"

    def test_datasource_yaml_uid_matches(self):
        d = load_yaml(DATASOURCE_PATH)
        ds = d["datasources"][0]
        assert ds["uid"] == DATASOURCE_UID

    def test_datasource_yaml_type_is_postgres(self):
        d = load_yaml(DATASOURCE_PATH)
        assert d["datasources"][0]["type"] == "postgres"

    def test_datasource_yaml_timescaledb_enabled(self):
        d = load_yaml(DATASOURCE_PATH)
        assert d["datasources"][0]["jsonData"].get("timescaledb") is True

    def test_datasource_yaml_sslmode_disable(self):
        d = load_yaml(DATASOURCE_PATH)
        assert d["datasources"][0]["jsonData"].get("sslmode") == "disable"

    def test_datasource_yaml_points_to_correct_host(self):
        d = load_yaml(DATASOURCE_PATH)
        url = d["datasources"][0]["url"]
        assert "172.20.0.10" in url
        assert "5432" in url


# ===========================================================================
# 4. PAINÉIS ESPERADOS (IDs e tipos)
# ===========================================================================

class TestExpectedPanels:

    @pytest.fixture(scope="class")
    def overview_panels(self):
        return {p["id"]: p for p in get_panels(load_json(OVERVIEW_PATH))}

    @pytest.fixture(scope="class")
    def host_panels(self):
        return {p["id"]: p for p in get_panels(load_json(HOST_DETAIL_PATH))}

    # Overview
    def test_overview_has_agents_online_stat(self, overview_panels):
        assert 1 in overview_panels
        assert overview_panels[1]["type"] == "stat"

    def test_overview_has_agents_offline_stat(self, overview_panels):
        assert 2 in overview_panels
        assert overview_panels[2]["type"] == "stat"

    def test_overview_has_alerts_stat(self, overview_panels):
        assert 3 in overview_panels

    def test_overview_has_dns_success_rate_stat(self, overview_panels):
        assert 4 in overview_panels

    def test_overview_has_agents_table(self, overview_panels):
        assert 10 in overview_panels
        assert overview_panels[10]["type"] == "table"

    def test_overview_has_dns_failures_chart(self, overview_panels):
        assert 20 in overview_panels

    def test_overview_has_dns_latency_chart(self, overview_panels):
        assert 21 in overview_panels

    def test_overview_has_alerts_table(self, overview_panels):
        assert 30 in overview_panels
        assert overview_panels[30]["type"] == "table"

    # Host detail
    def test_host_detail_has_agent_status(self, host_panels):
        assert 1 in host_panels
        assert host_panels[1]["type"] == "stat"

    def test_host_detail_has_cpu_gauge(self, host_panels):
        assert 2 in host_panels
        assert host_panels[2]["type"] == "gauge"

    def test_host_detail_has_ram_gauge(self, host_panels):
        assert 3 in host_panels
        assert host_panels[3]["type"] == "gauge"

    def test_host_detail_has_dns_service_stat(self, host_panels):
        assert 4 in host_panels

    def test_host_detail_has_cpu_timeseries(self, host_panels):
        assert 10 in host_panels
        assert host_panels[10]["type"] == "timeseries"

    def test_host_detail_has_ram_timeseries(self, host_panels):
        assert 11 in host_panels
        assert host_panels[11]["type"] == "timeseries"

    def test_host_detail_has_disk_timeseries(self, host_panels):
        assert 20 in host_panels
        assert host_panels[20]["type"] == "timeseries"

    def test_host_detail_has_io_timeseries(self, host_panels):
        assert 21 in host_panels
        assert host_panels[21]["type"] == "timeseries"

    def test_host_detail_has_dns_latency_timeseries(self, host_panels):
        assert 30 in host_panels
        assert host_panels[30]["type"] == "timeseries"

    def test_host_detail_has_dns_results_table(self, host_panels):
        assert 31 in host_panels
        assert host_panels[31]["type"] == "table"

    def test_host_detail_has_load_timeseries(self, host_panels):
        assert 40 in host_panels
        assert host_panels[40]["type"] == "timeseries"

    def test_host_detail_has_swap_timeseries(self, host_panels):
        assert 41 in host_panels
        assert host_panels[41]["type"] == "timeseries"


# ===========================================================================
# 5. QUALIDADE DAS QUERIES SQL
# ===========================================================================

class TestSqlQueries:

    @pytest.fixture(scope="class")
    def all_overview_sqls(self):
        return get_all_sql(load_json(OVERVIEW_PATH))

    @pytest.fixture(scope="class")
    def all_host_sqls(self):
        return get_all_sql(load_json(HOST_DETAIL_PATH))

    def _check_balanced(self, sql: str) -> bool:
        """Verifica parênteses balanceados."""
        count = 0
        for c in sql:
            if c == "(":
                count += 1
            elif c == ")":
                count -= 1
            if count < 0:
                return False
        return count == 0

    def _check_quotes(self, sql: str) -> bool:
        """Verifica aspas simples balanceadas (fora de strings escapadas)."""
        count = sql.count("'") - sql.count("\\'")
        return count % 2 == 0

    def test_overview_all_queries_have_balanced_parens(self, all_overview_sqls):
        for sql in all_overview_sqls:
            assert self._check_balanced(sql), f"Parênteses desbalanceados:\n{sql}"

    def test_host_detail_all_queries_have_balanced_parens(self, all_host_sqls):
        for sql in all_host_sqls:
            assert self._check_balanced(sql), f"Parênteses desbalanceados:\n{sql}"

    def test_overview_all_queries_have_balanced_quotes(self, all_overview_sqls):
        for sql in all_overview_sqls:
            assert self._check_quotes(sql), f"Aspas desbalanceadas:\n{sql}"

    def test_host_detail_all_queries_have_balanced_quotes(self, all_host_sqls):
        for sql in all_host_sqls:
            assert self._check_quotes(sql), f"Aspas desbalanceadas:\n{sql}"

    def test_overview_queries_reference_known_tables(self, all_overview_sqls):
        for sql in all_overview_sqls:
            tables = re.findall(r'\bFROM\s+(\w+)', sql, re.IGNORECASE)
            for t in tables:
                assert t in KNOWN_TABLES, f"Tabela desconhecida '{t}' em:\n{sql}"

    def test_host_detail_queries_reference_known_tables(self, all_host_sqls):
        for sql in all_host_sqls:
            tables = re.findall(r'\bFROM\s+(\w+)', sql, re.IGNORECASE)
            for t in tables:
                assert t in KNOWN_TABLES, f"Tabela desconhecida '{t}' em:\n{sql}"

    def test_host_detail_queries_use_hostname_variable(self, all_host_sqls):
        """Queries que filtram por host devem usar $hostname."""
        for sql in all_host_sqls:
            if "WHERE" in sql.upper() and "hostname" in sql.lower():
                assert "$hostname" in sql, f"Query com WHERE hostname sem variável:\n{sql}"

    def test_timeseries_panels_use_time_bucket(self, all_host_sqls):
        """Painéis de série temporal devem usar time_bucket (TimescaleDB)."""
        timeseries_sqls = [s for s in all_host_sqls if "time_bucket" in s.lower() or "AS time" in s]
        assert len(timeseries_sqls) > 0, "Nenhuma query usa time_bucket"

    def test_overview_dns_success_rate_divides_correctly(self, all_overview_sqls):
        """A taxa de sucesso DNS deve calcular percentual."""
        rate_sqls = [s for s in all_overview_sqls if "success" in s.lower() and "count" in s.lower()]
        assert len(rate_sqls) > 0
        # Deve ter divisão para percentual
        assert any("/" in s for s in rate_sqls)

    def test_host_detail_io_query_calculates_rate(self, all_host_sqls):
        """Query de I/O deve calcular delta (bytes por segundo)."""
        io_sqls = [s for s in all_host_sqls if "read_bytes" in s or "write_bytes" in s]
        assert len(io_sqls) > 0
        # Deve ter MAX - MIN para delta
        assert any("MAX" in s and "MIN" in s for s in io_sqls)

    def test_alerts_table_converts_timezone(self, all_overview_sqls):
        """Tabela de alertas deve converter timezone para Sao_Paulo."""
        alert_sqls = [s for s in all_overview_sqls if "alerts_log" in s]
        assert len(alert_sqls) > 0
        assert any("Sao_Paulo" in s or "America" in s for s in alert_sqls)

    def test_host_detail_dns_results_converts_timezone(self, all_host_sqls):
        dns_sqls = [s for s in all_host_sqls if "dns_checks" in s and "horario" in s]
        assert len(dns_sqls) > 0
        assert any("Sao_Paulo" in s for s in dns_sqls)


# ===========================================================================
# 6. THRESHOLDS E CONFIGURAÇÃO DOS PAINÉIS
# ===========================================================================

class TestPanelConfig:

    @pytest.fixture(scope="class")
    def host_panels(self):
        return {p["id"]: p for p in get_panels(load_json(HOST_DETAIL_PATH))}

    @pytest.fixture(scope="class")
    def overview_panels(self):
        return {p["id"]: p for p in get_panels(load_json(OVERVIEW_PATH))}

    def _get_thresholds(self, panel) -> list:
        return panel.get("fieldConfig", {}).get("defaults", {}) \
                    .get("thresholds", {}).get("steps", [])

    def _get_unit(self, panel) -> str:
        return panel.get("fieldConfig", {}).get("defaults", {}).get("unit", "")

    def test_cpu_gauge_has_percent_unit(self, host_panels):
        assert self._get_unit(host_panels[2]) == "percent"

    def test_ram_gauge_has_percent_unit(self, host_panels):
        assert self._get_unit(host_panels[3]) == "percent"

    def test_cpu_gauge_has_thresholds(self, host_panels):
        steps = self._get_thresholds(host_panels[2])
        assert len(steps) >= 3

    def test_cpu_gauge_thresholds_values(self, host_panels):
        steps = self._get_thresholds(host_panels[2])
        values = [s.get("value") for s in steps if s.get("value") is not None]
        assert 80 in values   # warning
        assert 95 in values   # critical

    def test_ram_gauge_thresholds_values(self, host_panels):
        steps = self._get_thresholds(host_panels[3])
        values = [s.get("value") for s in steps if s.get("value") is not None]
        assert 85 in values
        assert 95 in values

    def test_disk_panel_thresholds_values(self, host_panels):
        steps = self._get_thresholds(host_panels[20])
        values = [s.get("value") for s in steps if s.get("value") is not None]
        assert 80 in values
        assert 90 in values

    def test_dns_latency_has_ms_unit(self, host_panels):
        assert self._get_unit(host_panels[30]) == "ms"

    def test_dns_latency_thresholds_values(self, host_panels):
        steps = self._get_thresholds(host_panels[30])
        values = [s.get("value") for s in steps if s.get("value") is not None]
        assert 200  in values
        assert 1000 in values

    def test_io_panel_has_bps_unit(self, host_panels):
        assert self._get_unit(host_panels[21]) == "Bps"

    def test_agents_online_has_green_threshold(self, overview_panels):
        steps = self._get_thresholds(overview_panels[1])
        colors = [s.get("color") for s in steps]
        assert "green" in colors

    def test_agents_offline_has_red_threshold(self, overview_panels):
        steps = self._get_thresholds(overview_panels[2])
        colors = [s.get("color") for s in steps]
        assert "red" in colors

    def test_dns_results_table_has_color_mappings(self, host_panels):
        overrides = host_panels[31].get("fieldConfig", {}).get("overrides", [])
        assert len(overrides) > 0
        # Deve ter mapeamento para OK/FALHA
        override_str = json.dumps(overrides)
        assert "OK" in override_str
        assert "FALHA" in override_str

    def test_agents_table_has_status_color_override(self, overview_panels):
        overrides = overview_panels[10].get("fieldConfig", {}).get("overrides", [])
        assert len(overrides) > 0


# ===========================================================================
# 7. PROVISIONING YAML
# ===========================================================================

class TestProvisioningYaml:

    @pytest.fixture(scope="class")
    def datasource(self):
        return load_yaml(DATASOURCE_PATH)

    @pytest.fixture(scope="class")
    def provider(self):
        return load_yaml(PROVIDER_PATH)

    def test_datasource_api_version(self, datasource):
        assert datasource.get("apiVersion") == 1

    def test_datasource_has_one_entry(self, datasource):
        assert len(datasource.get("datasources", [])) == 1

    def test_datasource_name_timescaledb(self, datasource):
        assert datasource["datasources"][0]["name"] == "TimescaleDB"

    def test_datasource_postgres_version_1500(self, datasource):
        assert datasource["datasources"][0]["jsonData"]["postgresVersion"] == 1500

    def test_datasource_max_connections(self, datasource):
        assert datasource["datasources"][0]["jsonData"]["maxOpenConns"] >= 5

    def test_provider_api_version(self, provider):
        assert provider.get("apiVersion") == 1

    def test_provider_has_providers(self, provider):
        assert len(provider.get("providers", [])) > 0

    def test_provider_type_is_file(self, provider):
        assert provider["providers"][0]["type"] == "file"

    def test_provider_path_is_set(self, provider):
        path = provider["providers"][0]["options"]["path"]
        assert path and len(path) > 0

    def test_provider_update_interval(self, provider):
        assert provider["providers"][0]["updateIntervalSeconds"] > 0


# ===========================================================================
# 8. CONSISTÊNCIA ENTRE DASHBOARDS
# ===========================================================================

class TestCrossConsistency:

    def test_no_duplicate_panel_ids_in_overview(self):
        panels = get_panels(load_json(OVERVIEW_PATH))
        ids = [p["id"] for p in panels]
        assert len(ids) == len(set(ids)), f"IDs duplicados: {ids}"

    def test_no_duplicate_panel_ids_in_host_detail(self):
        panels = get_panels(load_json(HOST_DETAIL_PATH))
        ids = [p["id"] for p in panels]
        assert len(ids) == len(set(ids)), f"IDs duplicados: {ids}"

    def test_overview_uid_differs_from_host_detail_uid(self):
        ov = load_json(OVERVIEW_PATH)
        hd = load_json(HOST_DETAIL_PATH)
        assert ov["uid"] != hd["uid"]

    def test_all_panels_have_titles(self):
        for path in [OVERVIEW_PATH, HOST_DETAIL_PATH]:
            for panel in get_panels(load_json(path)):
                assert panel.get("title", "").strip() != "", \
                    f"Painel {panel['id']} sem título em {path}"

    def test_all_panels_have_targets(self):
        for path in [OVERVIEW_PATH, HOST_DETAIL_PATH]:
            for panel in get_panels(load_json(path)):
                assert len(panel.get("targets", [])) > 0, \
                    f"Painel {panel['id']} '{panel['title']}' sem targets em {path}"

    def test_all_targets_have_rawsql(self):
        for path in [OVERVIEW_PATH, HOST_DETAIL_PATH]:
            for panel in get_panels(load_json(path)):
                for target in panel.get("targets", []):
                    assert "rawSql" in target, \
                        f"Target sem rawSql no painel {panel['id']} em {path}"

    def test_time_range_set_in_both_dashboards(self):
        for path in [OVERVIEW_PATH, HOST_DETAIL_PATH]:
            d = load_json(path)
            assert "time" in d, f"Campo 'time' ausente em {path}"
            assert "from" in d["time"]
            assert "to" in d["time"]

    def test_both_dashboards_have_tags(self):
        for path in [OVERVIEW_PATH, HOST_DETAIL_PATH]:
            d = load_json(path)
            assert "dns-monitor" in d.get("tags", []), \
                f"Tag 'dns-monitor' ausente em {path}"


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])