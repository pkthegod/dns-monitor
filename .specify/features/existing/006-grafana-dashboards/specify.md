# Feature: Grafana Dashboards

## Overview
Auto-provisioned Grafana dashboards providing system-wide overview and per-host detail views. Connected to TimescaleDB via PostgreSQL datasource. Dashboards and datasources are provisioned via YAML files mounted as Docker volumes.

## User Stories

### US-001: System Overview Dashboard
As a sysadmin, I want a system-wide dashboard so that I can see the health of all monitored machines at a glance.

**Acceptance Criteria:**
- Agent status table (online/offline/never_seen)
- CPU usage distribution across fleet
- RAM usage distribution across fleet
- Open alerts count and list
- DNS success rate percentage
- Top 10 DNS latencies
- Last heartbeat times per agent

### US-002: Host Detail Dashboard
As a sysadmin, I want a per-host detail dashboard so that I can drill into a specific machine's metrics.

**Acceptance Criteria:**
- Host selector dropdown (template variable)
- CPU percentage over time with warning/critical threshold lines
- RAM percentage with swap usage
- Disk usage per mountpoint
- I/O throughput (read/write bytes over time)
- Load average trends (1m/5m/15m)
- DNS latency by domain
- DNS test success/failure breakdown
- DNS service status
- Last check timestamp

### US-003: Auto-Provisioning
As ops, I want dashboards and datasources to be automatically configured so that Grafana is ready to use after `docker compose up`.

**Acceptance Criteria:**
- Datasource configured via `provisioning/datasources/timescaledb.yaml`
- Dashboards imported via `provisioning/dashboards/provider.yaml`
- No manual configuration steps after deployment
- Dashboard JSON files mounted as read-only volumes

## Functional Requirements

- **FR-001**: Overview dashboard with fleet-wide panels
- **FR-002**: Host detail dashboard with template variable for host selection
- **FR-003**: TimescaleDB datasource auto-provisioned
- **FR-004**: Dashboard JSON auto-imported on Grafana startup
- **FR-005**: Queries use continuous aggregates where available
- **FR-006**: Threshold lines on CPU/RAM panels matching alert thresholds

## Success Criteria

- **SC-001**: Grafana usable immediately after `docker compose up`
- **SC-002**: All panels load data correctly with TimescaleDB queries
- **SC-003**: Host selector shows all registered agents
- **SC-004**: 92 automated tests validating dashboard JSON structure and queries

## Implementation Files

- `grafana/dashboards/overview.json` — System-wide dashboard
- `grafana/dashboards/host-detail.json` — Per-host detail dashboard
- `grafana/provisioning/datasources/timescaledb.yaml` — Datasource config
- `grafana/provisioning/dashboards/provider.yaml` — Dashboard provider config
- `test_grafana.py` (602 lines, 92 tests) — Dashboard validation tests
