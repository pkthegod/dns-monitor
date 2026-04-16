# Feature Specification: DNS Quick Probe

**Feature Branch**: `007-dns-quick-probe`
**Created**: 2026-04-15
**Status**: Complete
**Input**: User description: "Lightweight DNS resolution test that runs every 60 seconds (configurable) alongside the heartbeat. Tests 1 domain (configurable) with 2s timeout, 0 retries (fail-fast). Results sent as dns_checks in the heartbeat payload so backend stores them in dns_checks table. Full checks every 2h remain unchanged. Goal: near-real-time DNS availability monitoring without the overhead of full checks."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Near-Real-Time DNS Monitoring (Priority: P1)

As a sysadmin, I want my DNS agents to test resolution every 60 seconds so that I detect DNS failures within 1 minute instead of waiting up to 2 hours between full checks.

**Why this priority**: This is the core value proposition. Without frequent DNS probes, a DNS outage could go undetected for 2 hours — unacceptable for production DNS servers. A 1-minute probe interval gives near-real-time visibility.

**Independent Test**: Can be fully tested by deploying an agent with quick_probe enabled, stopping the DNS service, and verifying that a failure appears in the backend within 60 seconds.

**Acceptance Scenarios**:

1. **Given** an agent with quick probe enabled (default), **When** 60 seconds elapse, **Then** the agent performs a single DNS resolution test and includes the result in the next heartbeat payload.
2. **Given** a quick probe that detects a DNS failure, **When** the heartbeat is sent, **Then** the backend stores the failure in dns_checks and triggers the appropriate alert.
3. **Given** a quick probe that succeeds, **When** the heartbeat is sent, **Then** the backend stores the latency measurement in dns_checks for trend analysis.
4. **Given** a DNS server responding slowly (>2s), **When** the quick probe times out, **Then** the result is recorded as a failure (TIMEOUT) without retrying — fail-fast behavior.

---

### User Story 2 - Configurable Probe Behavior (Priority: P2)

As a sysadmin, I want to configure the quick probe interval, target domain, and timeout per agent so that I can tune monitoring intensity for different environments.

**Why this priority**: Different environments have different needs — a production DNS server may need 30-second probes, while a secondary backup can use 5-minute probes. Configuration prevents one-size-fits-all limitations.

**Independent Test**: Can be tested by modifying agent.conf settings and verifying the agent respects the new interval, domain, and timeout values.

**Acceptance Scenarios**:

1. **Given** `quick_probe_interval = 30` in agent.conf, **When** the agent starts, **Then** the quick probe runs every 30 seconds.
2. **Given** `quick_probe_domain = cloudflare.com` in agent.conf, **When** the probe runs, **Then** it tests cloudflare.com instead of the default domain.
3. **Given** `quick_probe_timeout = 1` in agent.conf, **When** the probe runs, **Then** it uses a 1-second timeout for the DNS query.
4. **Given** `quick_probe_enabled = false` in agent.conf, **When** the agent starts, **Then** no quick probes run and heartbeats remain DNS-free (current behavior).

---

### User Story 3 - Grafana Visibility of Quick Probe Data (Priority: P3)

As a sysadmin, I want to see quick probe results in Grafana dashboards so that I can visualize DNS availability and latency at 1-minute granularity.

**Why this priority**: The data is only useful if it can be visualized. Since quick probe results are stored in the same dns_checks table as full check results, existing Grafana panels automatically benefit from the higher-resolution data — no dashboard changes required.

**Independent Test**: Can be tested by enabling quick probes and verifying that the Grafana host-detail dashboard shows DNS latency data points every ~60 seconds instead of every ~2 hours.

**Acceptance Scenarios**:

1. **Given** quick probes have been running for 1 hour, **When** a sysadmin opens the Grafana host-detail dashboard, **Then** the DNS latency graph shows ~60 data points for the last hour.
2. **Given** a DNS outage lasting 5 minutes, **When** the sysadmin reviews the dashboard, **Then** the failure is visible as a gap or red markers in the latency timeline — not hidden between 2-hour checks.

---

### Edge Cases

- What happens when the quick probe domain itself is permanently unreachable (NXDOMAIN)? The agent records a failure each probe cycle without retrying. The sysadmin should configure a domain known to resolve.
- What happens when the quick probe and a full check overlap in time? Both run independently. The heartbeat includes the quick probe result; the full check sends its own payload. No conflict — they write to the same dns_checks table with different timestamps.
- What happens when the local DNS service (unbound/bind9) is stopped? The quick probe records TIMEOUT or connection refused, exactly as expected — this IS the failure the feature is designed to detect.
- What happens when the agent has no network connectivity to the backend? The probe still runs and the result is included in the heartbeat. If the heartbeat fails to send (backend unreachable), normal retry logic applies. The probe result is lost if all retries fail — this is acceptable since the backend would already know the agent is offline.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Agent MUST perform a lightweight DNS resolution test at a configurable interval (default: 60 seconds)
- **FR-002**: Quick probe MUST test a single configurable domain (default: first domain from test_domains)
- **FR-003**: Quick probe MUST use a short timeout (default: 2 seconds) with zero retries (fail-fast)
- **FR-004**: Quick probe results MUST be included in the heartbeat payload as dns_checks entries
- **FR-005**: Backend MUST store quick probe results in the existing dns_checks table (same schema as full checks)
- **FR-006**: Backend MUST evaluate alerts on quick probe results (DNS failure, latency thresholds)
- **FR-007**: Quick probe MUST be independently enable/disable via agent.conf (default: enabled)
- **FR-008**: Full checks (every 2 hours) MUST remain unchanged and unaffected by quick probe settings
- **FR-009**: Quick probe MUST use the same local resolver configured for full checks (local_resolver setting)
- **FR-010**: Heartbeat payload type MUST remain "heartbeat" — backend MUST now process dns_checks for heartbeat payloads too

### Key Entities

- **Quick Probe Result**: Single DNS resolution test result — domain, resolver, success, latency_ms, error, attempts (always 1)
- **Heartbeat Payload**: Existing payload extended to optionally include dns_checks when quick probe is enabled
- **agent.conf [schedule] section**: Extended with quick_probe_interval, quick_probe_domain, quick_probe_timeout, quick_probe_enabled

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: DNS failures are detected within 60 seconds of occurrence (down from up to 2 hours)
- **SC-002**: Quick probe adds less than 500ms of overhead to each heartbeat cycle
- **SC-003**: Quick probe results are visible in Grafana at 1-minute granularity
- **SC-004**: Sysadmin can enable/disable quick probes per agent without restarting the backend
- **SC-005**: Existing full checks continue to function identically with quick probes enabled or disabled
- **SC-006**: Automated tests cover quick probe scheduling, payload construction, backend processing, and alert evaluation

## Assumptions

- DNS resolution of a single domain via local resolver typically completes in <100ms, making the 2-second timeout generous for fail-fast behavior
- The existing dns_checks hypertable and continuous aggregates handle the increased data volume (~1440 additional records/day per agent) without performance impact — TimescaleDB's compression and retention policies apply automatically
- The heartbeat interval (default 5 minutes) is independent of the quick probe interval — the probe runs on its own schedule and attaches results to the next heartbeat
- The backend's existing _evaluate_alerts logic works unchanged for quick probe results since they use the same dns_checks payload structure
- Grafana dashboards automatically benefit from higher-resolution data since they query the same dns_checks table
