# Feature: Agent Metrics Collection

## Overview
Lightweight Python daemon deployed on monitored machines that collects system metrics (CPU, RAM, disk, I/O, load) and performs DNS resolution tests, reporting results to the central backend via HTTP.

## User Stories

### US-001: Heartbeat Signal
As a sysadmin, I want each agent to send periodic heartbeat signals so that I can detect when a machine goes offline.

**Acceptance Criteria:**
- Agent sends heartbeat every 5 minutes (configurable)
- Heartbeat includes: hostname, timestamp, agent version, hardware fingerprint
- Heartbeat is lightweight (minimal payload)
- Agent tolerates backend unavailability (retries silently)

### US-002: Full System Check
As a sysadmin, I want comprehensive system metrics collected 4 times per day so that I can monitor trends without excessive overhead.

**Acceptance Criteria:**
- Full check runs at 00:00, 06:00, 12:00, 18:00 (configurable)
- Collects: CPU (%, cores, frequency, load averages), RAM (%, used, total, swap), disk (per-mount usage with alert levels), I/O (read/write bytes, ops, time)
- Includes DNS resolution tests for multiple domains
- Single POST request to backend with all metrics

### US-003: DNS Resolution Testing
As a sysadmin, I want each agent to test DNS resolution against configurable domains so that I can detect DNS failures or high latency.

**Acceptance Criteria:**
- Tests multiple domains (default: google.com, cloudflare.com, gov.br, aliexpress.com)
- Uses configurable resolver (default: 127.0.0.1 for local DNS server)
- Retry logic: 3 attempts per domain
- Captures: latency (ms), response IPs, status (ok/error)
- Error codes: TIMEOUT, NXDOMAIN, NO_NAMESERVERS

### US-004: Hardware Fingerprint
As a sysadmin, I want each agent to generate a unique hardware fingerprint so that I can detect unauthorized hardware changes or cloned machines.

**Acceptance Criteria:**
- SHA256 hash of: hostname + MAC address + /etc/machine-id
- Sent with every payload (heartbeat and full check)
- Backend stores first_seen and last_seen timestamps
- Backend warns if fingerprint changes for a known hostname

### US-005: Agent Configuration
As a sysadmin, I want to configure the agent via config files so that I can customize behavior per machine.

**Acceptance Criteria:**
- Config file: `/etc/dns-agent/agent.conf` (ConfigParser with interpolation)
- Secrets file: `/etc/dns-agent/env` (chmod 640)
- Configurable: backend URL, agent token, hostname, check schedule, DNS domains, resolver, retry count
- Agent validates config on startup

## Functional Requirements

- **FR-001**: Heartbeat sending at configurable interval (default 5min)
- **FR-002**: Full metrics collection at scheduled times
- **FR-003**: CPU metrics: percentage, core count, frequency, load averages (1m/5m/15m)
- **FR-004**: RAM metrics: percentage, used MB, total MB, swap percentage and used
- **FR-005**: Disk metrics: per-mountpoint usage with ok/warning/critical classification
- **FR-006**: I/O metrics: read/write bytes, operation counts, time spent
- **FR-007**: DNS resolution with retry logic and latency measurement
- **FR-008**: Hardware fingerprint generation and transmission
- **FR-009**: Configuration via ConfigParser files
- **FR-010**: Graceful retry on backend unavailability
- **FR-011**: Systemd service integration (auto-start, restart on failure)

## Success Criteria

- **SC-001**: Agent runs continuously as systemd service without memory leaks
- **SC-002**: Heartbeats arrive at backend within expected interval (< 6 minutes)
- **SC-003**: DNS tests complete within timeout (default 5 seconds per domain)
- **SC-004**: Agent handles network errors without crashing
- **SC-005**: Disk metrics correctly classify alert levels based on thresholds
- **SC-006**: 105 automated tests covering all agent functionality

## Edge Cases

- **EC-001**: Backend is unreachable — agent retries silently, does not crash
- **EC-002**: DNS resolver is down — reports TIMEOUT error, does not hang
- **EC-003**: Disk mount is read-only — still reports usage metrics
- **EC-004**: Machine has no /etc/machine-id — fallback fingerprint strategy
- **EC-005**: Config file missing — agent exits with clear error message
- **EC-006**: Agent runs on minimal system (no swap) — handles missing swap gracefully

## Implementation Files

- `agent/dns_agent.py` (1269 lines) — Main agent code
- `agent/agent.conf` — Configuration template
- `agent/.env.sample` — Secrets template
- `agent/install_agent.sh` — Automated installer
- `agent/dns_agent.service` — Systemd unit file
- `agent/requirements.txt` — Python dependencies
- `agent/test_agent.py` (105 tests) — Test suite
