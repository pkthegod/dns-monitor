# Feature: Remote Command Execution

## Overview
Allows the sysadmin to issue commands to agents via the backend API. Agents poll for pending commands, execute them with appropriate sudo privileges, and report results back. Supports DNS service lifecycle management, remote diagnostic scripts, dig trace analysis, and agent self-update.

## User Stories

### US-001: Issue Commands
As a sysadmin, I want to send commands to specific agents so that I can remotely control DNS services.

**Acceptance Criteria:**
- POST /commands creates a pending command for a target agent
- Supported commands: stop, disable, enable, restart, purge, run_script, update_agent
- Command includes: target hostname, command type, optional parameters (params field)
- Returns command ID for tracking
- GET /commands/{id}/status returns real-time command status

### US-002: Agent Command Polling
As an agent, I want to poll for pending commands so that I can execute them without maintaining a persistent connection.

**Acceptance Criteria:**
- GET /commands/{hostname} returns pending commands with params
- Agent polls on startup and every 12 hours (configurable)
- Expired commands auto-marked as 'expired'
- Multiple pending commands returned in order

### US-003: Command Execution
As an agent, I want to execute commands with sudo privileges so that I can control system services.

**Acceptance Criteria:**
- Agent executes commands via subprocess with sudo
- Supports: systemctl stop/disable/enable/restart for DNS service (unbound/bind9)
- purge requires confirm_token for safety
- No TTY required (sudoers configured with !use_pty, NOPASSWD)
- Captures stdout/stderr for result reporting

### US-004: Result Reporting
As a sysadmin, I want to see command execution results so that I know whether commands succeeded.

**Acceptance Criteria:**
- POST /commands/{id}/result reports execution outcome
- Includes: status (done/failed), result text
- Result forwarded to Telegram
- GET /commands/{hostname}/history shows command history
- GET /commands/history shows global command history

### US-005: Diagnostic Scripts
As a sysadmin, I want to run diagnostic scripts remotely so that I can troubleshoot DNS issues without SSH access.

**Acceptance Criteria:**
- run_script command with params specifying script ID
- Built-in scripts: bind9_validate (service, ports, config, DNSSEC, memory, permissions) and dig_test (multi-resolver, multi-domain, DNSSEC, PTR, latency comparison)
- Script output parsed into structured JSON (CHECK_OK/FAIL/SKIP/INFO/WARN + SUMMARY)
- dig_trace: full DNS trace with hop-by-hop parsing, latency measurement, answer compilation
- Scripts run with 60s timeout, dig_trace with 90s timeout
- Unknown script names rejected with available list

### US-006: Agent Self-Update
As a sysadmin, I want to update agents remotely so that I can deploy new versions without SSH access.

**Acceptance Criteria:**
- update_agent command triggers download from backend
- GET /agent/version returns available version, SHA256 checksum, and size
- GET /agent/latest serves the dns_agent.py file with checksum header
- Agent verifies SHA256 checksum before applying
- Agent validates Python syntax (py_compile) before replacing
- Atomic file replacement with .bak backup
- Process auto-restarts via os.execv after 3-second delay
- Skips update if version already matches

## Functional Requirements

- **FR-001**: POST /commands — create pending command with optional params
- **FR-002**: GET /commands/{hostname} — return pending commands with params for agent
- **FR-003**: POST /commands/{id}/result — report execution result
- **FR-004**: GET /commands/{hostname}/history — command history per host
- **FR-005**: Agent polls on startup + every 12 hours (configurable)
- **FR-006**: Sudo execution without password or TTY
- **FR-007**: Command results forwarded to Telegram
- **FR-008**: Commands stored in agent_commands table with params column
- **FR-009**: run_script dispatches to embedded diagnostic scripts or dig_trace
- **FR-010**: _parse_diagnostic_output converts script output to structured JSON
- **FR-011**: update_agent downloads, verifies checksum, validates syntax, replaces atomically
- **FR-012**: GET /agent/version and GET /agent/latest endpoints for auto-update
- **FR-013**: GET /commands/{id}/status for individual command status polling
- **FR-014**: GET /commands/history — global command history

## Success Criteria

- **SC-001**: Command delivered to agent within 12 hours (polling interval)
- **SC-002**: Execution result reported back to backend
- **SC-003**: Sysadmin can track command status (pending/done/failed/expired)
- **SC-004**: Sudoers configuration allows only specific service control commands
- **SC-005**: Diagnostic scripts produce structured JSON with error counts
- **SC-006**: Agent self-update preserves backup and validates before replacing

## Implementation Files

- `backend/main.py` — Command API endpoints + agent version/download endpoints
- `backend/db.py` — Command persistence with params support
- `backend/schemas.sql` — agent_commands table with params column
- `agent/dns_agent.py` — Command polling, execution, diagnostics, update logic
- `agent/install_agent.sh` — Sudoers configuration
- `backend/telegram_bot.py` — Command result notifications
- `agent/test_agent.py` (105 tests) — Command, diagnostic, update tests
- `backend/test_backend.py` (137 tests) — Endpoint, validation, params tests
