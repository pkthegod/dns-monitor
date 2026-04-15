# Feature: Remote Command Execution

## Overview
Allows the sysadmin to issue commands to agents via the backend API. Agents poll for pending commands, execute them with appropriate sudo privileges, and report results back. Designed for DNS service lifecycle management (stop, disable, enable, purge).

## User Stories

### US-001: Issue Commands
As a sysadmin, I want to send commands to specific agents so that I can remotely control DNS services.

**Acceptance Criteria:**
- POST /commands creates a pending command for a target agent
- Supported commands: stop, disable, enable, purge (DNS service control)
- Command includes: target hostname, command type, optional parameters
- Returns command ID for tracking

### US-002: Agent Command Polling
As an agent, I want to poll for pending commands so that I can execute them without maintaining a persistent connection.

**Acceptance Criteria:**
- GET /commands/{hostname} returns pending commands
- Agent polls on startup and every 12 hours
- Commands marked as "in_progress" when picked up
- Multiple pending commands returned in order

### US-003: Command Execution
As an agent, I want to execute commands with sudo privileges so that I can control system services.

**Acceptance Criteria:**
- Agent executes commands via subprocess with sudo
- Supports: systemctl stop/disable/enable/restart for DNS service (unbound/bind9)
- No TTY required (sudoers configured with !use_pty, NOPASSWD)
- Captures stdout/stderr for result reporting

### US-004: Result Reporting
As a sysadmin, I want to see command execution results so that I know whether commands succeeded.

**Acceptance Criteria:**
- POST /commands/{id}/result reports execution outcome
- Includes: status (success/failure), stdout, stderr, exit code
- Result forwarded to Telegram
- GET /commands/{hostname}/history shows command history

## Functional Requirements

- **FR-001**: POST /commands — create pending command
- **FR-002**: GET /commands/{hostname} — return pending commands for agent
- **FR-003**: POST /commands/{id}/result — report execution result
- **FR-004**: GET /commands/{hostname}/history — command history
- **FR-005**: Agent polls on startup + every 12 hours
- **FR-006**: Sudo execution without password or TTY
- **FR-007**: Command results forwarded to Telegram
- **FR-008**: Commands stored in agent_commands table

## Success Criteria

- **SC-001**: Command delivered to agent within 12 hours (polling interval)
- **SC-002**: Execution result reported back to backend
- **SC-003**: Sysadmin can track command status (pending/in_progress/completed/failed)
- **SC-004**: Sudoers configuration allows only specific service control commands

## Implementation Files

- `backend/main.py` — Command API endpoints
- `backend/db.py` — Command persistence
- `agent/dns_agent.py` — Command polling and execution logic
- `agent/install_agent.sh` — Sudoers configuration
- `backend/telegram_bot.py` — Command result notifications
