# Feature: Alert System & Telegram Notifications

## Overview
Threshold-based alerting engine that evaluates incoming metrics against configurable thresholds, deduplicates alerts, persists them to the database, and sends real-time notifications via Telegram. Includes scheduled consolidated reports.

## User Stories

### US-001: Threshold-Based Alerts
As a sysadmin, I want automatic alerts when metrics exceed thresholds so that I'm notified of problems without constantly watching dashboards.

**Acceptance Criteria:**
- CPU: 80% (warning), 95% (critical)
- RAM: 85% (warning), 95% (critical)
- Disk: 80% (warning), 90% (critical)
- DNS latency: 200ms (warning), 1000ms (critical)
- DNS failure: immediate critical alert
- DNS service down: immediate critical alert
- Agent offline > 10 minutes: critical alert
- All thresholds configurable via environment variables

### US-002: Alert Deduplication
As a sysadmin, I want alert deduplication so that I don't receive repeated notifications for the same ongoing issue.

**Acceptance Criteria:**
- Same alert type for same hostname does not repeat while open
- Alert auto-resolves when condition clears
- Deduplication key: hostname + alert_type
- New alert created only if previous one is resolved

### US-003: Telegram Notifications
As a sysadmin, I want Telegram messages for alerts so that I receive them on my phone immediately.

**Acceptance Criteria:**
- Real-time alert messages with severity and details
- Command execution results forwarded to Telegram
- Telegram is optional (system works without it)
- Bot token and chat ID configurable via environment variables

### US-004: Consolidated Reports
As a sysadmin, I want periodic summary reports so that I can see overall system health at a glance.

**Acceptance Criteria:**
- Reports sent 4x/day (00:00, 06:00, 12:00, 18:00)
- Includes: online/offline agent count, DNS failures, disk warnings, open alerts
- Sent via Telegram
- Gracefully skipped if Telegram is not configured

### US-005: Offline Detection
As a sysadmin, I want automatic detection of agents that stop reporting so that I'm alerted to downed machines.

**Acceptance Criteria:**
- Backend checks for agents with no heartbeat in last 10 minutes (configurable)
- Creates critical alert for offline agents
- Check runs every 5 minutes via APScheduler
- Alert resolves when agent comes back online

### US-006: Auto-Purge Inactive Agents
As a sysadmin, I want agents inactive for > 3 days to be automatically purged so that the system stays clean.

**Acceptance Criteria:**
- Purge job runs every 1 hour
- Agents with no heartbeat for > 3 days are removed
- Agent record and recent data cleaned up
- Purge threshold configurable

## Functional Requirements

- **FR-001**: Evaluate metrics against configurable thresholds
- **FR-002**: Deduplicate alerts by hostname + type
- **FR-003**: Persist alerts to alerts_log table
- **FR-004**: Send Telegram messages for new alerts
- **FR-005**: Send consolidated reports 4x/day
- **FR-006**: Detect offline agents every 5 minutes
- **FR-007**: Auto-purge inactive agents (> 3 days)
- **FR-008**: All thresholds configurable via environment variables
- **FR-009**: Telegram integration is optional/degradable

## Success Criteria

- **SC-001**: No duplicate alerts for same ongoing condition
- **SC-002**: Alert created within 5 minutes of threshold breach
- **SC-003**: Offline detection within 10 minutes of agent silence
- **SC-004**: Reports include accurate counts from database
- **SC-005**: System operates normally without Telegram configured

## Implementation Files

- `backend/main.py` — Alert evaluation logic, scheduler jobs
- `backend/telegram_bot.py` (~300 lines) — Telegram integration
- `backend/db.py` — Alert persistence, deduplication queries
- `backend/test_backend.py` — Alert, report, offline, and purge tests
