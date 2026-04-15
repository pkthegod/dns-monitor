# Feature: Backend API & Data Persistence

## Overview
Central FastAPI server that receives agent payloads, validates and persists metrics in TimescaleDB, manages agent registry, and serves as the hub for all monitoring data.

## User Stories

### US-001: Receive Agent Metrics
As the monitoring system, I want to receive and persist agent payloads so that metrics are stored for analysis and alerting.

**Acceptance Criteria:**
- POST /metrics endpoint accepts JSON payloads with Bearer token auth
- Validates payload structure with Pydantic models
- Persists to appropriate hypertables (heartbeats, cpu, ram, disk, io, dns_checks, dns_service_status)
- Returns 200 on success, 401 on auth failure, 422 on validation error

### US-002: Auto-Register Agents
As a sysadmin, I want new agents to be automatically registered so that I don't need to manually configure each one.

**Acceptance Criteria:**
- First payload from unknown hostname creates agent record
- Stores: hostname, first_seen, last_seen, agent_version, fingerprint
- Agent appears in agent list immediately
- No manual registration step required

### US-003: Agent Management
As a sysadmin, I want to list, update, and remove agents so that I can manage the monitored fleet.

**Acceptance Criteria:**
- GET /agents returns all agents with current status (online/offline/never_seen)
- PATCH /agents/{hostname} updates agent metadata
- DELETE /agents/{hostname} removes agent and optionally its data
- Status derived from last heartbeat timestamp vs threshold

### US-004: Database Schema Management
As the system, I want the database schema to be automatically created and maintained so that deployment is straightforward.

**Acceptance Criteria:**
- Schema created on first backend startup
- 8 hypertables with appropriate chunk intervals
- Compression policies (auto after 7 days)
- Retention policies (30 days heartbeats, 1 year metrics)
- Continuous aggregates for hourly rollups
- Indexes for common query patterns

### US-005: Health Check
As ops tooling, I want a health endpoint so that I can monitor backend availability.

**Acceptance Criteria:**
- GET /health returns {"status": "ok"} with 200
- Used by Docker health check and external monitoring

## Functional Requirements

- **FR-001**: POST /metrics — receive and persist agent payloads
- **FR-002**: GET /agents — list agents with derived status
- **FR-003**: PATCH /agents/{hostname} — update agent metadata
- **FR-004**: DELETE /agents/{hostname} — remove agent
- **FR-005**: GET /health — health check endpoint
- **FR-006**: Bearer token authentication on all agent endpoints
- **FR-007**: Pydantic validation for all request payloads
- **FR-008**: asyncpg connection pool for database operations
- **FR-009**: Auto-registration of unknown agents
- **FR-010**: Fingerprint storage with first/last seen tracking
- **FR-011**: Schema auto-creation on startup

## Success Criteria

- **SC-001**: Backend handles concurrent agent submissions without errors
- **SC-002**: Database schema creation is idempotent (safe to restart)
- **SC-003**: API response time < 200ms for metric ingestion
- **SC-004**: 137 automated tests covering all backend functionality

## Implementation Files

- `backend/main.py` (716 lines) — FastAPI application + scheduler
- `backend/db.py` (593 lines) — Database layer (asyncpg)
- `backend/schemas.sql` (16.3KB) — Database DDL
- `backend/Dockerfile` — Container definition
- `backend/docker-compose.yaml` — Full stack orchestration
- `backend/requirements.txt` — Python dependencies
- `backend/test_backend.py` (137 tests) — Test suite
