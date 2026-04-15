# Brownfield Analysis Report — dns-monitor

**Date:** 2026-04-09
**Depth:** Moderate
**Analyzer:** Claude Code (SDD Brownfield Workflow)

---

## Architecture Overview

Distributed DNS monitoring system with 4 main components:

1. **Agent** (`agent/`) — Python daemon deployed on N monitored machines
2. **Backend** (`backend/`) — FastAPI central server receiving metrics
3. **Database** — TimescaleDB (PostgreSQL 15) for time-series storage
4. **Grafana** (`grafana/`) — Pre-provisioned dashboards for visualization
5. **Telegram Bot** (`backend/telegram_bot.py`) — Alert notifications

## Technology Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Language | Python | 3.8+ (agent), 3.12 (backend container) |
| API Framework | FastAPI | ≥0.111 |
| ASGI Server | Uvicorn | ≥0.29 |
| Database | TimescaleDB on PostgreSQL | 15 |
| DB Driver | asyncpg | ≥0.29 |
| Scheduler | APScheduler | ≥3.10 |
| HTTP Client | httpx (backend), requests (agent) | |
| System Metrics | psutil | ≥5.9 |
| DNS Library | dnspython | ≥2.4 |
| Dashboards | Grafana | latest |
| Containers | Docker Compose | ≥1.29 |
| Alerts | Telegram Bot API | |
| Testing | pytest + pytest-asyncio | ≥9.0 |

## Design Patterns Identified

- **Agent-Server Architecture**: Distributed agents report to central backend
- **Bearer Token Auth**: Shared token for agent-to-backend authentication
- **Async I/O**: FastAPI + asyncpg throughout backend (non-blocking)
- **Time-Series Hypertables**: TimescaleDB for efficient metric storage
- **Threshold-Based Alerting**: Configurable CPU/RAM/disk/DNS thresholds
- **Alert Deduplication**: Prevents repeat alerts for same condition
- **Auto-Registration**: New agents self-register on first contact
- **Hardware Fingerprint**: SHA256 identity verification per agent
- **Remote Command Execution**: Backend issues commands, agents poll and execute
- **Auto-Provisioned Dashboards**: Grafana datasources + dashboards via YAML

## Coding Conventions

- Python with type hints (Pydantic models for validation)
- Async/await pattern for all I/O operations
- Parameterized SQL queries (no ORM)
- ConfigParser with interpolation for agent config
- Environment variables for secrets and thresholds
- Systemd service units for agent deployment
- Docker Compose for backend stack

## Testing Patterns

- **242 total tests** (80 agent + 70 backend + 92 grafana)
- TDD workflow (Red → Green → Refactor)
- All tests use mocks (no real database)
- pytest with unittest.mock (MagicMock, AsyncMock, patch)
- Separate test files per component

## Database Schema

- 8 hypertables: heartbeats, cpu, ram, disk, io, dns_checks, dns_service_status, alerts_log
- 2 regular tables: agents, agent_commands
- 1 view: v_agent_current_status
- Continuous aggregates: hourly rollups for cpu, ram
- Compression: auto after 7 days
- Retention: 30 days (heartbeats), 1 year (metrics)

## Deployment Model

- **Backend**: Docker Compose (3 services: postgres, backend, grafana)
- **Agent**: Systemd service installed via bash script
- **Network**: Custom bridge 172.20.0.0/24

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | /metrics | Receive agent payloads |
| GET | /agents | List agents with status |
| GET | /alerts | View open alerts |
| PATCH | /agents/{hostname} | Update agent metadata |
| DELETE | /agents/{hostname} | Remove agent |
| POST | /commands | Issue remote command |
| GET | /commands/{hostname} | Agent polls commands |
| POST | /commands/{id}/result | Agent reports result |
| GET | /commands/{hostname}/history | Command history |
| GET/POST | /admin/login | Admin panel auth |
| GET | /admin/logout | Logout |
| GET | /admin | Admin dashboard |
| GET | /health | Health check |

## Integration Points

- Agent → Backend: HTTP POST with Bearer Token
- Backend → TimescaleDB: asyncpg connection pool
- Backend → Telegram: Bot API for alerts/reports
- Grafana → TimescaleDB: PostgreSQL datasource (read-only)
- Admin Panel: Static HTML served by FastAPI

## Technical Debt / Observations

- Single-process backend (APScheduler constraint)
- No API versioning
- Shared agent token (not per-agent tokens)
- Admin auth uses HMAC-signed cookies (not JWT)
- No CORS configuration (internal network assumed)
- No OpenAPI schema customization
- Agent config uses ConfigParser (not YAML/TOML)
