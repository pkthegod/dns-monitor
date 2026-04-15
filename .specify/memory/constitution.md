# DNS Monitor Constitution

## Core Principles

### I. Distributed Agent-Server Architecture
The system follows a hub-and-spoke model: lightweight agents deployed on monitored machines collect metrics and report to a central FastAPI backend. Agents are autonomous — they operate independently and tolerate backend unavailability gracefully. The backend is the single source of truth for agent state, alerts, and commands.

### II. Async-First, Non-Blocking I/O
All backend code uses async/await (FastAPI + asyncpg + httpx). No blocking I/O in the request path. The agent uses synchronous code (psutil, dnspython, requests) since it runs as a single-threaded daemon per machine.

### III. Test-First Development (NON-NEGOTIABLE)
TDD is mandatory: Red → Green → Refactor. All 284+ tests must pass before any deploy. Tests use mocks exclusively — no live database connections in test suites. Test structure mirrors production code: `test_agent.py`, `test_backend.py`, `test_grafana.py`.

### IV. Time-Series Data with TimescaleDB
All metric data uses TimescaleDB hypertables with automatic compression (7 days) and retention policies (30 days for heartbeats, 1 year for metrics). Continuous aggregates provide hourly rollups. Raw SQL with parameterized queries via asyncpg — no ORM.

### V. Security by Design
- Bearer token authentication for agent-to-backend communication
- Hardware fingerprint (SHA256) for agent identity verification
- HMAC-signed cookies for admin panel sessions
- Secrets via environment variables only (never in code or git)
- Parameterized SQL queries (no string interpolation)
- Non-root container user for backend

### VI. Observable and Alertable
Threshold-based alerting with deduplication for CPU, RAM, disk, DNS latency, and DNS failures. Telegram integration for real-time notifications and consolidated reports (4x/day). Grafana dashboards auto-provisioned for system-wide overview and per-host detail.

### VII. Simplicity and Pragmatism
YAGNI — no speculative abstractions. Single-process backend (APScheduler constraint). ConfigParser for agent config. Static HTML for admin panel. Docker Compose for deployment. Prefer direct, readable code over clever patterns.

## Technology Standards

| Component | Technology | Constraint |
|-----------|-----------|------------|
| Backend API | FastAPI >= 0.111 + Uvicorn | Single worker (APScheduler) |
| Database | TimescaleDB on PostgreSQL 15 | asyncpg driver, no ORM |
| Agent | Python 3.8+ with psutil, dnspython | Systemd service |
| Scheduler | APScheduler >= 3.10 | Must run in-process |
| Dashboards | Grafana (latest) | Auto-provisioned via YAML |
| Alerts | Telegram Bot API | Optional, degradable |
| Containers | Docker Compose >= 1.29 | Custom bridge network |
| Testing | pytest >= 9.0 + pytest-asyncio | 100% mock, no live DB |

## Coding Conventions

- **Python style**: PEP 8 with type hints on public interfaces
- **Validation**: Pydantic models for API payloads
- **SQL**: Raw parameterized queries via asyncpg ($1, $2 placeholders)
- **Config**: Environment variables for secrets/thresholds, ConfigParser for agent
- **Error handling**: Log and continue in agents, HTTP error responses in backend
- **Naming**: snake_case for functions/variables, PascalCase for Pydantic models
- **Language**: Code in English, user-facing messages (admin panel, Telegram) in Portuguese (pt-BR)

## Development Workflow

1. **Branch**: Work on `dev` branch, merge to `main` for releases
2. **Test**: Write test first, verify it fails, implement, verify it passes
3. **Verify**: All 284+ tests green before any deploy
4. **Build**: `docker compose build --no-cache backend`
5. **Deploy**: `docker compose up -d`
6. **Health**: `curl http://localhost:8000/health` returns `{"status":"ok"}`

## Deployment Constraints

- Backend must run with `--workers 1` (APScheduler cannot be duplicated)
- Docker network uses fixed IPs: postgres=172.20.0.10, backend=172.20.0.11, grafana=172.20.0.12
- Agent installation via `install_agent.sh` (creates user, venv, systemd unit, sudoers)
- Grafana datasources and dashboards provisioned via volume mounts

## Governance

- This constitution reflects the established patterns of the dns-monitor project
- All new features must comply with these principles
- Amendments require updating this document with rationale
- Constitution supersedes ad-hoc decisions

**Version**: 1.1.0 | **Ratified**: 2026-04-09 | **Last Amended**: 2026-04-15
