# Implementation Plan: DNS Quick Probe

**Branch**: `007-dns-quick-probe` | **Date**: 2026-04-15 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `specs/007-dns-quick-probe/spec.md`

## Summary

Add a lightweight DNS resolution probe that runs every 60 seconds (configurable) on each agent, testing a single domain with a 2-second timeout and zero retries. The probe result is attached to the next heartbeat payload and stored in the existing dns_checks table. The backend is modified to process dns_checks from heartbeat payloads (previously ignored). This gives near-real-time DNS availability monitoring with minimal overhead.

## Technical Context

**Language/Version**: Python 3.8+ (agent), Python 3.12 (backend)
**Primary Dependencies**: dnspython (agent DNS resolution), FastAPI + asyncpg (backend)
**Storage**: TimescaleDB — existing dns_checks hypertable, no schema changes
**Testing**: pytest >= 9.0 + pytest-asyncio, 100% mock, no live DB
**Target Platform**: Linux server (agent as systemd daemon), Docker container (backend)
**Project Type**: Distributed monitoring system (agent + web-service)
**Performance Goals**: Quick probe adds <500ms overhead per cycle; single DNS query ~100ms typical
**Constraints**: Single-threaded agent (schedule library), single-worker backend (APScheduler)
**Scale/Scope**: ~1440 additional dns_checks rows/day/agent; trivial for TimescaleDB

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Distributed Agent-Server | PASS | Agent probes independently, reports via existing heartbeat channel |
| II. Async-First | PASS | Backend uses existing async receive_metrics. Agent probe is sync (by design) |
| III. Test-First (NON-NEGOTIABLE) | PASS | Tests written before implementation. ~120 new lines of tests |
| IV. TimescaleDB | PASS | No schema changes. Uses existing dns_checks hypertable |
| V. Security by Design | PASS | Same Bearer token auth. No new endpoints or attack surface |
| VI. Observable and Alertable | PASS | Probe results feed existing alert evaluation pipeline |
| VII. Simplicity and Pragmatism | PASS | Module-level variable for probe↔heartbeat communication. No new abstractions |

**All gates pass. No violations.**

## Project Structure

### Documentation (this feature)

```text
specs/007-dns-quick-probe/
├── spec.md              # Feature specification
├── plan.md              # This file
├── research.md          # Phase 0: research decisions
├── data-model.md        # Phase 1: data model analysis
├── quickstart.md        # Phase 1: implementation quickstart
├── checklists/
│   └── requirements.md  # Spec quality checklist
└── tasks.md             # Phase 2 output (from /speckit.tasks)
```

### Source Code (files modified)

```text
agent/
├── dns_agent.py          # +run_quick_probe(), modify run_heartbeat(), modify setup_schedule()
├── agent.conf            # +4 quick_probe_* keys in [schedule]
└── test_agent.py         # +TestQuickProbe class (~80 lines, ~10 tests)

backend/
├── main.py               # modify receive_metrics() — remove type=="check" gate for dns_checks
└── test_backend.py        # +TestHeartbeatWithDnsChecks class (~40 lines, ~5 tests)
```

**Structure Decision**: No new files or directories. All changes are modifications to existing files, consistent with the project's pragmatic approach.

## Complexity Tracking

No constitution violations. No complexity justification needed.
