# Tasks: DNS Quick Probe

**Input**: Design documents from `specs/007-dns-quick-probe/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, quickstart.md

**Tests**: Required (Constitution Principle III: TDD is NON-NEGOTIABLE)

**Organization**: Tasks grouped by user story for independent implementation and testing.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

---

## Phase 1: Setup (Configuration)

**Purpose**: Add quick probe config keys to agent.conf template

- [ ] T001 Add quick_probe_enabled, quick_probe_interval, quick_probe_domain, quick_probe_timeout keys to agent/agent.conf [schedule] section with defaults and comments

---

## Phase 2: Foundational (Backend — Accept dns_checks in Heartbeats)

**Purpose**: Backend MUST process dns_checks from heartbeat payloads before agent changes are useful. This is the blocking prerequisite.

**CRITICAL**: No agent-side probe work is useful until the backend accepts dns_checks in heartbeats.

### Tests

> **Write these tests FIRST, ensure they FAIL before implementation**

- [ ] T002 [P] Test that heartbeat payload with dns_checks is stored in dns_checks table — add TestHeartbeatWithDnsChecks class in backend/test_backend.py
- [ ] T003 [P] Test that heartbeat payload with dns_checks triggers alert evaluation (DNS failure, latency thresholds) in backend/test_backend.py
- [ ] T004 [P] Test that heartbeat payload with empty dns_checks still works (backward compatibility) in backend/test_backend.py
- [ ] T005 [P] Test that heartbeat payload with dns_checks stores dns_service_status in backend/test_backend.py

### Implementation

- [ ] T006 Remove `if payload.type == "check":` gate around dns_checks and dns_service_status processing in backend/main.py receive_metrics() — process dns_checks whenever list is non-empty regardless of payload type

**Checkpoint**: Backend now processes dns_checks from any payload type. All existing tests still pass. New tests pass.

---

## Phase 3: User Story 1 — Near-Real-Time DNS Monitoring (Priority: P1) MVP

**Goal**: Agent performs a lightweight DNS probe every 60 seconds and includes result in heartbeat payload. Backend stores and alerts on the result.

**Independent Test**: Deploy agent with quick_probe enabled, stop DNS service, verify failure appears in backend within 60 seconds.

### Tests for User Story 1

> **Write these tests FIRST, ensure they FAIL before implementation**

- [ ] T007 [P] [US1] Test run_quick_probe() resolves single domain with short timeout and stores result in _latest_quick_probe in agent/test_agent.py
- [ ] T008 [P] [US1] Test run_quick_probe() records TIMEOUT on slow DNS (>2s) without retrying in agent/test_agent.py
- [ ] T009 [P] [US1] Test run_quick_probe() records NXDOMAIN failure in agent/test_agent.py
- [ ] T010 [P] [US1] Test run_heartbeat() includes _latest_quick_probe in dns_checks when probe result exists in agent/test_agent.py
- [ ] T011 [P] [US1] Test run_heartbeat() clears _latest_quick_probe after reading it in agent/test_agent.py
- [ ] T012 [P] [US1] Test run_heartbeat() sends empty dns_checks when no probe result exists (quick_probe disabled) in agent/test_agent.py

### Implementation for User Story 1

- [ ] T013 [US1] Add module-level variable `_latest_quick_probe = None` in agent/dns_agent.py
- [ ] T014 [US1] Implement run_quick_probe(cfg, logger) function in agent/dns_agent.py — resolve single domain using _resolve_domain() with quick timeout and 1 retry, store result in _latest_quick_probe
- [ ] T015 [US1] Modify run_heartbeat() in agent/dns_agent.py — read _latest_quick_probe, include in dns_checks list if present, reset to None after reading
- [ ] T016 [US1] Modify setup_schedule() in agent/dns_agent.py — add `schedule.every(quick_probe_interval).seconds.do(run_quick_probe)` when quick_probe_enabled is true

**Checkpoint**: Agent probes DNS every 60s, result goes in heartbeat, backend stores and alerts. Full checks unchanged. All 284+ existing tests still pass.

---

## Phase 4: User Story 2 — Configurable Probe Behavior (Priority: P2)

**Goal**: Sysadmin can configure probe interval, domain, timeout, and enable/disable per agent via agent.conf.

**Independent Test**: Change quick_probe_interval to 30 in agent.conf, restart agent, verify probe runs every 30 seconds.

### Tests for User Story 2

> **Write these tests FIRST, ensure they FAIL before implementation**

- [ ] T017 [P] [US2] Test setup_schedule() reads quick_probe_interval from config and schedules accordingly in agent/test_agent.py
- [ ] T018 [P] [US2] Test setup_schedule() does NOT schedule quick probe when quick_probe_enabled=false in agent/test_agent.py
- [ ] T019 [P] [US2] Test run_quick_probe() uses quick_probe_domain from config (custom domain) in agent/test_agent.py
- [ ] T020 [P] [US2] Test run_quick_probe() defaults to first domain from test_domains when quick_probe_domain is empty in agent/test_agent.py
- [ ] T021 [P] [US2] Test run_quick_probe() uses quick_probe_timeout from config in agent/test_agent.py

### Implementation for User Story 2

- [ ] T022 [US2] Read quick_probe_enabled, quick_probe_interval, quick_probe_domain, quick_probe_timeout from cfg in run_quick_probe() and setup_schedule() in agent/dns_agent.py
- [ ] T023 [US2] Add fallback logic for quick_probe_domain — use first domain from dns.test_domains when empty in agent/dns_agent.py

**Checkpoint**: All 4 config keys respected. Disabled probe = no probe job scheduled. Custom domain/timeout used. Existing tests pass.

---

## Phase 5: User Story 3 — Grafana Visibility (Priority: P3)

**Goal**: Quick probe results visible in Grafana at 1-minute granularity. Since data goes to the same dns_checks table, existing dashboards automatically show the data.

**Independent Test**: Enable quick probes for 1 hour, open Grafana host-detail dashboard, verify DNS latency graph shows ~60 data points for the last hour.

### Verification (no code changes needed)

- [ ] T024 [US3] Verify existing Grafana host-detail dashboard DNS latency panel displays quick probe data at 1-minute granularity — no dashboard JSON changes needed since it queries dns_checks table directly

**Checkpoint**: Grafana shows high-resolution DNS data without any dashboard modifications.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Documentation, cleanup, final validation

- [ ] T025 [P] Update agent/agent.conf with quick_probe section comments explaining each setting
- [ ] T026 [P] Update specs/007-dns-quick-probe/spec.md status from Draft to Complete
- [ ] T027 Run all tests (agent + backend + grafana) — verify 284+ existing tests still pass plus new tests
- [ ] T028 Run quickstart.md validation — verify probe is functional end-to-end

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: No dependency on Phase 1 — can start in parallel
- **US1 (Phase 3)**: Depends on Phase 1 (config keys) + Phase 2 (backend accepts heartbeat dns_checks)
- **US2 (Phase 4)**: Depends on Phase 3 (run_quick_probe exists to read config from)
- **US3 (Phase 5)**: Depends on Phase 3 (probe data must exist in dns_checks)
- **Polish (Phase 6)**: Depends on all phases complete

### User Story Dependencies

- **User Story 1 (P1)**: Depends on Foundational (Phase 2) — core functionality
- **User Story 2 (P2)**: Depends on US1 — configuration of existing probe function
- **User Story 3 (P3)**: Depends on US1 — verification only, no code changes

### Within Each User Story

- Tests MUST be written and FAIL before implementation (TDD)
- Implementation follows test guidance
- Story complete = all story tests pass

### Parallel Opportunities

- Phase 1 (config) and Phase 2 (backend) can run in parallel
- All [P] tests within a phase can run in parallel
- T007-T012 (US1 tests) can all run in parallel
- T017-T021 (US2 tests) can all run in parallel
- T002-T005 (backend tests) can all run in parallel

---

## Parallel Example: User Story 1

```bash
# Launch all US1 tests together (they test different behaviors):
Task T007: "Test run_quick_probe() resolves single domain"
Task T008: "Test run_quick_probe() records TIMEOUT"
Task T009: "Test run_quick_probe() records NXDOMAIN"
Task T010: "Test run_heartbeat() includes probe in dns_checks"
Task T011: "Test run_heartbeat() clears probe after reading"
Task T012: "Test run_heartbeat() empty dns_checks when no probe"

# Then implement sequentially:
Task T013: Module-level variable
Task T014: run_quick_probe() function
Task T015: Modify run_heartbeat()
Task T016: Modify setup_schedule()
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Config keys in agent.conf
2. Complete Phase 2: Backend accepts dns_checks in heartbeats (TDD)
3. Complete Phase 3: Agent quick probe (TDD)
4. **STOP and VALIDATE**: Test probe detects DNS failure within 60 seconds
5. Deploy if ready — US2 and US3 can come later

### Incremental Delivery

1. Phase 1 + Phase 2 → Backend ready
2. Add US1 (Phase 3) → MVP: 60s DNS monitoring
3. Add US2 (Phase 4) → Configurable per agent
4. Add US3 (Phase 5) → Verify Grafana visibility
5. Polish (Phase 6) → Docs and final validation

---

## Notes

- [P] tasks = different files or independent test functions, no dependencies
- [Story] label maps task to specific user story for traceability
- TDD is mandatory per Constitution Principle III
- All 284+ existing tests MUST continue to pass
- Estimated new tests: ~15 (agent: ~10, backend: ~5)
- Estimated new/modified code: ~50 lines agent, ~2 lines backend
- Commit after each phase checkpoint
