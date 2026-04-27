# Research: DNS Quick Probe

**Feature**: 007-dns-quick-probe
**Date**: 2026-04-15

## R-001: Quick Probe Scheduling Strategy

**Question**: Should the quick probe run on its own independent timer or piggyback on the heartbeat timer?

**Decision**: Independent timer with result attachment to heartbeat

**Rationale**: The heartbeat runs every 300s (5 min) but we want probes every 60s. Running the probe on its own `schedule.every(N).seconds` timer and storing the latest result in a module-level variable lets the heartbeat pick it up when it fires. This avoids:
- Changing heartbeat frequency (would affect backend load)
- Sending separate HTTP requests for probe results (doubles network traffic)

**Alternatives considered**:
- Piggyback on heartbeat only: Limited to 5-min resolution, defeats the purpose
- Separate HTTP POST per probe: 1440 extra requests/day/agent, unnecessary backend load
- Reduce heartbeat interval to 60s: Would 5x the system metrics writes — too heavy

## R-002: Backend Change — dns_checks in Heartbeat Payloads

**Question**: What's the minimal backend change to process dns_checks from heartbeat payloads?

**Decision**: Remove the `if payload.type == "check":` gate around dns_checks processing in receive_metrics

**Rationale**: Currently `backend/main.py:371-375` only processes dns_checks when `payload.type == "check"`. Changing this to process dns_checks whenever the list is non-empty (regardless of type) is a 2-line change that enables the entire feature on the backend side. Alert evaluation already works on any payload — no changes needed there.

**Alternatives considered**:
- New payload type "quick_probe": Would require Pydantic model changes, new backend logic — unnecessary complexity
- Separate endpoint for quick probe data: Violates YAGNI, adds surface area
- Store probe results locally and batch-send: Adds complexity, delays detection

## R-003: Probe Result Storage Between Probe and Heartbeat Cycles

**Question**: How does the probe (every 60s) pass its result to the heartbeat (every 300s)?

**Decision**: Module-level variable `_latest_quick_probe` set by probe job, read and cleared by heartbeat job

**Rationale**: Both jobs run in the same single-threaded process (schedule library). No race conditions possible. The heartbeat reads `_latest_quick_probe`, includes it in dns_checks if present, and resets to None. If multiple probes run between heartbeats, only the latest is sent — this is acceptable since intermediate results would be stale anyway.

**Alternatives considered**:
- Queue of all probe results: Would accumulate 5 results between heartbeats — unnecessary data, complicates payload
- Immediate send per probe: Defeats the lightweight approach
- Shared file: Overcomplicated for same-process communication

## R-004: Configuration Keys

**Question**: What configuration keys are needed and where do they go?

**Decision**: Four keys in `[schedule]` section of agent.conf

| Key | Default | Type | Description |
|-----|---------|------|-------------|
| `quick_probe_enabled` | `true` | boolean | Enable/disable quick probes |
| `quick_probe_interval` | `60` | int (seconds) | Probe frequency |
| `quick_probe_domain` | (empty = first from test_domains) | string | Domain to probe |
| `quick_probe_timeout` | `2` | float (seconds) | DNS query timeout |

**Rationale**: Placing in `[schedule]` section is consistent with existing `heartbeat_interval` and `check_times`. Default domain uses test_domains first entry to avoid requiring explicit configuration.

## R-005: Impact on Existing Tests

**Question**: What existing tests need updating?

**Decision**: 
1. `test_backend.py` — test that heartbeat payloads with dns_checks are now processed (previously ignored)
2. `test_agent.py` — new tests for quick probe function, scheduling, and heartbeat payload inclusion
3. Existing heartbeat tests must still pass when quick_probe_enabled=false

**Rationale**: TDD mandate requires tests first. The key behavioral change is backend accepting dns_checks in heartbeats — this MUST have test coverage.
