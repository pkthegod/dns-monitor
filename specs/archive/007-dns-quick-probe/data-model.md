# Data Model: DNS Quick Probe

**Feature**: 007-dns-quick-probe
**Date**: 2026-04-15

## Entities

### Quick Probe Result (reuses existing dns_checks schema)

No new tables or columns needed. Quick probe results use the existing `dns_checks` hypertable:

| Field | Type | Source | Notes |
|-------|------|--------|-------|
| ts | TIMESTAMPTZ | Agent timestamp | Probe execution time |
| hostname | TEXT | Agent hostname | Standard identifier |
| domain | TEXT | quick_probe_domain config | Single domain tested |
| resolver | TEXT | local_resolver config | Same as full checks |
| success | BOOLEAN | Resolution result | true/false |
| latency_ms | FLOAT | Measured | NULL on failure |
| response_ips | TEXT[] | DNS answer | IPs returned |
| error | TEXT | Error type | TIMEOUT, NXDOMAIN, etc. |
| attempts | INT | Always 1 | No retries (fail-fast) |

### Heartbeat Payload (extended)

Existing payload structure — no schema changes. The `dns_checks` field (already present, currently empty `[]` for heartbeats) now contains 0-1 quick probe results:

```
{
  "type": "heartbeat",           // unchanged
  "hostname": "...",
  "timestamp": "...",
  "dns_checks": [                // was always [], now 0-1 entries
    {
      "domain": "google.com",
      "resolver": "127.0.0.1",
      "success": true,
      "latency_ms": 12.5,
      "response_ips": ["142.250.218.46"],
      "error": null,
      "attempts": 1
    }
  ],
  "system": { ... },             // unchanged
  "dns_service": { ... }         // unchanged
}
```

### Agent Configuration (extended)

New keys in `[schedule]` section of agent.conf:

| Key | Type | Default | Validation |
|-----|------|---------|------------|
| quick_probe_enabled | boolean | true | getboolean() |
| quick_probe_interval | int | 60 | >= 10 seconds |
| quick_probe_domain | string | "" (→ first from test_domains) | valid domain name |
| quick_probe_timeout | float | 2.0 | > 0 |

### Module-Level State

| Variable | Type | Purpose |
|----------|------|---------|
| `_latest_quick_probe` | dict or None | Holds latest probe result for next heartbeat |

## State Transitions

```
Quick Probe Lifecycle:
  IDLE → (interval elapsed) → PROBING → (resolve domain) → RESULT_STORED → IDLE
                                                              ↓
                                                    _latest_quick_probe = result

Heartbeat Lifecycle (modified):
  IDLE → (heartbeat interval) → COLLECT_METRICS → ATTACH_PROBE → SEND → IDLE
                                                      ↓
                                          reads _latest_quick_probe
                                          includes in dns_checks[]
                                          resets to None
```

## Database Impact

No schema changes. Volume impact per agent:

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| dns_checks rows/day | ~48 (12 checks × 4 domains) | ~1488 (48 + 1440 probes) | +31x |
| Compressed size/day (est.) | ~5 KB | ~155 KB | +31x |
| Retention | 1 year | 1 year (unchanged) | - |
| Compression | After 7 days | After 7 days (unchanged) | - |

TimescaleDB handles this volume trivially — the dns_checks_1h continuous aggregate absorbs the detail.
