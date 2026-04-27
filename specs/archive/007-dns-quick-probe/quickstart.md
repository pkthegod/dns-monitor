# Quickstart: DNS Quick Probe

**Feature**: 007-dns-quick-probe

## What Changes

### Agent (dns_agent.py)
1. New function `run_quick_probe(cfg, logger)` — resolves 1 domain, stores in `_latest_quick_probe`
2. Modified `run_heartbeat()` — reads `_latest_quick_probe`, includes in dns_checks if present
3. Modified `setup_schedule()` — adds quick probe job if enabled
4. New config keys in `[schedule]`: `quick_probe_enabled`, `quick_probe_interval`, `quick_probe_domain`, `quick_probe_timeout`

### Backend (main.py)
1. Modified `receive_metrics()` — process dns_checks and dns_service for ALL payload types (not just "check")

### Config (agent.conf)
1. Four new keys in `[schedule]` section with sensible defaults

## How to Enable

Quick probe is **enabled by default**. Just update the agent to the new version.

To customize, edit `/etc/dns-agent/agent.conf`:

```ini
[schedule]
quick_probe_enabled = true
quick_probe_interval = 60
quick_probe_domain =
quick_probe_timeout = 2
```

To disable: `quick_probe_enabled = false`

## How to Verify

1. Check agent logs for probe activity:
   ```
   grep "quick_probe" /var/log/dns-agent/agent.log
   ```

2. Query dns_checks table for high-frequency data:
   ```sql
   SELECT ts, domain, success, latency_ms
   FROM dns_checks
   WHERE hostname = 'your-agent'
   ORDER BY ts DESC
   LIMIT 10;
   ```

3. Grafana host-detail dashboard should show 1-minute resolution DNS latency data.

## Files Modified

| File | Change Type | Size of Change |
|------|------------|----------------|
| agent/dns_agent.py | Add function + modify 2 functions | ~40 lines |
| agent/agent.conf | Add 4 config keys | ~8 lines |
| agent/test_agent.py | New test class | ~80 lines |
| backend/main.py | Remove 1 condition gate | ~2 lines |
| backend/test_backend.py | New test class | ~40 lines |
