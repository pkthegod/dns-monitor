# Feature: Admin Panel

## Overview
Web-based administration interface served as static HTML by FastAPI. Provides login-protected access to agent management (CRUD), command issuance (including diagnostics and update), IP geolocation, command status polling, and alert/history viewing. Uses HMAC-signed cookies for session management. Dark theme (Catppuccin) with monospace font (JetBrains Mono).

## User Stories

### US-001: Admin Login
As a sysadmin, I want to log in with username/password so that the admin panel is protected.

**Acceptance Criteria:**
- GET /admin/login serves login page
- POST /admin/login validates credentials against ADMIN_USER/ADMIN_PASSWORD env vars
- Successful login sets HMAC-signed cookie (SHA256)
- GET /admin/logout clears the session cookie
- Unauthenticated requests redirect to login (303)
- Missing ADMIN_USER/PASSWORD returns 503

### US-002: Agent CRUD
As a sysadmin, I want to view, edit, and delete agents from the admin panel so that I can manage the fleet visually.

**Acceptance Criteria:**
- Admin dashboard shows all agents with status (online/offline/never_seen)
- Can update agent metadata (display_name, location, notes, active)
- Can delete agents (cascading cleanup of 9 child tables)
- Shows agent_version from last heartbeat
- Auto-purge of agents inactive > 3 days

### US-003: Issue Commands via UI
As a sysadmin, I want to issue commands from the admin panel so that I don't need to use curl/API directly.

**Acceptance Criteria:**
- Select agent from list
- Choose command type (stop, disable, enable, restart, purge, run_script, update_agent)
- run_script supports script selection (bind9_validate, dig_test, dig_trace)
- dig_trace accepts domain and resolver parameters
- Submit and see confirmation
- Poll command status via GET /commands/{id}/status
- View command history and structured results

### US-004: View Alerts
As a sysadmin, I want to see open alerts in the admin panel so that I have a quick overview of issues.

**Acceptance Criteria:**
- List of open alerts with severity, hostname, type, timestamp
- Alert history viewable
- Filter by hostname or severity

### US-005: IP Geolocation
As a sysadmin, I want to geolocate DNS response IPs so that I can verify geographic distribution.

**Acceptance Criteria:**
- POST /tools/geolocate accepts list of IPs (max 100, deduplicated)
- Uses ip-api.com batch API (free, no key)
- Returns country, city, ISP, lat/lon per IP
- Graceful fallback on API failure

## Functional Requirements

- **FR-001**: Login/logout with HMAC-signed cookies (timing-safe comparison)
- **FR-002**: ADMIN_USER and ADMIN_PASSWORD via environment variables
- **FR-003**: Static HTML pages served by FastAPI (login.html, admin.html)
- **FR-004**: Agent list with derived status and agent_version
- **FR-005**: Agent edit (PATCH) and delete (DELETE) operations
- **FR-006**: Command issuance from UI with params support
- **FR-007**: Alert viewing with filters
- **FR-008**: POST /tools/geolocate for IP geolocation
- **FR-009**: GET /commands/{id}/status for command status polling
- **FR-010**: Catppuccin dark theme with JetBrains Mono font

## Implementation Files

- `backend/main.py` — Admin routes, auth middleware, geolocate endpoint
- `backend/static/login.html` — Login page
- `backend/static/admin.html` (63+ KB) — Admin dashboard (JavaScript embedded)
- `backend/static/logo.svg` — Project logo
- `backend/static/favicon.svg` — Browser favicon
- `backend/test_backend.py` (137 tests) — Login, cookie, admin endpoint tests
