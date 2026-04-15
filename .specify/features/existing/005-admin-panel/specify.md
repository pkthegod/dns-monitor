# Feature: Admin Panel

## Overview
Web-based administration interface served as static HTML by FastAPI. Provides login-protected access to agent management (CRUD), command issuance, and alert/history viewing. Uses HMAC-signed cookies for session management.

## User Stories

### US-001: Admin Login
As a sysadmin, I want to log in with username/password so that the admin panel is protected.

**Acceptance Criteria:**
- GET /admin/login serves login page
- POST /admin/login validates credentials against ADMIN_USER/ADMIN_PASSWORD env vars
- Successful login sets HMAC-signed cookie (SHA256)
- GET /admin/logout clears the session cookie
- Unauthenticated requests redirect to login

### US-002: Agent CRUD
As a sysadmin, I want to view, edit, and delete agents from the admin panel so that I can manage the fleet visually.

**Acceptance Criteria:**
- Admin dashboard shows all agents with status
- Can update agent metadata (labels, notes)
- Can delete agents
- Real-time status: online/offline/never_seen

### US-003: Issue Commands via UI
As a sysadmin, I want to issue commands from the admin panel so that I don't need to use curl/API directly.

**Acceptance Criteria:**
- Select agent from list
- Choose command type (stop, disable, enable, purge)
- Submit and see confirmation
- View command history and results

### US-004: View Alerts
As a sysadmin, I want to see open alerts in the admin panel so that I have a quick overview of issues.

**Acceptance Criteria:**
- List of open alerts with severity, hostname, type, timestamp
- Alert history viewable
- Filter by hostname or severity

## Functional Requirements

- **FR-001**: Login/logout with HMAC-signed cookies
- **FR-002**: ADMIN_USER and ADMIN_PASSWORD via environment variables
- **FR-003**: Static HTML pages served by FastAPI (login.html, admin.html)
- **FR-004**: Agent list with derived status
- **FR-005**: Agent edit and delete operations
- **FR-006**: Command issuance from UI
- **FR-007**: Alert viewing with filters

## Implementation Files

- `backend/main.py` — Admin routes and auth middleware
- `backend/static/login.html` — Login page
- `backend/static/admin.html` — Admin dashboard
- `backend/static/logo.svg` — Project logo
- `backend/static/favicon.svg` — Browser favicon
