# Security Fixes — 2026-04-22 (branch `dev`)

**Auditor:** Claude (dev-artist protocol)
**Commits:** `a979f3c` (hygiene) + `44ae33f` (security)
**Severidade global:** 🔴 CRITICAL — exploração trivial, impacto cross-tenant

---

## TL;DR

A versão `v1.1.0` claimed "Security Grade A+" no CHANGELOG, mas tinha
**isolamento multi-tenant completamente quebrado**. Qualquer cliente do
portal podia, em poucos cliques no DevTools:

1. Extrair o `AGENT_TOKEN` compartilhado via `GET /api/v1/session/token`
2. Chamar `POST /api/v1/commands` para executar `purge` (irreversível)
   em hosts de outros clientes
3. Listar `GET /api/v1/agents` vendo todos os hostnames do sistema
4. Conectar no WebSocket `/ws/live?token=…` e receber broadcast de
   métricas em tempo real de **todos os clientes**

Esta versão (`44ae33f` em `dev`) resolve as 3 vulnerabilidades raiz e
remove um fallback colateral perigoso.

---

## Tabela de vulnerabilidades

| ID | Severidade | Domínio | Arquivo:linha original | Status |
|---|---|---|---|---|
| C1 | 🔴 CRITICAL | Authorization + Data Security | `main.py:1035-1042` | ✅ Resolvido |
| C2 | 🔴 CRITICAL | Data Security | `main.py:1201-1213`, `main.py:654-662` | ✅ Resolvido |
| C3 | 🟠 HIGH | Authentication | `auth.py:33`, `main.py:1205` | ✅ Resolvido |
| Bonus | 🟠 HIGH | Authorization | `routes_client.py:399-401` | ✅ Resolvido |
| C4 | 🔴 CRITICAL | Frontend Security (XSS) | `main.py:617` (CSP) | ⏳ Próxima sprint |
| H1 | 🟠 HIGH | CSRF | `main.py:530` | ⏳ Próxima sprint |
| H2 | 🟠 HIGH | DoS / Memory | `auth.py`, `security.py`, `main.py` (rate-limit) | ⏳ Próxima sprint |

---

## C1 — Authorization break via shared `AGENT_TOKEN`

### Vulnerabilidade

`GET /api/v1/session/token` retornava o **mesmo `AGENT_TOKEN`** para
sessões `admin_session` E `client_session`:

```python
# main.py (antes)
@app.get("/api/v1/session/token")
async def session_token(request):
    admin = _verify_admin_cookie(request.cookies.get("admin_session", ""))
    client = _verify_client_cookie(request.cookies.get("client_session", ""))
    if not admin and not client:
        raise HTTPException(status_code=401)
    return JSONResponse({"token": AGENT_TOKEN})  # ⚠️ vaza p/ cliente
```

`backend/static/app.js` então cacheava esse token e o adicionava em
todas requests `Authorization: Bearer …`. Como praticamente toda rota
admin usava `Depends(require_token)` (verificação simples de Bearer),
qualquer cliente do portal tinha acesso administrativo total.

### Exploração (PoC mental)

```js
// No DevTools de uma sessão client_session válida:
fetch('/api/v1/session/token').then(r => r.json()).then(d => {
  const t = d.token;
  // Ler todos hostnames de todos clientes
  fetch('/api/v1/agents', { headers: { Authorization: 'Bearer '+t } });
  // Mandar purge irreversível em host de outro cliente
  fetch('/api/v1/commands', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer '+t },
    body: JSON.stringify({ hostname: 'OUTRO_CLIENTE_HOST', command: 'purge' })
  });
});
```

### Correção

**Backend:**

1. `/api/v1/session/token` → marca como deprecated, retorna `410 Gone`
   com log de warning para detectar frontends desatualizados ainda chamando
2. `/api/v1/session/whoami` (novo) — retorna apenas `{kind, username,
   hostnames?}`, **nunca** o AGENT_TOKEN
3. `auth.py` ganha duas dependências novas:
   - `require_admin(request)`: aceita `admin_session` cookie OU Bearer
     `AGENT_TOKEN` (fallback para curl/tooling externo administrativo)
   - `require_client(request)`: aceita **apenas** `client_session` cookie,
     retorna o dict do cliente já validado e ativo
4. Todas rotas administrativas migradas de `require_token` →
   `require_admin` (lista completa abaixo)

**Frontend:**

1. `app.js`: removidos `_cachedToken`, `token()` e o header
   `Authorization: Bearer …`. `apiFetch` envia apenas cookies via
   `credentials: 'same-origin'`
2. Novo `fetchSession()` chama `/session/whoami` e cacheia o resultado em
   `_whoami`
3. `fetchSessionToken()` mantido como wrapper de compatibilidade (retorna
   `bool`) — chama `fetchSession()` por baixo para que HTMLs antigos não
   quebrem em produção durante o deploy

### Endpoints reclassificados

**Mantidos como `require_token` (Bearer / agente-only):**

| Método | Path | Razão |
|---|---|---|
| POST | `/api/v1/metrics` | Ingestão de métricas pelo agente |
| GET | `/api/v1/commands/{hostname}` | Polling de comandos pelo agente |
| POST | `/api/v1/commands/{id}/result` | Resultado reportado pelo agente |
| GET | `/api/v1/agent/version` | Self-update polling do agente |
| GET | `/api/v1/agent/latest` | Self-update download do agente |
| POST | `/api/v1/speedtest` | Ingestão de speedtest pelo agente |
| `_legacy.*` | (sem prefixo) | Compat com agentes v1.0.0 + tooling curl |

**Trocados para `require_admin` (cookie admin OR Bearer):**

| Método | Path |
|---|---|
| PATCH | `/api/v1/agents/{hostname}` |
| DELETE | `/api/v1/agents/{hostname}` |
| GET | `/api/v1/agents` |
| GET | `/api/v1/alerts` |
| POST | `/api/v1/commands` |
| GET | `/api/v1/commands/{hostname}/history` |
| GET | `/api/v1/commands/history` |
| GET | `/api/v1/security/blocked` |
| POST | `/api/v1/tools/geolocate` |
| GET | `/api/v1/dashboard/data` |
| GET | `/api/v1/speedtest/data` |
| GET/POST/PATCH/DELETE | `/api/v1/clients` (CRUD) |
| GET | `/api/v1/reports`, `/api/v1/reports/{date}/{client_id}` |

**Caso especial — `GET /api/v1/commands/{id}/status`:**

Aceita admin (cookie ou Bearer) OU cliente com cookie. Para clientes,
verifica que o `cmd.hostname` está na lista de `hostnames` do cliente
(filtro de tenant). Retorna 403 caso contrário.

---

## C2 — WebSocket `/ws/live`: broadcast irrestrito + token na URL

### Vulnerabilidade

```python
# main.py (antes)
@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket):
    token_param = websocket.query_params.get("token", "")
    if token_param != AGENT_TOKEN:  # ⚠️ token em URL = vaza em logs
        await websocket.close(code=4001)
        return
    await ws_manager.connect(websocket)  # ⚠️ broadcast irrestrito
```

E `ws_manager.broadcast(data)` enviava `{hostname, cpu, ram, dns_ok}`
para **todas** conexões ativas, sem filtro.

Combinado com C1, qualquer cliente do portal:

1. Pegava o token via `/session/token`
2. Conectava `wss://servidor/ws/live?token=…`
3. Recebia broadcasts em tempo real de **todos os hosts de todos os
   clientes** — vazamento massivo de telemetria cross-tenant

Riscos adicionais do token em query string:
- Logado em access logs do nginx/Apache/uvicorn
- Aparece em `Referer` headers se a página tiver links externos
- Persiste em browser history e cache de proxies

### Correção

**`WSManager` reescrito** com filtro por tenant:

```python
class WSManager:
    def __init__(self):
        self._connections: list[tuple] = []  # (ws, allowed_hostnames | None)

    async def connect(self, ws, allowed_hostnames=None):
        await ws.accept()
        allowed = None if allowed_hostnames is None else set(allowed_hostnames)
        self._connections.append((ws, allowed))

    async def broadcast(self, data: dict):
        hostname = data.get("hostname")
        for ws, allowed in self._connections:
            if allowed is not None and hostname not in allowed:
                continue  # cliente não autorizado para este host
            try: await ws.send_json(data)
            except Exception: dead.append(ws)
        ...
```

**`/ws/live` reescrito** com auth via cookie:

```python
@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket):
    cookies = websocket.cookies

    admin_user = _verify_admin_cookie(cookies.get("admin_session", ""))
    if admin_user:
        await ws_manager.connect(websocket, allowed_hostnames=None)  # tudo
    else:
        client_user = _verify_client_cookie(cookies.get("client_session", ""))
        if not client_user:
            await websocket.close(code=4401, reason="Unauthorized"); return
        user = await db.get_client(client_user)
        if not user or not user.get("active"):
            await websocket.close(code=4403, reason="Inactive"); return
        await ws_manager.connect(websocket, allowed_hostnames=user["hostnames"])
    ...
```

**Frontend:** `dashboard.html` e `admin.html` removeram `?token=…` da
URL; conexão WS herda o cookie de sessão do mesmo origin
automaticamente (browsers fazem isso por padrão para WS same-origin).

```js
// antes
_ws = new WebSocket(`${proto}//${host}/ws/live?token=${t}`);
// depois
_ws = new WebSocket(`${proto}//${host}/ws/live`);
```

---

## C3 — Timing attack em comparação de Bearer token

### Vulnerabilidade

```python
# auth.py (antes)
if not auth.startswith("Bearer ") or auth[7:] != AGENT_TOKEN:
    raise HTTPException(401)
```

Comparação direta de strings em Python aborta no primeiro byte
diferente. A diferença de tempo (microssegundos por byte) é mensurável
em redes locais e permite enumerar o token byte-a-byte (ataque clássico
de timing).

Mesmo problema em `main.py:1205` (WS) e em `main.py:1135`
(`/commands/{id}/status`).

### Correção

```python
# auth.py
if not hmac.compare_digest(auth[7:].encode(), AGENT_TOKEN.encode()):
    raise HTTPException(401)
```

`hmac.compare_digest` tem tempo constante independente de quantos bytes
batem — neutraliza o ataque. Aplicado em todos pontos.

---

## Bonus — Fallback `X-Client-User` em `client_data`

```python
# routes_client.py (antes, linha ~400)
if not client_user:
    await require_token(request)        # ⚠️ aceita Bearer
    client_user = request.headers.get("X-Client-User", "")  # ⚠️ impersona
```

Qualquer portador do `AGENT_TOKEN` podia impersonar qualquer cliente
passando `X-Client-User: vitima`. Removido — `client_data` agora exige
estritamente `client_session` cookie válido.

---

## Plano de teste no servidor

### Pré-requisitos

```bash
# Backup do banco antes (segurança)
docker exec dns_monitor_db pg_dump -U dnsmonitor dns_monitor \
  | gzip > backup-$(date +%F).sql.gz

# Em outra janela: tail logs
docker compose logs -f backend
```

### Aplicar a versão dev

```bash
cd /opt/infra-vision   # ou onde o repo está
git fetch origin
git checkout dev
git pull origin dev
docker compose build --no-cache backend
docker compose up -d --force-recreate backend
```

### Smoke tests manuais

#### 1. Health & whoami

```bash
curl -s http://localhost:8000/health
# {"status":"ok","db":"connected"}

curl -s http://localhost:8000/api/v1/session/token
# {"detail":"Endpoint removido por motivos de seguranca. Use /api/v1/session/whoami."}
# (HTTP 410)

curl -s http://localhost:8000/api/v1/session/whoami
# {"detail":"Sessao invalida"} (HTTP 401, sem cookie)
```

#### 2. Admin login → whoami → dashboard

```bash
# Login (substituir credenciais)
curl -s -c /tmp/cookies.txt -X POST http://localhost:8000/admin/login \
  -d "username=ADMIN_USER&password=ADMIN_PASS"

# Whoami
curl -s -b /tmp/cookies.txt http://localhost:8000/api/v1/session/whoami
# {"kind":"admin","username":"..."}

# Listar agentes (require_admin agora aceita cookie)
curl -s -b /tmp/cookies.txt http://localhost:8000/api/v1/agents | head -200
```

#### 3. Client login → tentar acesso admin (deve falhar)

```bash
# Login cliente
curl -s -c /tmp/client.txt -X POST http://localhost:8000/client/login \
  -d "username=CLIENTE&password=SENHA_CLIENTE"

# Whoami client
curl -s -b /tmp/client.txt http://localhost:8000/api/v1/session/whoami
# {"kind":"client","username":"...","hostnames":[...]}

# 🔴 ANTES: cliente conseguia. AGORA: 401
curl -s -o /dev/null -w "%{http_code}\n" -b /tmp/client.txt \
  http://localhost:8000/api/v1/agents
# Esperado: 401

# 🔴 ANTES: cliente conseguia executar purge em qualquer host. AGORA: 401
curl -s -o /dev/null -w "%{http_code}\n" -b /tmp/client.txt \
  -X POST http://localhost:8000/api/v1/commands \
  -H "Content-Type: application/json" \
  -d '{"hostname":"qualquer-host","command":"purge"}'
# Esperado: 401

# Acesso permitido — dados próprios
curl -s -b /tmp/client.txt "http://localhost:8000/api/v1/client/data?period=24h"
# 200 com agents/dns_latency só dos hostnames do cliente
```

#### 4. WebSocket — sem token na URL, com cookie

```bash
# Sem cookie nem token: rejeitado
wscat -c "ws://localhost:8000/ws/live"
# Esperado: 4401 Unauthorized

# Com cookie admin: conecta e recebe tudo
wscat -c "ws://localhost:8000/ws/live" \
  -H "Cookie: admin_session=<valor_do_cookie>"
# Esperado: aceita, broadcasts de todos hostnames

# Com cookie client: só recebe broadcasts dos hostnames associados
wscat -c "ws://localhost:8000/ws/live" \
  -H "Cookie: client_session=<valor_do_cookie>"
# Esperado: aceita, broadcasts apenas para hostnames do cliente
```

#### 5. Pytest

```bash
cd backend
PYTHONPATH=. pytest test_backend.py -v 2>&1 | tail -40
```

⚠️ **Esperado:** alguns testes que dependem do antigo `/session/token` ou
do AGENT_TOKEN compartilhado entre client/admin podem falhar. Esses
precisam ser atualizados na próxima iteração — listar com:

```bash
PYTHONPATH=. pytest test_backend.py -v 2>&1 | grep -E "FAIL|ERROR"
```

### Smoke tests UI (browser)

1. Abrir `https://servidor/admin/login` → logar → ir para `/admin`
   → verificar que tabela de agentes carrega, métricas aparecem,
   notificação "Live update HH:MM:SS" aparece (WS funciona)
2. Abrir aba anônima → `/client/login` → logar como cliente →
   `/client` → verificar que só vê seus hostnames; abrir DevTools →
   Network → procurar request a `/session/whoami` (deve retornar
   200 com hostnames) e WS conectado em `/ws/live` (sem `?token=`)
3. **Teste de regressão crítico:** logar como cliente, abrir DevTools
   → Console → digitar:
   ```js
   fetch('/api/v1/agents', { credentials: 'same-origin' }).then(r => r.status)
   ```
   Esperado: `401`. Antes era `200`.

### Rollback se algo quebrar

```bash
git checkout main
docker compose build --no-cache backend
docker compose up -d --force-recreate backend
```

---

## Próximas iterações pendentes

| ID | Descrição | Esforço |
|---|---|---|
| C4 | Remover `'unsafe-inline'` do CSP, adicionar diretiva `'nonce-…'`, auditar todos `<script>` inline em admin.html (1300+ linhas) | 4-8h |
| H1 | CSRF: trocar `endswith` por comparação exata de host em `urlparse(origin).netloc` | 30min |
| H2 | TTL bound em `_login_attempts`, `_events`, `_blocked_ips`, `_alerted`, `_requests` (job de limpeza periódico no APScheduler) | 1h |
| H3 | Migrar rate-limit in-memory para Redis ou tabela TimescaleDB antes de scale-out (Sprint 5.1 do roadmap) | 4h |
| M2 | Auditar rotas `/admin/*` POST/PATCH/DELETE não cobertas pelo CSRF | 1h |
| M3 | Plano de deprecação formal das rotas legacy (sem `/api/v1`) | 30min |
| M4 | Validar input em `models.py` Pydantic (todos os campos de payload do agente com regex/length limits) | 2h |
| Tests | Atualizar `test_backend.py` para novo schema de auth (whoami + require_admin/client) | 2h |

Total estimado para "Security Grade A+ real": ~16h de trabalho.

---

## Referências

- OWASP Top 10 2021 — A01: Broken Access Control (C1, bonus, C2)
- OWASP Top 10 2021 — A02: Cryptographic Failures (C3 timing attack)
- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization
- CWE-208: Observable Timing Discrepancy (C3)
- CWE-598: Use of GET Request Method With Sensitive Query Strings (C2)
- Dev-Artist Protocol (`.claude/skills/dev-artist/SKILL.md`):
  CRITICAL domains — Authentication, Authorization, Data Security
