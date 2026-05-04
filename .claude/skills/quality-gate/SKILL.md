---
name: quality-gate
version: 1.1.0
description: Babysit completo do projeto com tecnica de RATCHET — roda testes, sincroniza memorias + roadmap + GitHub, audita debitos, propoe melhorias/refactor/hardening, executa OSINT preventivo. Baseline nunca pode piorar. Bloqueia em violacao critica. Invoque com `/quality-gate` ou pedido explicito de auditoria.
author: PK
license: MIT
enforcement: strict
blocking: true
scope:
  - backend
  - agent
  - devops
  - security
  - documentation
  - osint
tags:
  - quality-gate
  - audit
  - babysit
  - roadmap
  - testing
  - ratchet
  - osint
---

# Princípios

> 1. **RATCHET.** O baseline so pode subir, nunca descer. Cada
>    rodada compara metricas contra `.claude/quality-baseline.json` —
>    se algo piorar SEM justificativa explicita, e violacao critica.
>
> 2. **NAO aceitar:** falha de teste, regressao silenciosa, piora de
>    metrica, quebra de invariante. Se rolar, BLOQUEIA o relatorio
>    com flag `[CRITICAL]` e pede acao do Paulo antes de seguir.
>
> 3. **Melhoria continua.** Toda rodada deve produzir pelo menos 1
>    sugestao acionavel, mesmo que o estado atual esteja bom.
>
> 4. **Read-mostly.** Skill nao comita, nao pusha, nao apaga.
>    Apenas analisa e propoe. Mudanca sai em commit separado pelo
>    Paulo, com diff revisado.


# Quality Gate — protocolo de babysit do projeto

> **Papel:** rotina completa de validacao e curadoria. NAO comita nada
> automaticamente — produz um relatorio consolidado pra Paulo decidir
> proximas acoes.
>
> **Inspiracao:** dev-artist (qualidade como gate), mas focado em
> *manutencao* em vez de *desenvolvimento*.

---

## Quando invocar

Paulo digita `/quality-gate` ou pede explicitamente:
- "roda quality gate"
- "uma rodada de qualidade"
- "audita o estado do projeto"
- "sincroniza tudo"

Tambem invocar **proativamente** apos:
- 5+ commits seguidos sem rodar testes
- Mudanca grande de schema (ALTER TABLE) sem migration test
- Suspeita de drift entre memoria e codigo

---

## Pipeline de execucao (em ordem)

Cada bloco abaixo deve produzir saida visivel pro user. Se algum
bloco *falhar*, **continua** e marca o item como `[FALHA]` no
relatorio final — nao aborta a rodada inteira.

### 0. Ratchet — carregar baseline

Antes de tudo, le `.claude/quality-baseline.json` (gitignored, fica
local no repo). Estrutura:

```json
{
  "updated_at": "2026-05-04T15:00:00Z",
  "tests": {
    "backend_passed": 281,
    "agent_passed": 157,
    "grafana_passed": 92,
    "total_passed": 530,
    "total_skipped": 5,
    "total_xfailed": 1,
    "total_xpassed": 0,
    "total_failed": 0,
    "duration_s_p95": 16.0
  },
  "loc": {
    "backend_total": 12500,
    "agent_total": 2600,
    "static_total": 5800
  },
  "files_over_1000_lines": [
    "backend/db.py",
    "backend/test_backend.py",
    "agent/dns_agent.py",
    "agent/test_agent.py"
  ],
  "todos_count": 8,
  "ratchet_locks": {
    "csp_unsafe_inline": "DEBT — refactor B agendado pra 2026-05-07",
    "nats_plain_text": "DEBT — Onda 1 P5 pendente"
  }
}
```

Se o arquivo NAO existir, este e o primeiro run — cria com snapshot
atual e marca `[BOOTSTRAP]` no relatorio.

Apos rodar testes (bloco 1), compara metricas. Regras:

| Metrica | Permitido baixar? | Acao se piorar |
|---|---|---|
| `total_passed` | NAO | `[CRITICAL]` — bloqueia |
| `total_failed` | NAO crescer | `[CRITICAL]` — bloqueia |
| `total_xfailed` apos xpassed | OK (xpassed = melhorou!) | `[INFO]` — atualiza baseline |
| `loc.backend_total` | Cresce livre, mas >20% num run = `[WARN]` | propor refactor |
| `files_over_1000_lines` | Nao crescer | `[WARN]` — propor split |
| `todos_count` | Nao crescer >2 num run | `[INFO]` — listar onde |
| `duration_s_p95` | Nao >1.5x baseline | `[WARN]` — propor parallelize |
| `ratchet_locks` | Itens NAO podem desaparecer sem entrega | `[CRITICAL]` |

`ratchet_locks` sao **debts conhecidos** que NAO podem ser silenciados.
Quando entregar um, atualiza valor pra `null` ou remove a chave —
isso e a "subida" do ratchet.

**Apos relatorio**, se Paulo confirmar acoes, atualizar baseline com
novos valores via `quality-baseline.json`. Se algum metric piorou
e Paulo justificar (ex: "loc cresceu por feature legitima"), ele
aprova update — caso contrario, baseline NAO atualiza e proxima
rodada continua flagando.

### 1. Testes (suite completa)

Roda os 3 conjuntos:

```bash
# Backend
cd <repo> && PYTHONPATH=backend py -m pytest backend/test_backend.py -q

# Agent
cd <repo> && PYTHONPATH=agent py -m pytest agent/test_agent.py -q

# Grafana dashboards (se existir)
cd <repo> && py -m pytest test_grafana.py -q  # ou ignora se nao houver
```

Reporta:
- Total passed / skipped / xfailed / xpassed / failed
- Diff vs ultima rodada (numero de testes nova/removida desde ultimo
  commit que mexeu em test_*.py)
- Tempo total (regression flag se >2x mediana)

Se houver `failed` ou `xpassed`, lista os nomes — Paulo pode pedir
fix imediato.

### 2. Sincronizacao com GitHub

Workflow Paulo: **main-only**, push direto. Nao tem branch `dev`.

```bash
git fetch origin --prune
git status -sb
git log --oneline origin/main..HEAD     # commits locais nao pushados
git log --oneline HEAD..origin/main     # commits remotos nao puxados
```

Reporta:
- `local AHEAD by N`, `BEHIND by N`, ou `synced`
- Branches stale no remoto (origin/feat-* parados >30d se houver)
- Arquivos uncommitted (`git status -s`) — flag se relevante (ignora
  `.claude/settings.local.json` e `*.update_tmp` que sao notmal)

**Se main local divergir de origin/main:** NAO faz pull/push automatico.
Sinaliza pro Paulo decidir (rebase? merge? force?).

**Se ele falar que quer usar `dev`:** explica que isso muda o workflow
estabelecido (memoria `feedback_workflow.md` registra main-only) e
pede confirmacao antes de criar/sincronizar `dev`.

### 3. Atualizacao de memorias

Le `~/.claude/projects/<projeto>/memory/MEMORY.md` + arquivos
referenciados.

Pra cada memoria:
- **project_***: cruza com `git log --since='<data>` desde a data
  do `originSessionId` ou ultima edicao. Se houver commits recentes
  que afetam o assunto da memoria, propoe atualizacao do conteudo.
- **feedback_***: estavel — so revisa se conflitam com algo recente.
- **reference_***: estavel — atualiza se infra mudou (novo container,
  nova porta).
- **user_***: estavel — so atualiza se Paulo der info nova.

Atualizacoes sao **propostas**, nao automaticas. Pra cada update
sugerido: descreve em 1-2 linhas no relatorio + pergunta se aplica.

**Pega memorias contraditorias** (ex: 2 arquivos dizem coisas
diferentes sobre mesma tabela) e flag.

### 4. Estado do roadmap

Le `memory/project_*.md` que ancoram fases (matriz de fundamentos,
Onda 1/2, etc.).

Pra cada item marcado como `pending` ou `em curso`:
- Procura commits relacionados via `git log --grep='<keyword>'`
- Se commit existe mas memoria nao atualizou: flag pra atualizar
- Se >7 dias sem progresso: flag como `parado` (talvez deprioritizado?)

Pra cada item marcado como `concluido`:
- Confere commit hash referenciado existe
- Confere SHA do commit ainda esta em main (nao foi force-pushed away)

Output: tabela ASCII com status real de cada fase.

### 5. Auditoria de debitos tecnicos conhecidos

Pull explicito da lista de debts da memoria + scan automatico:

**Manuais (memoria):**
- CSP `'unsafe-inline'` em `middlewares.py` (refactor B)
- NATS plain text em prod (Onda 1 P5 — exige janela)
- Per-host NATS scoping (P4b futuro)
- Bearer admin fallback global (mesmo que prod tenha guard, dev nao tem)
- `IPAPI_KEY` opcional — se vazio em prod, geo HTTP plain
- Single-process scheduler (D7)
- Backup verify nao agendado em cron

**Automaticos (scan):**
```bash
# Arquivos > 1000 linhas (candidato a modularizar)
find backend agent -name "*.py" -exec wc -l {} \; | awk '$1 > 1000'

# TODOs/FIXMEs/XXX no codigo
grep -rn "TODO\|FIXME\|XXX\|HACK" backend agent --include="*.py" | head -20

# Funcoes longas (heuristica simples — chunks com >100 linhas entre defs)
# Reporta como candidato a quebrar

# Imports nao usados / mortos
# (deixa pra um linter dedicado se Paulo quiser)
```

Reporta cada debt com:
- Arquivo:linha de origem
- Esforco estimado pra resolver (h)
- Beneficio (security / performance / clarity)
- Bloqueador se houver (precisa janela de manutencao? mexe em agente?)

### 5b. OSINT — robustez via inteligencia aberta

Roda checagens publicas (sem autenticar em service externo —
APIs gratuitas, ou inferencias locais). Foco em ameacas que afetam
um produto multi-tenant pra ISPs.

**Categorias:**

#### a. Vazamento de credenciais no repo

```bash
# gitleaks (D6 do roadmap fundamentos — quando instalar):
gitleaks detect --source . --no-git --redact

# Fallback heuristico se gitleaks nao instalado:
git log --all -p -G '(api[_-]?key|password|token|secret)' \
  --source --since='90 days ago' | head -200
```

Flag commits com pattern de secret exposto. Sugere `git filter-repo`
+ rotacao de credencial (NUNCA propoe so deletar — historia continua
no GitHub).

#### b. Subdomain takeover risks

Se o dominio principal (ex: `procyontecnologia.net`) tem CNAMEs
apontando pra services externos (Heroku, Azure, GitHub Pages) que
podem ter sido decomissionados:

```bash
# Lista CNAMEs do dominio principal (heuristica simples):
dig procyontecnologia.net ANY +short
dig nsmonitor.procyontecnologia.net CNAME +short
# Se algum CNAME aponta pra subdominio nao-cliente (*.herokuapp.com,
# *.azurewebsites.net, etc.) que ja esta livre, alguem pode reclamar
# o subdominio = takeover.
```

Reporta CNAMEs suspeitos pro Paulo verificar manualmente.

#### c. Certificate Transparency Logs (CT)

Pesquisa se existe cert emitido pra dominios do projeto que NAO foi
issued pelo operador legitimo:

```bash
# crt.sh API (publica, sem auth):
curl -s "https://crt.sh/?q=%25.procyontecnologia.net&output=json" \
  | jq -r '.[].name_value' | sort -u
```

Lista subdominios + data de emissao. Se aparece subdominio
desconhecido com cert recente, possivel hijack DNS ou rogue cert.

#### d. Exposicao publica via Shodan-style

Sem chave Shodan, mas heuristicas:

```bash
# Servicos expostos diretos no IP do servidor backend:
nmap -sT -p- --open <IP_PROD> 2>/dev/null | grep '/tcp.*open'

# Esperado em prod: 80, 443, 22 (ssh).
# 4222 (NATS) so se Onda 1 P5 nao foi feito ainda — flag.
# 8222 (NATS monitor) NUNCA deve aparecer publico — CRITICAL se houver.
# 5432 (PG) NUNCA deve aparecer publico — CRITICAL.
# 8000 (backend HTTP) NUNCA direto — backed devia ficar atras de nginx/CF.
```

Reporta cada porta inesperada como `[CRITICAL]` ou `[WARN]`.

#### e. CVEs em dependencias

```bash
# pip-audit (instalavel via pipx):
pip-audit -r backend/requirements.txt
pip-audit -r agent/requirements.txt

# Fallback: cruza requirements com NVD via API publica
# (so os pacotes diretos — fica como sugestao)
```

Lista CVEs com severity HIGH/CRITICAL. Sugere bump de versao no
proximo Dependabot PR.

#### f. DNS hijacking detection

Se o dominio do produto (`nsmonitor.procyontecnologia.net`) **estiver
servido pelos proprios agentes** do projeto (raro mas possivel),
checa se o registro NS bate:

```bash
dig +short NS procyontecnologia.net
dig +short SOA procyontecnologia.net
```

Mismatch entre NS de pais e filho = possivel hijacking. Flag.

#### g. Privacy patterns

Heuristica: hostnames de cliente seguem o padrao `NS<num>_<CLIENTE>`
(ex: `NS1_AVISOLUCOES`). Se algum log ou export publico expor estes
nomes, vaza relacao cliente <-> infra do operador. Procura:

```bash
# Pattern de hostname em arquivos publicos do repo
grep -rn "NS[0-9_]*_[A-Z]" backend/static/ docs/ specs/archive/ \
  --include="*.html" --include="*.md" 2>/dev/null
```

Flag se hostname real (nao placeholder tipo NS1_X) aparece em
docs/specs publicos.

#### h. Rate-limit tester adversarial (off-line)

Em vez de rodar contra prod (chama atencao), simula localmente:

```bash
# Testa que limite do middleware bate com .env
docker compose exec backend python -c "
from middlewares import APIRateLimitMiddleware
mw = APIRateLimitMiddleware(app=None)
# checa que limite default 120/min nao foi acidentalmente baixado
print('Defaults:', mw.LIMITS)
"
```

Reporta se algum limite parece muito alto (= permite DoS) ou muito
baixo (= rejeita user legit).

---

### 6. Sugestoes de melhoria proativas

Categorias:

**Refactor:** se `db.py` passou 1500 linhas, propoe split por dominio.
Se `routes_*.py` tem funcoes com 5+ niveis de indentacao, propoe extrair.
Se duas funcoes tem >70% de codigo similar, propoe helper.

**Modularizacao:** se um arquivo tem N "secoes" demarcadas por
comentarios `# ===`, e cada secao podia ser submodulo, sugere extracao.
Se `static/*.js` tem funcoes globais que so um HTML usa, sugere
escopa-las.

**Hardening:** olha pra superficie nova nos ultimos commits e propoe
defesas. Exemplos:
- Endpoint novo aceitando user input -> Pydantic schema explicito?
- DB query com f-string -> parametrizar?
- Operacao destrutiva sem confirm token -> adicionar?
- Funcao que faz HTTP request -> tem timeout?
- Exception handler engole exception -> logar?

**Performance:** se Fase B (N+1 detector) reportou template novo no
log de prod, sugere batch/JOIN. Se slow request middleware logou
warning recente, lista candidatos.

### 7. Sincronizacao final

Apos producir relatorio:
- NAO comita nada
- NAO faz push
- NAO faz pull
- Salva o relatorio em `/tmp/quality-gate-<timestamp>.md` pro
  Paulo poder consultar dpois

---

## Formato do relatorio final

Saida unica markdown na resposta do chat (Paulo le e decide acoes):

```markdown
# Quality Gate — <data ISO>

## RATCHET status
[OK | CRITICAL | BOOTSTRAP]
- total_passed: <N> (baseline: <N>) — <subiu N | manteve | DESCEU N>
- total_failed: <N> (baseline: 0) — <ok | CRITICAL>
- files_over_1000: <N> (baseline: <N>) — <ok | WARN +N>
- duration_s_p95: <N>s (baseline: <N>s) — <ok | regressao Nx>

## Sumario executivo
- Testes: <ok/fail>, <N> passed
- Ratchet: <OK | violacoes>
- GitHub: <synced/ahead/behind>
- Memorias: <N> propostas de update
- Roadmap: <N> itens pending; <N> stale
- Debts: <N> conhecidos; <N> novos via scan
- OSINT: <N> findings (P0=criticos, P1=importantes, P2=info)
- Sugestoes: <N>

## 0. Ratchet
[detalhes — comparacao baseline vs atual; cada violacao com [CRITICAL/WARN/INFO]]

## 1. Testes
[detalhes]

## 2. GitHub
[detalhes]

## 3. Memorias
- [PROPOR] arquivo X: <delta sugerido>
- [OK] arquivo Y: estavel

## 4. Roadmap
| Fase | Status memoria | Status real | Acao |
|---|---|---|---|
| Onda 1 P5 | pending | pending — sem commits | nenhuma |
| Onda 2 SEC-2.4 | concluido | concluido (1d62204) | OK |

## 5. Debts
### Conhecidos
- CSP unsafe-inline (middlewares.py:227): refactor B em curso, ETA 2026-05-07
- ...

### Novos (scan)
- backend/db.py: 1467 linhas — candidato a split por dominio (audit/admin/metrics)
- ...

## 5b. OSINT findings
### P0 (Criticos — acao imediata)
- ...

### P1 (Importante)
- ...

### P2 (Informativo)
- ...

## 6. Sugestoes
### Refactor
- ...
### Hardening
- ...
### Performance
- ...

## 7. Acoes recomendadas (top 3)
1. ...
2. ...
3. ...

## 8. Atualizar baseline?
[Lista de mudancas que estariam OK promover ao novo baseline. Paulo
confirma com 'sim' antes de gravar em quality-baseline.json.]
```

---

## Politica de bloqueio (CRITICAL)

Se qualquer item virar `[CRITICAL]`, a skill **interrompe o pipeline**
e exige acao do Paulo antes de continuar. Itens criticos:

- Teste falhando (`total_failed > 0`)
- `total_passed` desceu sem motivo (regressao silenciosa)
- `ratchet_locks` perdeu chave sem entrega no commit log
- OSINT: porta 5432/8222/8000 publica
- OSINT: secret exposto no git log
- OSINT: cert emitido pra dominio nao-autorizado em CT log

Em CRITICAL, o relatorio **comeca com banner**:

```
🛑 RATCHET VIOLATION DETECTED — fix antes de continuar.

Critical: <descricao curta>
Acao recomendada: <comando ou step explicito>
```

Paulo decide: corrige e re-executa, ou justifica explicitamente
(skill aceita `--accept-violation=<motivo>` em situacao excepcional).

---

## Restricoes (NAO faca)

- **NAO comite** nada automaticamente. Mesmo que detecte fix obvio.
- **NAO modifique memorias** sem permissao explicita do Paulo —
  apenas *proponha*.
- **NAO faca pull/push** automatico. Mesmo que main esteja divergente.
- **NAO altere roadmap** sem confirmacao — apenas reflete estado real.
- **NAO crie issue/PR no GitHub** automaticamente.

A skill e **read-mostly**: produz analise + sugestoes. Mudancas saem
em commits separados, com Paulo aprovando cada um.

---

## Execucao tipica

```
Paulo: /quality-gate
Skill:
  [1/7] Testes... 281 passed, 2 skipped, 1 xfailed (15.43s) — OK
  [2/7] GitHub... main local: synced com origin/main — OK
  [3/7] Memorias... 2 propostas de update; nenhuma contradicao
  [4/7] Roadmap... Onda 1 P5 e P4b pendentes; FundamentosC ainda pending
  [5/7] Debts... 3 conhecidos; 2 novos via scan
  [6/7] Sugestoes... 4 refactors, 2 hardenings, 1 performance
  [7/7] Salvando relatorio em /tmp/quality-gate-2026-05-04T15-10-00.md

  [Relatorio markdown completo aqui]

  Top 3 acoes recomendadas:
    1. Atualizar memoria 'project_onda1_security.md' (commit 80a5774
       falta no status da P4)
    2. SEC: routes_agent.py:639 ainda usa http://ip-api.com/batch
       quando IPAPI_KEY ausente em INFRA_VISION_ENV=production —
       considerar hard-fail.
    3. db.py com 1467 linhas — extrair `audit/` e `metrics/`
       pra modulos separados (preserva imports via re-export).
```

---

## Regra de ouro

Se algum bloco produzir saida que **assusta** o operador (ex: `git log`
com commit de force-push misterioso, ou memoria com fato falso sobre
estado de prod), **interrompe o pipeline** e pergunta ao Paulo antes
de continuar. Babysit nao significa execucao cega.
