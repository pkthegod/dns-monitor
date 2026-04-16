---
name: dev-artist
version: 2.0.0
description: Engineering protocol — Shokunin craftsmanship, XP discipline, and security-first gates for every code change
author: PK
license: MIT
enforcement: strict
blocking: true
scope:
  - backend
  - agent
  - devops
  - security
tags:
  - xp
  - shokunin
  - esaa
  - security
  - engineering
  - quality-gate
---

# Dev-Artist Engineering Protocol

> **Papel**: protocolo de qualidade e seguranca que governa COMO desenvolver.
> Os skills speckit governam O QUE construir (spec, plan, tasks, implement).
> Dev-Artist atua como overlay de qualidade sobre qualquer workflow.

---

## Principios Fundamentais

### 1. Shokunin Katagi (artesao)

- Responsabilidade total pelo codigo entregue
- Atencao obsessiva ao detalhe — cada linha importa
- Kaizen: melhoria continua, nunca "bom o bastante"
- Resolver causa raiz, nao sintoma

### 2. Extreme Programming (XP)

- Iteracoes curtas: mudanca minima, feedback imediato
- TDD obrigatorio: Red -> Green -> Refactor
- Simplicidade radical: YAGNI, sem abstracoes especulativas
- Coragem para refatorar, disciplina para nao extrapolar escopo

### 3. ESAA-Security (Evidence-Sourced Audit & Assurance)

- Toda mudanca de seguranca precisa de evidencia (teste, log, diff)
- Execucao deterministica: mesma entrada = mesma saida
- Auditoria por dominios com severidade
- Findings rastreados ate resolucao

---

## Fases Operacionais

### Fase 1: CONHECER

Antes de tocar qualquer arquivo:

- [ ] Ler todo codigo relevante ao escopo da mudanca
- [ ] Entender arquitetura existente e padroes do projeto
- [ ] Consultar a constituicao do projeto (`.specify/memory/constitution.md`)
- [ ] Identificar testes existentes que cobrem a area

**GATE**: nao prosseguir sem entendimento. Se nao leu, nao altera.

### Fase 2: SEGURANCA

Avaliar a mudanca contra os dominios de seguranca:

#### CRITICAL (bloqueante se violado)

| Dominio | Verificacao |
|---------|------------|
| Secrets | Nenhum segredo hardcoded; `.env` no `.gitignore`; vars via `EnvironmentFile` |
| Auth | Bearer token com validacao; cookies HMAC-signed com expiracao |
| AuthZ | Rotas admin protegidas; controle de acesso por papel |
| Input | Parametros validados; SQL com `$1, $2` (asyncpg); sem interpolacao |
| Dados | Sem vazamento de dados sensiveis em logs ou respostas de erro |

#### HIGH (corrigir antes de merge)

| Dominio | Verificacao |
|---------|------------|
| Deps | Sem vulnerabilidades conhecidas em dependencias |
| API | Rate limiting em endpoints publicos; respostas sem stack traces |
| Agente | Fingerprint SHA256 validado; auto-update com `py_compile` antes de aplicar |
| Sessao | Cookies `httponly`, `samesite`; sessao com TTL |
| Crypto | Hashing com algoritmos atuais (SHA256+); sem MD5/SHA1 para seguranca |

#### MEDIUM (corrigir no proximo ciclo)

| Dominio | Verificacao |
|---------|------------|
| Infra | Container non-root; rede isolada; `--workers 1` |
| Headers | CORS restrito (nao `*`); headers de seguranca presentes |
| Logging | Logs sem dados sensiveis; rotacao configurada |
| DevSecOps | CI/CD sem secrets expostos; deploy requer testes verdes |

**GATE**: qualquer CRITICAL aberto bloqueia a entrega.

### Fase 3: ITERAR

- [ ] Mudanca minima e focada — um conceito por commit
- [ ] Escrever teste primeiro (Red)
- [ ] Implementar ate teste passar (Green)
- [ ] Refatorar se necessario (Refactor)
- [ ] Build/lint sem erros nem warnings novos

**GATE**: nao acumular mudancas sem validacao.

### Fase 4: VALIDAR

- [ ] Todos os testes passando (`pytest --tb=short -q`)
- [ ] Testes do agente: `agent/test_agent.py`
- [ ] Testes do backend: `backend/test_backend.py`
- [ ] Verificar que nenhum teste foi removido ou desabilitado sem justificativa
- [ ] Contagem de testes >= contagem anterior

**GATE**: merge bloqueado se qualquer teste falhar.

### Fase 5: ENTREGAR

- [ ] Commit com mensagem descritiva (feat/fix/refactor/docs/chore)
- [ ] Sem arquivos desnecessarios no staging (`.env`, `__pycache__`, `.update_tmp`)
- [ ] CHANGELOG atualizado se for release
- [ ] Tag de versao se aplicavel
- [ ] Deploy: `docker compose build --no-cache backend && docker compose up -d`
- [ ] Health check: `curl http://localhost:8000/health`

---

## Anti-Padroes (proibidos)

### Codigo

- Alterar codigo sem ter lido o contexto
- Ignorar erros de build ou warnings
- Deploy sem rodar testes
- Adicionar features nao solicitadas
- Criar abstracoes para uso unico

### Seguranca

- Secrets no codigo ou em commits
- CORS com `*` em producao
- SQL por concatenacao de string
- Input do usuario sem validacao
- Dependencias com CVEs conhecidos
- `--no-verify` em commits ou push
- Container rodando como root

---

## Scoring de Seguranca

Calcular apos revisar todos os dominios:

| Score | Status | Acao |
|-------|--------|------|
| 86-100 | OK | Pode entregar |
| 71-85 | Atencao | Corrigir MEDIUM antes do proximo ciclo |
| 51-70 | Risco | Corrigir HIGH antes de merge |
| 31-50 | Critico | Corrigir CRITICAL imediatamente |
| 0-30 | Bloqueado | Parar. Nao entregar ate resolver |

**Formula**: iniciar em 100, subtrair por finding:
- CRITICAL: -20 pontos cada
- HIGH: -10 pontos cada
- MEDIUM: -5 pontos cada

---

## Regras de Bloqueio

A execucao DEVE parar se:

1. Qualquer finding CRITICAL aberto
2. Testes falhando
3. Build com erros
4. Mudanca sem evidencia de validacao
5. Seguranca nao revisada

O agente (Claude) deve reportar o bloqueio ao usuario com:
- O que bloqueou
- Por que bloqueou
- Como resolver

---

## Protocolo de Execucao (para agentes)

```
1. CONHECER  ->  ler codigo, entender contexto, consultar constituicao
2. SEGURANCA ->  avaliar dominios, calcular score, reportar findings
3. ITERAR    ->  TDD (Red-Green-Refactor), mudanca minima
4. VALIDAR   ->  rodar todos os testes, verificar contagem
5. ENTREGAR  ->  commit limpo, CHANGELOG, deploy, health check
```

Cada fase tem um GATE. Nao pular fases. Se um gate falhar, resolver antes de avancar.

---

## Complementaridade com SpecKit

| Aspecto | SpecKit | Dev-Artist |
|---------|---------|------------|
| Foco | O QUE construir | COMO construir |
| Specs | `/speckit-specify`, `/speckit-clarify` | -- |
| Planejamento | `/speckit-plan`, `/speckit-tasks` | -- |
| Qualidade de requisitos | `/speckit-checklist`, `/speckit-analyze` | -- |
| Qualidade de codigo | -- | Fases CONHECER + ITERAR |
| Seguranca | -- | Fase SEGURANCA + Scoring |
| Filosofia de engenharia | -- | Shokunin + XP + ESAA |
| Implementacao | `/speckit-implement` | Overlay de qualidade |

Dev-Artist nao substitui nenhum skill speckit. Ele adiciona gates de qualidade e seguranca ao fluxo.

---

## Enforcement

- Protocolo obrigatorio em toda mudanca de codigo
- Violacoes invalidam a entrega
- Score de seguranca deve ser >= 71 para merge
- Evidencia de validacao (testes verdes) e requisito, nao sugestao
