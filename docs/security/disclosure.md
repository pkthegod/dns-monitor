# Politica de Disclosure de Seguranca

**Ultima atualizacao:** 2026-04-30

## Reportando uma vulnerabilidade

Se voce descobriu uma vulnerabilidade de seguranca no Infra-Vision,
**nao** abra issue publica no GitHub. Reporte por email pra:

> **security@procyontecnologia.com.br**

Use este modelo:

```
Resumo: <1 linha>
Componente: <backend / agent / install_agent.sh / outro>
Versao afetada: <commit hash ou tag>
Impacto estimado: <low / medium / high / critical>
Como reproduzir: <passos minimos>
PoC (se houver): <anexo ou paste>
Mitigacao sugerida: <opcional>
```

PGP opcional — chave publica sob pedido no mesmo email.

## Compromisso de resposta

| SLA | Compromisso |
|-----|-------------|
| 48h | Confirmacao de recebimento + triagem inicial |
| 7d  | Decisao: fix, mitigation, ou wontfix com justificativa |
| 30d | Patch publicado pra critical/high (se confirmado) |
| 90d | Patch publicado pra medium/low |

## Coordinated disclosure

Pedimos pra **nao divulgar publicamente** (post, twitter, talk) ate
que um dos seguintes ocorra:

1. Patch publicado e disponivel pra clientes via update do agente, OU
2. 90 dias passaram desde o report (regra de transparencia), OU
3. Mutuamente acordamos data de disclosure.

Em troca: damos credito publico (a menos que voce prefira anonimato),
incluimos no changelog, e priorizamos o issue.

## Escopo

### In-scope
- Backend (`backend/*` no repo)
- Agente (`agent/*` no repo, instalado em `/opt/dns-agent/`)
- Scripts de provisionamento (`agent/install_agent.sh`, `agent/setup_dns_stats.sh`)
- Containers Docker oficiais
- Painel admin (`/admin/*`) e portal cliente (`/client/*`)
- Endpoints API (`/api/v1/*`)
- Mecanismo de auto-update (`/agent/version`, `/agent/latest`)

### Out-of-scope
- Hosts de clientes individuais (BIND/Unbound configurados pelo cliente)
- DNS recursivo upstream (Google, Cloudflare, etc.)
- Ataques que requerem comprometimento previo da maquina onde o agente roda
- Social engineering contra operadores
- DDoS volumetrico (mitigacao e responsabilidade do cliente/upstream)
- Ataques fisicos contra servidores

## Severidade — guia interno

Usamos CVSS v3.1 como referencia, mas damos peso extra a cenarios ISP:

| Severidade | Exemplo |
|------------|---------|
| Critical | RCE remoto sem auth no backend; vazamento de chaves DNSSEC do cliente; bypass total de RBAC |
| High | Privilege escalation viewer→admin; SQL injection autenticado; comprometimento de 1 agente vira admin geral |
| Medium | XSS authenticated; CSRF em mutativos; informacao sensivel em logs |
| Low | Header missing; rate limit bypassable em endpoint nao-critico; info disclosure menor |

## Hall of fame

Pesquisadores que reportaram falhas legítimas e cooperaram com
disclosure aparecem aqui (lista atualizada apos primeiro report
elegivel).

## Changelog

- **2026-04-30** — Documento criado. Bloco 4 do roadmap v1.5 security audit.

## Referencias

- [security_audit_2026_04_27](../../specs/archive/) — auditoria interna
- [SECURITY-FIXES-2026-04-22](./SECURITY-FIXES-2026-04-22.md) — historico de fixes
- ASVS Level 2 — referencia de baseline pra alvos de cada release
- OWASP Top 10 — checklist por release
