# Contribuindo com o DNS Monitor

## Workflow obrigatório: TDD + XP

Todo código novo segue o ciclo **Red → Green → Refactor**.
Nenhuma implementação entra sem testes que a especifiquem primeiro.

---

## Ciclo por feature

### 1. Especificação (SDD)
Antes de qualquer código, descreva o comportamento em linguagem natural:

```
DADO que o agente está marcado como inativo
QUANDO inactive_since > 3 dias
ENTÃO delete_inactive_agents() deve remover o agente e retornar o hostname
```

Isso vira o nome da classe e dos métodos de teste.

### 2. RED — Escreva o teste primeiro

O teste deve falhar porque a implementação ainda não existe.

```bash
# Backend
cd backend && pytest test_backend.py::NomeDaClasseDeTeste -v
# → FAILED (ImportError ou AssertionError esperado)

# Agente
pytest test_agent.py::NomeDaClasseDeTeste -v
# → FAILED
```

Regra: **não avance se o teste já passar** — significa que o comportamento já existe
ou o teste está errado.

### 3. GREEN — Mínimo para passar

Implemente apenas o necessário para o teste passar. Sem código extra, sem "já que estou aqui".

```bash
pytest test_backend.py::NomeDaClasseDeTeste -v
# → PASSED
```

### 4. REFACTOR — Limpar sem quebrar

Melhore o código mantendo os testes verdes.

```bash
pytest test_backend.py -v   # todos devem continuar passando
pytest test_agent.py -v
```

---

## Rodar todos os testes

```bash
# Backend (rodar na pasta backend/)
cd backend
PYTHONPATH=. pytest test_backend.py -v

# Agente (rodar na raiz)
PYTHONPATH=. pytest agent/test_agent.py -v

# Dashboards
pytest test_grafana.py -v
```

**Todos devem passar antes de qualquer `docker compose build`.**

---

## Convenções de teste

| O que testar | Onde |
|---|---|
| Endpoints FastAPI, db.py, scheduler | `backend/test_backend.py` |
| Agente (coleta, DNS, comandos) | `agent/test_agent.py` |
| Dashboards Grafana (JSON) | `test_grafana.py` |

### Estrutura padrão de uma classe de teste

```python
class TestNomoDaFeature:
    """
    DADO <contexto>
    QUANDO <ação>
    ENTÃO <resultado esperado>
    """

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def test_comportamento_especifico(self):
        # Arrange — monta mocks e dados
        mock_db = AsyncMock(return_value=True)

        async def run():
            # Act — executa a função
            with patch("main.db.alguma_funcao", mock_db):
                resp = await m.algum_endpoint(...)
            # Assert — verifica resultado
            assert resp.status_code == 200

        self._run(run())
```

### Regras

- Um teste = um comportamento. Nomes no formato `test_<o_que_faz>_<sob_qual_condicao>`.
- Nunca use banco real nos testes — sempre `AsyncMock` + `patch`.
- Testes de assinatura (`inspect.signature`) verificam contratos de API interna.
- Se um bug aparecer em produção: escreva o teste que o reproduz **antes** de corrigir.

---

## Checklist antes do deploy

- [ ] `pytest backend/test_backend.py -v` — todos passando
- [ ] `pytest agent/test_agent.py -v` — todos passando
- [ ] `pytest test_grafana.py -v` — todos passando
- [ ] `docker compose build --no-cache backend` sem erros
- [ ] `curl http://localhost:8000/health` retorna `{"status":"ok"}`
