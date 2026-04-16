# Domain Security Checker

Aplicação web para análise de postura de segurança de domínio e autenticação de e-mail.

## Status atual

Etapa 1 concluída: estrutura inicial do projeto e esqueleto funcional do MVP.

## Stack

- Python
- FastAPI
- Pydantic v2
- dnspython
- SQLAlchemy
- Jinja2
- SQLite
- Pytest

## Executando localmente

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .[dev]
uvicorn app.main:app --reload
```

Abra `http://127.0.0.1:8000`.

## O que já existe

- Estrutura em camadas (`api`, `core`, `schemas`, `services`, `utils`, `db`)
- Aplicação FastAPI mínima com rotas web e API
- Template HTML inicial com formulário
- Normalização básica de domínio ou e-mail
- Resposta placeholder honesta para a análise
- Testes básicos de smoke test

## Limitação importante sobre DKIM

DKIM não pode ser confirmado de forma confiável apenas com o domínio informado. No MVP haverá apenas uma estratégia honesta:

- tentar heurísticas quando o selector não for conhecido
- deixar a estrutura pronta para validação confiável futura via headers reais de e-mail

## Próximas etapas

1. Implementar o backend base com tratamento de erros mais completo
2. Implementar serviços reais de DNS, MX, SPF, DMARC e heurística de DKIM
3. Adicionar score e recomendações priorizadas
4. Evoluir a interface HTML
5. Configurar Docker do MVP

