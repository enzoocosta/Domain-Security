# Arquitetura inicial

## Objetivo desta etapa

Criar a base do projeto com separação clara entre camadas, pronto para receber a implementação real da análise nas próximas etapas.

## Camadas

- `app/api/routes`: endpoints web e JSON
- `app/core`: configuração central e exceções compartilhadas
- `app/schemas`: contratos Pydantic para request e response
- `app/services`: orquestração e regras de negócio
- `app/utils`: normalização e helpers puros
- `app/db`: base SQLAlchemy e sessão
- `app/templates`: HTML do frontend inicial
- `app/static`: CSS estático
- `tests`: smoke tests do esqueleto
- `docs`: documentação do projeto

## Fluxo atual

1. O usuário envia um domínio ou e-mail.
2. A rota chama `DomainAnalysisService`.
3. O serviço normaliza a entrada.
4. A aplicação retorna um placeholder honesto, sem simular validações DNS ainda não implementadas.

## Nota sobre DKIM

Confirmar DKIM apenas com o domínio não é confiável em todos os casos, porque normalmente é necessário conhecer o selector usado na assinatura e, idealmente, validar headers reais da mensagem.

Estratégia do MVP:

- usar heurísticas apenas quando o selector não for conhecido
- manter a arquitetura pronta para evolução posterior via análise de headers de e-mail
