# Domain Security Checker

Aplicacao web para analise de postura de seguranca de dominio, autenticacao de e-mail, transporte seguro, monitoramento, historico, asset discovery e relatorios.

## Stack

- Python
- FastAPI
- Pydantic v2
- SQLAlchemy
- Jinja2
- SQLite
- dnspython
- Pytest
- WeasyPrint
- GeoIP2 / MaxMind

## Principios mantidos

- Regras de negocio continuam em `app/services`
- Rotas permanecem finas
- Schemas publicos seguem normalizados e sem vazar estruturas internas de bibliotecas de referencia
- DKIM continua heuristico sem headers reais
- `provider_guess` continua inferencia
- TLS de e-mail continua deixando claro que o certificado costuma ser do servidor MX
- RDAP, GeoIP e discovery continuam podendo retornar dados parciais
- Asset discovery continua separado do score principal e do request publico `/analyze`

## Novidades desta iteracao

- Exportacao PDF a partir de HTML/CSS com presenter e template dedicados
- Inteligencia de IP via provider MaxMind/GeoIP2 com import tardio e fallback controlado
- Aprofundamento de politicas de e-mail:
  - contagem SPF com recursion e void lookups
  - MTA-STS
  - SMTP TLS Reporting
  - BIMI readiness
  - base de schema para DNSSEC futuro
- Modulo separado de Asset Discovery inspirado em Amass
- Endpoints e telas dedicados para discovery

## Instalacao local

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .[dev]
uvicorn app.main:app --reload
```

## Dependencias opcionais importantes

### PDF com WeasyPrint

O projeto agora usa `WeasyPrint` como motor principal de PDF.

- Dependencia Python ja esta declarada no projeto
- Em Windows, o runtime nativo do WeasyPrint pode exigir Pango e dependencias do MSYS2
- Se o ambiente nao conseguir carregar o WeasyPrint, a rota de exportacao responde com indisponibilidade controlada em vez de quebrar a aplicacao

Rotas:

- `GET /reports/{domain}.pdf`

### GeoIP com MaxMind

O bloco `ip_intelligence` agora usa provider MaxMind/GeoIP2.

Modos suportados:

- bases locais MMDB
- credenciais de web service MaxMind para enriquecimento parcial

Se nada estiver configurado:

- a resolucao A/AAAA continua funcionando
- o bloco de GeoIP volta como indisponivel de forma explicita
- a analise principal nao quebra

### Asset Discovery com Amass

O discovery usa um runner externo configuravel.

- nunca roda dentro de `/analyze`
- persiste execucoes e subdominios descobertos
- marca quais achados eram novos para o sistema
- falha de forma controlada quando o binario nao existe ou a feature esta desabilitada

Rotas web:

- `GET /discovery`
- `POST /discovery/runs`
- `GET /discovery/runs/{id}`

Rotas API autenticadas por sessao:

- `GET /api/v1/discovery`
- `POST /api/v1/discovery`
- `GET /api/v1/discovery/{id}`

## Variaveis de ambiente

Consulte `.env.example`. Os grupos principais agora sao:

- `DSC_GEOIP_*`: provider MaxMind/GeoIP2
- `DSC_ASSET_DISCOVERY_*` e `DSC_AMASS_*`: modulo de discovery
- `DSC_EMAIL_DELIVERY_ENABLED` e `DSC_SMTP_*`: alertas por e-mail

## Modulo de monitoramento

O monitoramento autenticado continua disponivel com:

- estados `active`, `paused` e `deleted`
- API externa autenticada por token somente para monitoramento
- exportacao PDF do snapshot mais recente

Endpoints externos de monitoramento:

- `POST /api/external/v1/monitoring`
- `GET /api/external/v1/monitoring`
- `GET /api/external/v1/monitoring/{id}`
- `POST /api/external/v1/monitoring/{id}/pause`
- `POST /api/external/v1/monitoring/{id}/resume`
- `DELETE /api/external/v1/monitoring/{id}`

## Testes

```bash
pytest -q
```

Estado atual da suite nesta implementacao:

- `53 passed`

## Limitacoes conhecidas

- WeasyPrint depende de bibliotecas nativas do sistema
- MaxMind pode retornar campos ausentes; geolocalizacao continua aproximada
- BIMI readiness nao equivale a garantia de exibicao universal em provedores de mailbox
- DNSSEC ficou preparado no schema e na apresentacao, mas ainda nao entrou no motor principal
- O runner de Amass foi mantido desacoplado e simples; nao ha fila assicrona dedicada ainda

## Referencias arquiteturais usadas nesta iteracao

- `Kozea/WeasyPrint`: renderizacao HTML/CSS para PDF
- `maxmind/GeoIP2-python`: provider MaxMind para contexto de IP
- `domainaware/checkdmarc`: abordagem de parsing e normalizacao para SPF, MTA-STS, TLS-RPT e BIMI
- `owasp-amass/amass`: separacao do modulo de attack surface discovery e persistencia de runs
