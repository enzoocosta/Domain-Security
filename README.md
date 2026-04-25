# Domain Security Checker

Aplicacao web para analise de postura de seguranca de dominio, autenticacao de e-mail, transporte seguro, monitoramento, historico, asset discovery, relatorios e analise de seguranca para sites WordPress.

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

---

## Novidades desta iteracao

### Controle de visibilidade por perfil de usuario (navegacao)

A barra de navegacao agora aplica renderizacao condicional com base no perfil do usuario autenticado:

- Usuarios com perfil `client` visualizam apenas: **Analise Publica**, **Monitoramento**, **Monitoring Plus** e **WordPress**
- Usuarios com perfil `developer` ou `admin` visualizam todos os itens, incluindo **Asset Discovery** e **API Docs**
- Os itens restritos sao removidos do DOM (nao apenas ocultados via CSS) para usuarios sem permissao

### Modulo WordPress — Analise de Seguranca para Sites WordPress

Nova pagina dedicada em `/wordpress` com foco em diagnostico de vulnerabilidades em sites construidos com WordPress, acessivel para todos os perfis de usuario.

#### Seletor de perfil de analise

Ao acessar a pagina, o usuario escolhe entre dois modos antes de iniciar qualquer analise:

- **Usuario Comum** — linguagem simplificada, analogias do cotidiano, exemplos visuais e orientacoes em linguagem acessivel para leigos
- **Tecnico de TI** — dados tecnicos completos, CVEs, CVSS scores, evidencias coletadas e orientacoes de remediacao

O conteudo exibido muda integralmente conforme a escolha, sem recarregar a pagina.

#### Deteccao de WordPress em 10 camadas

O sistema aplica deteccao em multiplas camadas em paralelo (`Promise.allSettled`). WordPress e considerado presente se **qualquer** camada retornar positivo. Apenas quando todas as 10 falharem o site e classificado como nao-WordPress:

| Camada | Sinal verificado |
|--------|-----------------|
| 1 | Meta tag `<meta name="generator" content="WordPress...">` |
| 2 | Paths `/wp-content/` ou `/wp-includes/` no HTML |
| 3 | Endpoint REST API em `/wp-json/` |
| 4 | Presenca de `wp-login.php` |
| 5 | Presenca de `xmlrpc.php` |
| 6 | Diretorio `/wp-admin/` acessivel |
| 7 | Feed RSS com generator WordPress |
| 8 | Cookies de sessao com prefixo `wordpress_` ou `wp-settings-` |
| 9 | Script handles exclusivos do core (`wp-emoji`, `/wp-includes/js/`) |
| 10 | Classes CSS automaticas do WordPress no elemento `<body>` |

O resultado inclui nivel de confianca (`confirmed` / `likely` / `unlikely`), versao detectada quando disponivel, e flag `versionHidden` quando o WordPress e identificado mas a versao esta oculta.

#### Integracao com WPVulnerability.net

Apos confirmar WordPress, o sistema executa analise de vulnerabilidades em tres etapas via API publica e gratuita do WPVulnerability.net (sem autenticacao, sem limite de requests):

**Etapa 1 — Core WordPress**
- Detecta a versao via meta generator, feed RSS ou `readme.html`
- Consulta `GET https://www.wpvulnerability.net/core/{versao}`

**Etapa 2 — Plugins ativos**
- Extrai slugs de plugins a partir de paths `/wp-content/plugins/{slug}/` no HTML
- Consulta `GET https://www.wpvulnerability.net/plugin/{slug}` para cada plugin detectado

**Etapa 3 — Tema ativo**
- Extrai o slug do tema a partir de `/wp-content/themes/{slug}/` no HTML
- Consulta `GET https://www.wpvulnerability.net/theme/{slug}`

Todas as requisicoes sao realizadas server-side para evitar bloqueios de CORS. Cache de 1 hora por URL analisada esta implementado para evitar chamadas redundantes.

#### Score de seguranca WordPress

Ao concluir a analise, um score de 0 a 100 e calculado:

- Inicia em 100
- `-30` por vulnerabilidade critica
- `-15` por vulnerabilidade alta
- `-8` por vulnerabilidade media
- `-3` por vulnerabilidade baixa

Classificacao visual do score:

- 80–100 → Seguro
- 50–79 → Atencao
- 0–49 → Em Risco

#### Exportacao

- Botao **Exportar PDF** com relatorio completo da analise WordPress
- Botao **Copiar JSON** com dados tecnicos estruturados (modo Tecnico de TI)
- Botao **Gerar relatorio para o cliente** (converte visao tecnica em visao simplificada)

---

## Instalacao local

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .[dev]
uvicorn app.main:app --reload
```

---

## Dependencias opcionais importantes

### PDF com WeasyPrint

O projeto usa `WeasyPrint` como motor principal de PDF.

- Dependencia Python ja esta declarada no projeto
- Em Windows, o runtime nativo do WeasyPrint pode exigir Pango e dependencias do MSYS2
- Se o ambiente nao conseguir carregar o WeasyPrint, a rota de exportacao responde com indisponibilidade controlada em vez de quebrar a aplicacao

Rotas:

- `GET /reports/{domain}.pdf`

### GeoIP com MaxMind

O bloco `ip_intelligence` usa provider MaxMind/GeoIP2.

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

Rotas web (visivel apenas para perfis `developer` e `admin`):

- `GET /discovery`
- `POST /discovery/runs`
- `GET /discovery/runs/{id}`

Rotas API autenticadas por sessao (visivel apenas para perfis `developer` e `admin`):

- `GET /api/v1/discovery`
- `POST /api/v1/discovery`
- `GET /api/v1/discovery/{id}`

---

## Rotas da aplicacao

### Publicas

- `GET /` — pagina inicial
- `GET /analyze` — analise publica de dominio
- `GET /wordpress` — analise de seguranca WordPress (todos os perfis)

### Autenticadas — todos os usuarios

- `GET /monitoring` — painel de monitoramento
- `GET /monitoring-plus` — monitoramento avancado

### Autenticadas — apenas `developer` e `admin`

- `GET /discovery` — asset discovery
- `GET /api-docs` — documentacao da API

### API de monitoramento externo

- `POST /api/external/v1/monitoring`
- `GET /api/external/v1/monitoring`
- `GET /api/external/v1/monitoring/{id}`
- `POST /api/external/v1/monitoring/{id}/pause`
- `POST /api/external/v1/monitoring/{id}/resume`
- `DELETE /api/external/v1/monitoring/{id}`

---

## Variaveis de ambiente

Consulte `.env.example`. Os grupos principais sao:

- `DSC_GEOIP_*` — provider MaxMind/GeoIP2
- `DSC_ASSET_DISCOVERY_*` e `DSC_AMASS_*` — modulo de discovery
- `DSC_EMAIL_DELIVERY_ENABLED` e `DSC_SMTP_*` — alertas por e-mail

---

## Modulo de monitoramento

O monitoramento autenticado continua disponivel com:

- estados `active`, `paused` e `deleted`
- API externa autenticada por token somente para monitoramento
- exportacao PDF do snapshot mais recente

---

## Testes

```bash
pytest -q
```

Estado atual da suite:

- `53 passed`

---

## Limitacoes conhecidas

- WeasyPrint depende de bibliotecas nativas do sistema
- MaxMind pode retornar campos ausentes; geolocalizacao continua aproximada
- BIMI readiness nao equivale a garantia de exibicao universal em provedores de mailbox
- DNSSEC ficou preparado no schema e na apresentacao, mas ainda nao entrou no motor principal
- O runner de Amass foi mantido desacoplado e simples; nao ha fila assicrona dedicada ainda
- A deteccao de plugins e temas WordPress depende de assets expostos no HTML publico; plugins carregados condicionalmente podem nao ser detectados
- A versao do WordPress nao e detectada quando todos os sinais de exposicao de versao foram removidos (boa pratica de hardening); o sistema sinaliza isso explicitamente ao usuario

---

## Referencias arquiteturais

- `Kozea/WeasyPrint` — renderizacao HTML/CSS para PDF
- `maxmind/GeoIP2-python` — provider MaxMind para contexto de IP
- `domainaware/checkdmarc` — parsing e normalizacao para SPF, MTA-STS, TLS-RPT e BIMI
- `owasp-amass/amass` — separacao do modulo de attack surface discovery e persistencia de runs
- `WPVulnerability.net` — base de dados publica e gratuita de vulnerabilidades WordPress (core, plugins e temas)
