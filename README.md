# Domain Security Checker

Aplicação web para análise de postura de segurança de domínio, autenticação de e-mail e segurança de transporte.

## Status do projeto

🚧 **Em desenvolvimento**

O projeto já passou da fase inicial de estruturação e atualmente possui um MVP funcional com análise real de domínio, interface web operante, score de segurança, severidade, findings e recomendações.

> Esta ainda não é a versão final do projeto.

---

## Sobre o projeto

O **Domain Security Checker** foi criado com o objetivo de transformar verificações técnicas de segurança em um diagnóstico mais claro, útil e acessível.

Muitas informações importantes sobre a segurança de um domínio ficam distribuídas entre diferentes camadas, como:

- configuração DNS
- autenticação de e-mail
- certificados TLS/SSL
- segurança de transporte de e-mail
- ciclo de vida do domínio

Para quem não trabalha diariamente com infraestrutura ou segurança, interpretar esses dados pode ser difícil.  
A proposta deste projeto é permitir que o usuário informe um **domínio ou e-mail** e receba uma análise que mostre de forma simples:

- o que está configurado corretamente
- o que está ausente
- o que representa risco
- o que deve ser corrigido primeiro

Além de resolver um problema real, este projeto também está sendo desenvolvido como forma de aprofundar conhecimentos em:

- segurança da informação
- redes e DNS
- autenticação de e-mail
- TLS/SSL
- desenvolvimento backend com Python
- arquitetura de sistemas
- construção de produtos com foco em clareza técnica

---

## Funcionalidades já implementadas

### Arquitetura e base do sistema
- Estrutura em camadas (`api`, `core`, `schemas`, `services`, `utils`, `db`)
- Aplicação FastAPI com rotas web e API
- Interface HTML com Jinja2
- Testes automatizados iniciais com Pytest
- Base do projeto organizada para crescimento futuro

### Entrada e normalização
- Suporte para entrada de domínio ou e-mail
- Extração e normalização do domínio analisável
- Tratamento básico de entradas inválidas

### Análise de domínio e autenticação de e-mail
- Consulta DNS
- Verificação de registros MX
- Verificação de SPF
- Verificação de DMARC
- Estrutura com abordagem honesta para DKIM

### Inteligência do diagnóstico
- Motor de score com categorias ponderadas
- Classificação de severidade
- Findings estruturados
- Recomendações priorizadas

### TLS / SSL
- Verificação de TLS/SSL do website
- Leitura de certificado apresentado no site
- Identificação de emissor e validade do certificado
- Tentativa de análise de segurança de transporte de e-mail via MX
- Exibição condicional da seção de segurança de e-mail apenas quando houver dados úteis reais

### Registro do domínio
- Consulta de informações de registro do domínio quando disponíveis
- Data de criação
- Data de expiração
- Prazo restante para expiração
- Status e registrador quando disponíveis

### Interface
- Página inicial com formulário de análise
- Página de resultado funcional
- Exibição de score e severidade
- Exibição de findings e recomendações
- Layout inicial voltado para leitura clara do diagnóstico

---

## Capacidades atuais

Atualmente o sistema já consegue analisar, quando as informações estão disponíveis:

- DNS
- MX
- SPF
- DKIM *(com limitações conhecidas e abordagem honesta)*
- DMARC
- TLS/SSL do website
- segurança de transporte de e-mail
- dados de registro do domínio
- score de segurança
- severidade
- findings
- recomendações priorizadas

---

## Limitação importante sobre DKIM

DKIM não pode ser confirmado de forma totalmente confiável apenas com o domínio informado em todos os cenários.

Por isso, o projeto adota uma abordagem honesta:

- usar heurísticas quando o selector não for conhecido
- evitar afirmar ausência com falsa certeza
- manter a estrutura pronta para futura validação mais confiável via headers reais de e-mail

---

## Stack utilizada

- **Python**
- **FastAPI**
- **Pydantic v2**
- **dnspython**
- **SQLAlchemy**
- **Jinja2**
- **SQLite**
- **Pytest**

---

## Executando localmente

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .[dev]
uvicorn app.main:app --reload
