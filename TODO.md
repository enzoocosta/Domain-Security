# Monitoring Plus — TODO

## 1. Fundação (db / config / exceções)
- [x] Adicionar exceção `SubscriptionRequiredError` em `app/core/exceptions.py`
- [x] Mapear 402 em `app/api/routes/error_utils.py`
- [x] Adicionar configurações Monitoring Plus em `app/core/config.py`
- [x] Criar modelos `PremiumSubscription`, `PremiumIngestToken`, `TrafficEvent`, `TrafficIncident` em `app/db/models.py`
- [x] Exportar novos modelos em `app/db/__init__.py`
- [x] Garantir `init_db` cria as tabelas novas (já feito por `create_all`)

## 2. Schemas
- [x] Criar `app/schemas/monitoring_plus.py` com inputs/outputs (subscription, ingestion, incident, dashboard)

## 3. Services (lógica de negócio)
- [x] `app/services/billing_service.py`
- [x] `app/services/premium_ingest_token_service.py`
- [x] `app/services/traffic_ingest_service.py`
- [x] `app/services/traffic_detection_service.py`
- [x] `app/services/monitoring_plus_alert_service.py`
- [x] `app/services/monitoring_plus_service.py`
- [x] `app/services/monitoring_plus_scheduler_service.py`

## 4. Rotas (sem regra)
- [ ] `app/api/routes/monitoring_plus_web.py`
- [ ] `app/api/routes/traffic_ingest.py`
- [ ] Registrar routers em `app/api/routes/__init__.py`

## 5. Apresentação / UI
- [ ] `app/presenters/monitoring_plus_offer_presenter.py`
- [ ] Editar `app/api/routes/web.py` para injetar oferta no resultado
- [ ] `app/templates/partials/premium_offer_card.html`
- [ ] Editar `app/templates/pages/result.html` para renderizar oferta
- [ ] `app/templates/pages/monitoring_plus_dashboard.html`
- [ ] `app/templates/pages/monitoring_plus_domain.html`
- [ ] Editar `app/templates/partials/header.html` (link Monitoring Plus)
- [ ] `app/static/css/pages/monitoring_plus.css` + ajuste em `components.css`
- [ ] Editar `app/templates/base.html` para incluir o CSS

## 6. Lifespan / app
- [ ] Editar `app/main.py` para iniciar scheduler do Monitoring Plus

## 7. Testes
- [ ] `tests/test_billing_service.py`
- [ ] `tests/test_traffic_ingest_service.py`
- [ ] `tests/test_traffic_detection_service.py`
- [ ] `tests/test_monitoring_plus_service.py`
- [ ] Ajustar `tests/conftest.py` (flag scheduler plus desativado)

## 8. Validação final
- [ ] Rodar pytest completo
- [ ] Subir aplicação e validar fluxo manual
