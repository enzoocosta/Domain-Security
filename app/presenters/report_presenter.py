from datetime import UTC, datetime

from app.presenters.ui_formatters import (
    alignment_label,
    category_label,
    check_status_badge,
    compact_fields,
    compact_list_blocks,
    confidence_label,
    dkim_status_badge,
    dmarc_strength_label,
    expiry_status_badge,
    field_value,
    finding_severity_badge,
    format_datetime,
    humanize_token,
    make_field,
    make_list_block,
    overall_severity_badge,
    recommendation_priority_badge,
    spf_posture_label,
    yes_no,
)
from app.schemas.analysis import AnalysisResponse, EmailTLSMXResult, Finding, Recommendation

_FINDING_ORDER = {
    "critico": 0,
    "alto": 1,
    "medio": 2,
    "baixo": 3,
}

_RECOMMENDATION_ORDER = {
    "alta": 0,
    "media": 1,
    "baixa": 2,
}


class ReportPresenter:
    def present(
        self,
        result: AnalysisResponse,
        *,
        submitted_target: str,
        analyzed_at: datetime | None = None,
    ) -> dict:
        analysis_timestamp = analyzed_at or datetime.now(tz=UTC)
        return {
            "executive": self._build_executive(result, submitted_target=submitted_target, analyzed_at=analysis_timestamp),
            "score_breakdown": self._build_score_breakdown(result),
            "changes": self._build_changes(result),
            "findings": self._build_findings(result.findings),
            "recommendations": self._build_recommendations(result.recommendations),
            "technical_sections": [
                self._build_email_authentication(result),
                self._build_email_policy_section(result),
                self._build_dns_mx_section(result),
                self._build_ip_intelligence_section(result),
                self._build_website_tls_section(result),
                self._build_mail_transport_section(result),
                self._build_domain_registration_section(result),
                self._build_technical_notes_section(result),
            ],
        }

    def _build_executive(
        self,
        result: AnalysisResponse,
        *,
        submitted_target: str,
        analyzed_at: datetime,
    ) -> dict:
        severity = overall_severity_badge(result.severity)
        return {
            "domain": result.normalized.analysis_domain,
            "input": result.normalized.original or submitted_target,
            "target_type": "Endereco de e-mail" if result.normalized.target_type == "email" else "Dominio",
            "summary": result.summary,
            "score": result.score,
            "score_caption": self._score_caption(result.score),
            "severity": severity,
            "status_text": self._executive_status_text(result.score, result.severity),
            "analyzed_at": format_datetime(analyzed_at),
            "actions": [
                {"href": "/", "label": "Nova analise", "style": "primary"},
                {
                    "href": f"/history/{result.normalized.analysis_domain}",
                    "label": "Ver historico",
                    "style": "secondary",
                },
                {
                    "href": f"/reports/{result.normalized.analysis_domain}.pdf",
                    "label": "Exportar PDF",
                    "style": "secondary",
                },
            ],
        }

    def _build_score_breakdown(self, result: AnalysisResponse) -> list[dict[str, str]]:
        breakdown = [
            ("DNS", result.score_breakdown.dns_score),
            ("MX", result.score_breakdown.mx_score),
            ("SPF", result.score_breakdown.spf_score),
            ("DKIM", result.score_breakdown.dkim_score),
            ("DMARC", result.score_breakdown.dmarc_score),
            ("Consistencia", result.score_breakdown.consistency_score),
        ]
        return [
            {
                "label": label,
                "value": f"{score}/100",
                "tone": self._score_tone(score),
                "detail": self._score_caption(score),
            }
            for label, score in breakdown
        ]

    def _build_changes(self, result: AnalysisResponse) -> dict:
        metrics = []
        changes = result.changes
        if changes.has_previous_snapshot:
            metrics = compact_fields(
                [
                    make_field("Score anterior", changes.previous_score, skip_if_empty=False),
                    make_field("Score atual", changes.current_score, tone=self._score_tone(changes.current_score), skip_if_empty=False),
                    make_field("Variacao", self._score_delta_label(changes.score_delta), tone=self._delta_tone(changes.score_delta), skip_if_empty=False),
                    make_field("Severity anterior", changes.previous_severity),
                    make_field("Severity atual", changes.current_severity),
                    make_field("Ultimo snapshot", changes.previous_snapshot_created_at),
                ]
            )

        return {
            "message": changes.message,
            "metrics": metrics,
            "changed_checks": [
                {
                    "label": item.label,
                    "previous": field_value(item.previous),
                    "current": field_value(item.current),
                }
                for item in changes.changed_checks
            ],
            "added_findings": list(changes.added_findings),
            "removed_findings": list(changes.removed_findings),
        }

    def _build_findings(self, findings: list[Finding]) -> list[dict]:
        ordered = sorted(
            findings,
            key=lambda item: (_FINDING_ORDER.get(item.severity, 99), item.title.lower()),
        )
        return [
            {
                "title": item.title,
                "detail": item.detail,
                "category": category_label(item.category),
                "severity": finding_severity_badge(item.severity),
            }
            for item in ordered
        ]

    def _build_recommendations(self, recommendations: list[Recommendation]) -> list[dict]:
        ordered = sorted(
            recommendations,
            key=lambda item: (_RECOMMENDATION_ORDER.get(item.priority, 99), item.title.lower()),
        )
        return [
            {
                "title": item.title,
                "action": item.action,
                "rationale": item.rationale,
                "category": category_label(item.category),
                "priority": recommendation_priority_badge(item.priority),
            }
            for item in ordered
        ]

    def _build_email_authentication(self, result: AnalysisResponse) -> dict:
        spf_card = {
            "title": "SPF",
            "summary": result.checks.spf.message,
            "badge": check_status_badge(result.checks.spf.status),
            "fields": compact_fields(
                [
                    make_field("Mecanismo final", result.checks.spf.final_all or "Nao identificado"),
                    make_field("Postura", spf_posture_label(result.checks.spf.posture)),
                    make_field("Consultas SPF", self._lookup_status_label(result.checks.spf.lookup_count_status)),
                    make_field("Total de lookups", result.checks.spf.lookup_count),
                    make_field("Void lookups", result.checks.spf.void_lookup_count),
                    make_field("Limite excedido", yes_no(result.checks.spf.lookup_limit_exceeded), skip_if_empty=not result.checks.spf.lookup_limit_exceeded),
                ]
            ),
            "lists": compact_list_blocks(
                [
                    make_list_block("Registros SPF", result.checks.spf.records),
                    make_list_block("Cadeia de lookups", result.checks.spf.lookup_chain),
                    make_list_block("Riscos observados", result.checks.spf.risks),
                ]
            ),
            "note": None,
        }

        dkim_note = result.checks.dkim.confidence_note.strip()
        if "headers reais" not in dkim_note.lower():
            dkim_note = (
                f"{dkim_note} A validacao confiavel pode depender de headers reais de e-mail."
            )
        dkim_card = {
            "title": "DKIM",
            "summary": result.checks.dkim.message,
            "badge": dkim_status_badge(result.checks.dkim.status),
            "fields": compact_fields(
                [
                    make_field("Seletores com registro", len(result.checks.dkim.selectors_with_records), skip_if_empty=False),
                    make_field("Seletores verificados", len(result.checks.dkim.checked_selectors), skip_if_empty=False),
                ]
            ),
            "lists": compact_list_blocks(
                [
                    make_list_block("Seletores com registros", result.checks.dkim.selectors_with_records),
                    make_list_block("Seletores verificados", result.checks.dkim.checked_selectors),
                ]
            ),
            "note": dkim_note,
        }

        dmarc_reports = [f"rua: {item}" for item in result.checks.dmarc.rua] + [
            f"ruf: {item}" for item in result.checks.dmarc.ruf
        ]
        dmarc_card = {
            "title": "DMARC",
            "summary": result.checks.dmarc.message,
            "badge": check_status_badge(result.checks.dmarc.status),
            "fields": compact_fields(
                [
                    make_field("Politica", result.checks.dmarc.policy or "Ausente"),
                    make_field("Forca", dmarc_strength_label(result.checks.dmarc.policy_strength)),
                    make_field("pct", result.checks.dmarc.pct),
                    make_field("adkim", alignment_label(result.checks.dmarc.adkim)),
                    make_field("aspf", alignment_label(result.checks.dmarc.aspf)),
                ]
            ),
            "lists": compact_list_blocks(
                [
                    make_list_block("Registros DMARC", result.checks.dmarc.records),
                    make_list_block("Destinos de relatorio", dmarc_reports),
                    make_list_block("Riscos observados", result.checks.dmarc.risks),
                ]
            ),
            "note": None,
        }

        return {
            "id": "email-authentication",
            "title": "Email Authentication",
            "description": "SPF, DKIM e DMARC apresentados com estados honestos e contexto curto para priorizacao.",
            "cards": [spf_card, dkim_card, dmarc_card],
            "empty_text": "",
        }

    def _build_dns_mx_section(self, result: AnalysisResponse) -> dict:
        mx_fields = compact_fields(
            [
                make_field("DNS score", f"{result.score_breakdown.dns_score}/100", tone=self._score_tone(result.score_breakdown.dns_score), skip_if_empty=False),
                make_field("MX score", f"{result.score_breakdown.mx_score}/100", tone=self._score_tone(result.score_breakdown.mx_score), skip_if_empty=False),
                make_field("Aceita e-mail", yes_no(result.checks.mx.accepts_mail), skip_if_empty=result.checks.mx.accepts_mail is None),
                make_field("Null MX", yes_no(result.checks.mx.is_null_mx), skip_if_empty=not result.checks.mx.is_null_mx),
            ]
        )
        mx_records = [f"{record.preference} {record.exchange}" for record in result.checks.mx.records]
        return {
            "id": "dns-mx",
            "title": "DNS & MX",
            "description": "Postura basica de roteamento de e-mail e presenca de registros MX visiveis na consulta.",
            "cards": [
                {
                    "title": "MX",
                    "summary": result.checks.mx.message,
                    "badge": check_status_badge(result.checks.mx.status),
                    "fields": mx_fields,
                    "lists": compact_list_blocks([make_list_block("Registros MX", mx_records)]),
                    "note": result.checks.mx.lookup_error,
                }
            ],
            "empty_text": "",
        }

    def _build_email_policy_section(self, result: AnalysisResponse) -> dict:
        mta_sts = result.email_policies.mta_sts
        tls_rpt = result.email_policies.tls_rpt
        bimi = result.email_policies.bimi
        dnssec = result.email_policies.dnssec
        return {
            "id": "email-policies",
            "title": "Mail Transport Policies",
            "description": "Politicas complementares de transporte e readiness de marca, com separacao clara entre fato, inferencia e indisponibilidade.",
            "cards": [
                {
                    "title": "MTA-STS",
                    "summary": mta_sts.message,
                    "badge": check_status_badge(mta_sts.status),
                    "fields": compact_fields(
                        [
                            make_field("Modo", mta_sts.mode),
                            make_field("Policy ID", mta_sts.policy_id),
                            make_field("Max age", mta_sts.max_age),
                            make_field("Policy URL", mta_sts.policy_url),
                        ]
                    ),
                    "lists": compact_list_blocks(
                        [
                            make_list_block("MX patterns", mta_sts.mx_patterns),
                            make_list_block("Warnings", mta_sts.warnings),
                            make_list_block("Recomendacoes", mta_sts.recommendations),
                        ]
                    ),
                    "note": mta_sts.fetch_error or mta_sts.lookup_error,
                },
                {
                    "title": "SMTP TLS Reporting",
                    "summary": tls_rpt.message,
                    "badge": check_status_badge(tls_rpt.status),
                    "fields": compact_fields(
                        [
                            make_field("Registro efetivo", tls_rpt.effective_record),
                        ]
                    ),
                    "lists": compact_list_blocks(
                        [
                            make_list_block("Destinos rua", tls_rpt.rua),
                            make_list_block("Warnings", tls_rpt.warnings),
                            make_list_block("Recomendacoes", tls_rpt.recommendations),
                        ]
                    ),
                    "note": tls_rpt.lookup_error,
                },
                {
                    "title": "BIMI readiness",
                    "summary": bimi.message,
                    "badge": check_status_badge(bimi.status),
                    "fields": compact_fields(
                        [
                            make_field("Readiness", humanize_token(bimi.readiness)),
                            make_field("Location", bimi.location),
                            make_field("Authority", bimi.authority),
                        ]
                    ),
                    "lists": compact_list_blocks(
                        [
                            make_list_block("Warnings", bimi.warnings),
                            make_list_block("Recomendacoes", bimi.recommendations),
                        ]
                    ),
                    "note": bimi.dmarc_dependency or bimi.lookup_error,
                },
                {
                    "title": "DNSSEC",
                    "summary": dnssec.message,
                    "badge": {"value": dnssec.status, "label": humanize_token(dnssec.status), "tone": "neutral"},
                    "fields": [],
                    "lists": compact_list_blocks([make_list_block("Notas", dnssec.notes)]),
                    "note": None,
                },
            ],
            "empty_text": "",
        }

    def _build_website_tls_section(self, result: AnalysisResponse) -> dict:
        badge = self._tls_badge(result.website_tls.ssl_active, result.website_tls.certificate_valid)
        note_parts = []
        if result.website_tls.provider_guess:
            note_parts.append(
                "Provider guess e apenas uma inferencia com base na resposta observada; nao identifica com certeza a hospedagem real."
            )
        if result.website_tls.error:
            note_parts.append(f"Erro tecnico: {result.website_tls.error}")
        return {
            "id": "website-tls",
            "title": "Website TLS/SSL",
            "description": "Configuracao HTTPS observada no website, com emissor real do certificado e inferencias separadas do fato verificado.",
            "cards": [
                {
                    "title": "TLS do website",
                    "summary": result.website_tls.message,
                    "badge": badge,
                    "fields": compact_fields(
                        [
                            make_field("TLS ativo", result.website_tls.ssl_active, skip_if_empty=False),
                            make_field("Certificado valido", result.website_tls.certificate_valid),
                            make_field("Versao TLS", result.website_tls.tls_version),
                            make_field("Status do certificado", expiry_status_badge(result.website_tls.expiry_status)["label"]),
                            make_field("Dias para expirar", result.website_tls.days_to_expire),
                            make_field("Issuer", result.website_tls.issuer),
                            make_field("Subject", result.website_tls.subject),
                            make_field("Not before", result.website_tls.not_before),
                            make_field("Not after", result.website_tls.not_after),
                            make_field("Provider guess", result.website_tls.provider_guess),
                            make_field("Confianca", confidence_label(result.website_tls.confidence)),
                        ]
                    ),
                    "lists": compact_list_blocks([make_list_block("SAN", result.website_tls.san)]),
                    "note": " ".join(note_parts).strip() or None,
                }
            ],
            "empty_text": "",
        }

    def _build_ip_intelligence_section(self, result: AnalysisResponse) -> dict:
        resolved_labels = [
            f"{item.ip} ({item.version.upper()} / {item.source_record_type} / {'publico' if item.is_public else 'nao publico'})"
            for item in result.ip_intelligence.resolved_ips
        ]
        note_parts = list(result.ip_intelligence.notes)
        if result.ip_intelligence.reputation_summary:
            note_parts.append(result.ip_intelligence.reputation_summary)
        if result.ip_intelligence.confidence_note:
            note_parts.append(result.ip_intelligence.confidence_note)
        return {
            "id": "ip-intelligence",
            "title": "IP Intelligence",
            "description": "Contexto tecnico e geografico aproximado do IP observado para o website, sem assumir que ele representa toda a infraestrutura real.",
            "cards": [
                {
                    "title": "IP resolvido para o website",
                    "summary": result.ip_intelligence.message,
                    "badge": self._ip_badge(result.ip_intelligence.has_public_ip),
                    "fields": compact_fields(
                        [
                            make_field("IP principal", result.ip_intelligence.primary_ip),
                            make_field("Versao", result.ip_intelligence.ip_version),
                            make_field("IP publico", yes_no(result.ip_intelligence.is_public)),
                            make_field("Reverse DNS", result.ip_intelligence.reverse_dns),
                            make_field("ASN", result.ip_intelligence.asn),
                            make_field("ASN org", result.ip_intelligence.asn_org),
                            make_field("ISP", result.ip_intelligence.isp),
                            make_field("Organizacao", result.ip_intelligence.organization),
                            make_field("Provider guess", result.ip_intelligence.provider_guess),
                            make_field("Pais", result.ip_intelligence.country),
                            make_field("Regiao", result.ip_intelligence.region),
                            make_field("Cidade", result.ip_intelligence.city),
                            make_field("Timezone", result.ip_intelligence.timezone),
                            make_field("Proxy ou hosting guess", yes_no(result.ip_intelligence.is_proxy_or_hosting_guess)),
                            make_field("Fonte", result.ip_intelligence.source),
                            make_field("Confianca", confidence_label(result.ip_intelligence.confidence)),
                        ]
                    ),
                    "lists": compact_list_blocks(
                        [
                            make_list_block("IPs resolvidos", resolved_labels),
                            make_list_block("Flags de anonimidade", result.ip_intelligence.anonymous_ip_flags),
                            make_list_block("Tags de reputacao", result.ip_intelligence.reputation_tags),
                        ]
                    ),
                    "note": " ".join(note_parts).strip() or None,
                }
            ],
            "empty_text": "",
        }

    def _build_mail_transport_section(self, result: AnalysisResponse) -> dict:
        if not result.email_tls.has_email_tls_data:
            return {
                "id": "mail-transport",
                "title": "Mail Transport Security",
                "description": "Tentativa de STARTTLS observada nos MX do dominio quando ha dados uteis para exibir.",
                "cards": [],
                "empty_text": (
                    f"Nao foi possivel obter informacoes de TLS/SSL dos registros MX do dominio "
                    f"{result.normalized.analysis_domain}."
                ),
            }

        cards = [self._build_mail_transport_card(mx_result) for mx_result in result.email_tls.mx_results if mx_result.has_tls_data]
        return {
            "id": "mail-transport",
            "title": "Mail Transport Security",
            "description": (
                "Tentativa de TLS em e-mail com foco no servidor MX observado. "
                f"{result.email_tls.note}"
            ),
            "cards": cards,
            "empty_text": "",
        }

    def _build_mail_transport_card(self, mx_result: EmailTLSMXResult) -> dict:
        note_parts = []
        if mx_result.error:
            note_parts.append(f"Erro tecnico: {mx_result.error}")
        badge = self._mail_tls_badge(mx_result.starttls_supported, mx_result.certificate_valid)
        return {
            "title": mx_result.host,
            "summary": f"Seguranca de transporte de e-mail observada na porta {mx_result.port}.",
            "badge": badge,
            "fields": compact_fields(
                [
                    make_field("Porta", mx_result.port, skip_if_empty=False),
                    make_field("STARTTLS", mx_result.starttls_supported),
                    make_field("Certificado valido", mx_result.certificate_valid),
                    make_field("Hostname confere", mx_result.hostname_match),
                    make_field("Versao TLS", mx_result.tls_version),
                    make_field("Status do certificado", expiry_status_badge(mx_result.expiry_status)["label"]),
                    make_field("Dias para expirar", mx_result.days_to_expire),
                    make_field("Issuer", mx_result.issuer),
                    make_field("Subject", mx_result.subject),
                    make_field("Not before", mx_result.not_before),
                    make_field("Not after", mx_result.not_after),
                ]
            ),
            "lists": [],
            "note": " ".join(note_parts).strip() or None,
        }

    def _build_domain_registration_section(self, result: AnalysisResponse) -> dict:
        note_parts = [
            "Criacao, expiracao, registrador e status podem variar conforme TLD e disponibilidade RDAP."
        ]
        if result.domain_registration.error:
            note_parts.append(f"Erro tecnico: {result.domain_registration.error}")
        return {
            "id": "domain-registration",
            "title": "Domain Registration",
            "description": "Dados de registro exibidos apenas quando a origem retorna informacao real e util.",
            "cards": [
                {
                    "title": "Registro do dominio",
                    "summary": result.domain_registration.message,
                    "badge": self._registration_badge(result.domain_registration.rdap_available),
                    "fields": compact_fields(
                        [
                            make_field("Fonte", result.domain_registration.source),
                            make_field("Registrar", result.domain_registration.registrar),
                            make_field("Criado em", result.domain_registration.created_at),
                            make_field("Expira em", result.domain_registration.expires_at),
                            make_field("Status de expiracao", expiry_status_badge(result.domain_registration.expiry_status)["label"]),
                            make_field("Dias para expirar", result.domain_registration.days_to_expire),
                        ]
                    ),
                    "lists": compact_list_blocks(
                        [make_list_block("Status do registro", result.domain_registration.status)]
                    ),
                    "note": " ".join(note_parts).strip(),
                }
            ],
            "empty_text": "",
        }

    def _build_technical_notes_section(self, result: AnalysisResponse) -> dict:
        notes = list(result.notes)
        if result.email_tls.probe_limited and result.email_tls.probe_note:
            notes.append(result.email_tls.probe_note)
        cards = []
        if notes:
            cards.append(
                {
                    "title": "Notas importantes",
                    "summary": "Limites tecnicos e observacoes relevantes para interpretar o resultado sem falsa certeza.",
                    "badge": None,
                    "fields": [],
                    "lists": compact_list_blocks([make_list_block("Technical Notes", notes)]),
                    "note": None,
                }
            )

        cards.append(
            {
                "title": "Performance da analise",
                "summary": "Sinais de execucao uteis para observabilidade da camada de apresentacao e da analise.",
                "badge": None,
                "fields": compact_fields(
                    [
                        make_field("Tempo total", f"{result.performance.total_ms} ms", skip_if_empty=False),
                        make_field("DNS", f"{result.performance.mx_ms} ms", skip_if_empty=False),
                        make_field("SPF", f"{result.performance.spf_ms} ms", skip_if_empty=False),
                        make_field("DKIM", f"{result.performance.dkim_ms} ms", skip_if_empty=False),
                        make_field("DMARC", f"{result.performance.dmarc_ms} ms", skip_if_empty=False),
                        make_field("TLS do website", f"{result.performance.website_tls_ms} ms", skip_if_empty=False),
                        make_field("TLS de e-mail", f"{result.performance.email_tls_ms} ms", skip_if_empty=False),
                        make_field("RDAP", f"{result.performance.rdap_ms} ms", skip_if_empty=False),
                        make_field("IP intelligence", f"{result.performance.ip_intelligence_ms} ms", skip_if_empty=False),
                        make_field("Cache hit", result.performance.cache_hit, skip_if_empty=False),
                    ]
                ),
                "lists": [],
                "note": None,
            }
        )
        return {
            "id": "technical-notes",
            "title": "Technical Notes",
            "description": "Observacoes tecnicas e sinais de execucao que ajudam a interpretar confianca e cobertura.",
            "cards": cards,
            "empty_text": "",
        }

    @staticmethod
    def _score_caption(score: int) -> str:
        if score >= 90:
            return "Postura muito forte"
        if score >= 75:
            return "Base de seguranca consistente"
        if score >= 60:
            return "Controles parciais"
        if score >= 40:
            return "Risco operacional relevante"
        return "Postura fragil"

    @staticmethod
    def _executive_status_text(score: int, severity: str) -> str:
        if severity in {"critico", "alto"}:
            return "O dominio exige atencao imediata nos controles principais."
        if score >= 80:
            return "A configuracao mostra boa maturidade, com ajustes finos possiveis."
        return "Ha oportunidades claras para endurecer a postura do dominio."

    @staticmethod
    def _score_tone(score: int) -> str:
        if score >= 85:
            return "success"
        if score >= 70:
            return "info"
        if score >= 50:
            return "warning"
        return "danger"

    @staticmethod
    def _lookup_status_label(value: str) -> str:
        labels = {
            "nao_implementado": "Nao implementado",
            "estimado": "Estimado",
            "exato": "Exato",
        }
        return labels.get(value, value.replace("_", " ").title())

    @staticmethod
    def _score_delta_label(delta: int | None) -> str:
        if delta is None:
            return "-"
        if delta > 0:
            return f"+{delta}"
        return str(delta)

    @staticmethod
    def _delta_tone(delta: int | None) -> str:
        if delta is None:
            return "neutral"
        if delta > 0:
            return "success"
        if delta < 0:
            return "danger"
        return "info"

    @staticmethod
    def _tls_badge(ssl_active: bool, certificate_valid: bool | None) -> dict[str, str]:
        if not ssl_active:
            return {"value": "ausente", "label": "Sem HTTPS", "tone": "danger"}
        if certificate_valid is False:
            return {"value": "invalido", "label": "Certificado invalido", "tone": "warning"}
        return {"value": "presente", "label": "HTTPS ativo", "tone": "success"}

    @staticmethod
    def _mail_tls_badge(starttls_supported: bool | None, certificate_valid: bool | None) -> dict[str, str]:
        if starttls_supported is False:
            return {"value": "ausente", "label": "Sem STARTTLS", "tone": "warning"}
        if certificate_valid is False:
            return {"value": "invalido", "label": "Certificado invalido", "tone": "warning"}
        return {"value": "presente", "label": "TLS observado", "tone": "success"}

    @staticmethod
    def _registration_badge(rdap_available: bool) -> dict[str, str]:
        if rdap_available:
            return {"value": "presente", "label": "RDAP disponivel", "tone": "success"}
        return {"value": "ausente", "label": "RDAP indisponivel", "tone": "warning"}

    @staticmethod
    def _ip_badge(has_public_ip: bool) -> dict[str, str]:
        if has_public_ip:
            return {"value": "presente", "label": "IP publico observado", "tone": "success"}
        return {"value": "desconhecido", "label": "Sem IP publico util", "tone": "warning"}
