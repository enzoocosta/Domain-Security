from datetime import UTC, datetime

from app.presenters.ui_formatters import (
    alignment_label,
    category_label,
    check_status_badge,
    compact_fields,
    compact_list_blocks,
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
from app.schemas.analysis import (
    AnalysisResponse,
    EmailTLSMXResult,
    Finding,
    Recommendation,
)

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

_FROZEN_DOMAIN_STATUS_MARKERS = (
    "hold",
    "suspended",
    "frozen",
    "inactive",
    "serverhold",
    "clienthold",
)
_SUSPENDED_DOMAIN_STATUS_MARKERS = ("hold", "suspended", "serverhold", "clienthold")
_MONTH_ABBR = {
    1: "jan",
    2: "fev",
    3: "mar",
    4: "abr",
    5: "mai",
    6: "jun",
    7: "jul",
    8: "ago",
    9: "set",
    10: "out",
    11: "nov",
    12: "dez",
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
            "alert_banner": self._build_domain_status_banner(result),
            "executive": self._build_executive(
                result,
                submitted_target=submitted_target,
                analyzed_at=analysis_timestamp,
            ),
            "score_breakdown": self._build_score_breakdown(result),
            "changes": self._build_changes(result),
            "findings": self._build_findings(result.findings),
            "recommendations": self._build_recommendations(result.recommendations),
            "technical_sections": [
                self._build_email_authentication(result),
                self._build_dns_mx_section(result),
                self._build_ip_intelligence_section(result),
                self._build_website_tls_section(result),
                self._build_mail_transport_section(result),
                self._build_domain_registration_section(result),
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
            "target_type": "Endereco de e-mail"
            if result.normalized.target_type == "email"
            else "Dominio",
            "summary": result.summary,
            "score": result.score,
            "score_caption": self._score_caption(result.score),
            "severity": severity,
            "status_text": self._executive_status_text(result.score, result.severity),
            "analyzed_at": format_datetime(analyzed_at),
            "blocks": [
                self._build_executive_registration_block(result),
                self._build_executive_ip_block(result),
                self._build_executive_tls_block(result),
            ],
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

    def _build_executive_registration_block(self, result: AnalysisResponse) -> dict:
        registration = result.domain_registration
        status_alert = self._registration_status_alert(registration.status)
        return {
            "title": "WHOIS / Registro",
            "icon": "registration",
            "badge": status_alert["badge"]
            if status_alert
            else self._registration_badge(
                self._registration_available(registration),
                registration.expiry_status,
            ),
            "fields": compact_fields(
                [
                    make_field(
                        "Registrar",
                        registration.registrar,
                        skip_if_empty=False,
                        empty="Indisponivel",
                    ),
                    make_field(
                        "Criado em",
                        self._format_date_long(registration.created_at),
                        skip_if_empty=False,
                        empty="Indisponivel",
                    ),
                    make_field(
                        "Expira em",
                        self._format_date_long(registration.expires_at),
                        tone=self._expiry_tone(registration.expiry_status),
                        badge=self._expiry_inline_badge(
                            registration.days_to_expire, threshold=60
                        ),
                        skip_if_empty=False,
                        empty="Indisponivel",
                    ),
                ]
            ),
            "status_field": make_field(
                "Status",
                self._registration_status_value(registration.status),
                tone="danger" if status_alert else "neutral",
                skip_if_empty=False,
                empty="Indisponivel",
                classes="metric-card--status-alert" if status_alert else "",
                badge=status_alert["badge"] if status_alert else None,
            ),
            "note": None,
        }

    def _build_executive_ip_block(self, result: AnalysisResponse) -> dict:
        ip_info = result.ip_intelligence
        return {
            "title": "IP principal",
            "icon": "ip",
            "badge": self._ip_badge(ip_info.has_public_ip),
            "fields": compact_fields(
                [
                    make_field(
                        "IP principal",
                        ip_info.primary_ip,
                        skip_if_empty=False,
                        empty="Indisponivel",
                    ),
                    make_field(
                        "ASN",
                        self._join_non_empty(
                            ip_info.asn,
                            ip_info.asn_name or ip_info.asn_org,
                            separator=" · ",
                        ),
                        skip_if_empty=False,
                        empty="Indisponivel",
                    ),
                    make_field(
                        "Pais",
                        self._country_display(
                            ip_info.country_name,
                            ip_info.country_code,
                            fallback=ip_info.country,
                        ),
                        skip_if_empty=False,
                        empty="Indisponivel",
                    ),
                ]
            ),
            "note": self._ip_source_note(ip_info),
        }

    def _build_executive_tls_block(self, result: AnalysisResponse) -> dict:
        tls = result.website_tls
        return {
            "title": "SSL do website",
            "icon": "tls",
            "badge": self._tls_badge(
                tls.ssl_active, tls.certificate_valid, tls.expiry_status
            ),
            "fields": compact_fields(
                [
                    make_field(
                        "SSL ativo",
                        yes_no(tls.ssl_active),
                        skip_if_empty=False,
                        empty="Indisponivel",
                    ),
                    make_field(
                        "Emissor", tls.issuer, skip_if_empty=False, empty="Indisponivel"
                    ),
                    make_field(
                        "Expira em",
                        self._format_date_long(tls.not_after),
                        tone=self._expiry_tone(tls.expiry_status),
                        detail=self._days_remaining_label(tls.days_to_expire),
                        badge=self._expiry_inline_badge(
                            tls.days_to_expire, threshold=30
                        ),
                        skip_if_empty=False,
                        empty="Indisponivel",
                    ),
                    make_field(
                        "Versao TLS",
                        tls.tls_version,
                        skip_if_empty=False,
                        empty="Indisponivel",
                    ),
                ]
            ),
            "note": None,
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
                    make_field(
                        "Score anterior", changes.previous_score, skip_if_empty=False
                    ),
                    make_field(
                        "Score atual",
                        changes.current_score,
                        tone=self._score_tone(changes.current_score),
                        skip_if_empty=False,
                    ),
                    make_field(
                        "Variacao",
                        self._score_delta_label(changes.score_delta),
                        tone=self._delta_tone(changes.score_delta),
                        skip_if_empty=False,
                    ),
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
            key=lambda item: (
                _FINDING_ORDER.get(item.severity, 99),
                item.title.lower(),
            ),
        )
        return [
            {
                "title": item.title,
                "detail": item.detail,
                "category": category_label(item.category),
                "severity": self._finding_badge(item),
            }
            for item in ordered
        ]

    def _build_recommendations(
        self, recommendations: list[Recommendation]
    ) -> list[dict]:
        ordered = sorted(
            recommendations,
            key=lambda item: (
                _RECOMMENDATION_ORDER.get(item.priority, 99),
                item.title.lower(),
            ),
        )
        return [
            {
                "title": item.title,
                "description": item.action,
                "category": category_label(item.category),
                "priority": recommendation_priority_badge(item.priority),
                "priority_value": item.priority,
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
                    make_field(
                        "Mecanismo final",
                        result.checks.spf.final_all or "Nao identificado",
                    ),
                    make_field("Postura", spf_posture_label(result.checks.spf.posture)),
                    make_field(
                        "Consultas SPF",
                        self._lookup_status_label(
                            result.checks.spf.lookup_count_status
                        ),
                    ),
                    make_field("Total de lookups", result.checks.spf.lookup_count),
                    make_field("Void lookups", result.checks.spf.void_lookup_count),
                    make_field(
                        "Limite excedido",
                        yes_no(result.checks.spf.lookup_limit_exceeded),
                        skip_if_empty=not result.checks.spf.lookup_limit_exceeded,
                    ),
                ]
            ),
            "lists": compact_list_blocks(
                [
                    make_list_block("Registros SPF", result.checks.spf.records),
                    make_list_block(
                        "Cadeia de lookups", result.checks.spf.lookup_chain
                    ),
                    make_list_block("Riscos observados", result.checks.spf.risks),
                ]
            ),
            "note": None,
        }

        dkim_note = result.checks.dkim.confidence_note.strip()
        if "headers reais" not in dkim_note.lower():
            dkim_note = f"{dkim_note} A validacao confiavel pode depender de headers reais de e-mail."
        dkim_card = {
            "title": "DKIM",
            "summary": result.checks.dkim.message,
            "badge": dkim_status_badge(result.checks.dkim.status),
            "fields": compact_fields(
                [
                    make_field(
                        "Seletores com registro",
                        len(result.checks.dkim.selectors_with_records),
                        skip_if_empty=False,
                    ),
                    make_field(
                        "Seletores verificados",
                        len(result.checks.dkim.checked_selectors),
                        skip_if_empty=False,
                    ),
                ]
            ),
            "lists": compact_list_blocks(
                [
                    make_list_block(
                        "Seletores com registros",
                        result.checks.dkim.selectors_with_records,
                    ),
                    make_list_block(
                        "Seletores verificados", result.checks.dkim.checked_selectors
                    ),
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
                    make_field(
                        "Forca",
                        dmarc_strength_label(result.checks.dmarc.policy_strength),
                    ),
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
                make_field(
                    "DNS score",
                    f"{result.score_breakdown.dns_score}/100",
                    tone=self._score_tone(result.score_breakdown.dns_score),
                    skip_if_empty=False,
                ),
                make_field(
                    "MX score",
                    f"{result.score_breakdown.mx_score}/100",
                    tone=self._score_tone(result.score_breakdown.mx_score),
                    skip_if_empty=False,
                ),
                make_field(
                    "Aceita e-mail",
                    yes_no(result.checks.mx.accepts_mail),
                    skip_if_empty=result.checks.mx.accepts_mail is None,
                ),
                make_field(
                    "Null MX",
                    yes_no(result.checks.mx.is_null_mx),
                    skip_if_empty=not result.checks.mx.is_null_mx,
                ),
            ]
        )
        mx_records = [
            f"{record.preference} {record.exchange}"
            for record in result.checks.mx.records
        ]
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
                    "lists": compact_list_blocks(
                        [make_list_block("Registros MX", mx_records)]
                    ),
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
                    "badge": {
                        "value": dnssec.status,
                        "label": humanize_token(dnssec.status),
                        "tone": "neutral",
                    },
                    "fields": [],
                    "lists": compact_list_blocks(
                        [make_list_block("Notas", dnssec.notes)]
                    ),
                    "note": None,
                },
            ],
            "empty_text": "",
        }

    def _build_website_tls_section(self, result: AnalysisResponse) -> dict:
        status_badge = self._tls_certificate_status_badge(
            result.website_tls.expiry_status, result.website_tls.ssl_active
        )
        return {
            "id": "website-tls",
            "title": "Website TLS/SSL",
            "description": "Visao objetiva do certificado HTTPS observado no website.",
            "cards": [
                {
                    "title": "TLS do website",
                    "summary": "Estado atual da conexao segura do site.",
                    "badge": status_badge,
                    "fields": compact_fields(
                        [
                            make_field(
                                "TLS ativo",
                                yes_no(result.website_tls.ssl_active),
                                skip_if_empty=False,
                                empty="—",
                            ),
                            make_field(
                                "Versao TLS",
                                result.website_tls.tls_version,
                                skip_if_empty=False,
                                empty="—",
                            ),
                            make_field(
                                "Emissor",
                                result.website_tls.issuer,
                                skip_if_empty=False,
                                empty="—",
                            ),
                            make_field(
                                "Validade",
                                self._format_date_long(result.website_tls.not_after),
                                skip_if_empty=False,
                                empty="—",
                            ),
                            make_field(
                                "Dias restantes",
                                result.website_tls.days_to_expire,
                                skip_if_empty=False,
                                empty="—",
                            ),
                            make_field(
                                "Status",
                                status_badge["label"],
                                tone=status_badge["tone"],
                                skip_if_empty=False,
                                empty="—",
                                badge=status_badge,
                            ),
                        ]
                    ),
                    "lists": [],
                    "note": None,
                }
            ],
            "empty_text": "",
        }

    def _build_ip_intelligence_section(self, result: AnalysisResponse) -> dict:
        resolved_labels = []
        for item in result.ip_intelligence.resolved_ips:
            label = (
                f"{item.ip} · {item.source_record_type} · PTR {item.reverse_dns or '—'}"
            )
            resolved_labels.append(label)
        return {
            "id": "ip-intelligence",
            "title": "IP Intelligence",
            "description": "Contexto resumido do IP principal observado para o website.",
            "cards": [
                {
                    "title": "IP resolvido para o website",
                    "summary": self._ip_summary(result.ip_intelligence),
                    "badge": self._ip_badge(result.ip_intelligence.has_public_ip),
                    "fields": compact_fields(
                        [
                            make_field(
                                "IP principal",
                                result.ip_intelligence.primary_ip,
                                skip_if_empty=False,
                                empty="—",
                            ),
                            make_field(
                                "Versao",
                                result.ip_intelligence.ip_version,
                                skip_if_empty=False,
                                empty="—",
                            ),
                            make_field(
                                "ASN",
                                result.ip_intelligence.asn,
                                skip_if_empty=False,
                                empty="—",
                            ),
                            make_field(
                                "Nome do AS",
                                result.ip_intelligence.asn_name
                                or result.ip_intelligence.asn_org,
                                skip_if_empty=False,
                                empty="—",
                            ),
                            make_field(
                                "Organizacao",
                                result.ip_intelligence.organization,
                                skip_if_empty=False,
                                empty="—",
                            ),
                            make_field(
                                "Pais",
                                self._country_display(
                                    result.ip_intelligence.country_name,
                                    result.ip_intelligence.country_code,
                                    fallback=result.ip_intelligence.country,
                                ),
                                skip_if_empty=False,
                                empty="—",
                            ),
                            make_field(
                                "Cidade",
                                result.ip_intelligence.city,
                                skip_if_empty=False,
                                empty="—",
                            ),
                            make_field(
                                "ISP",
                                result.ip_intelligence.isp,
                                skip_if_empty=False,
                                empty="—",
                            ),
                            make_field(
                                "Reverse DNS",
                                result.ip_intelligence.reverse_dns,
                                skip_if_empty=False,
                                empty="—",
                            ),
                            make_field(
                                "Tipo de uso",
                                result.ip_intelligence.usage_type,
                                skip_if_empty=False,
                                empty="—",
                            ),
                        ]
                    ),
                    "lists": compact_list_blocks(
                        [
                            make_list_block("IPs resolvidos", resolved_labels),
                        ]
                    ),
                    "note": self._ip_source_note(result.ip_intelligence),
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

        cards = [
            self._build_mail_transport_card(mx_result)
            for mx_result in result.email_tls.mx_results
            if mx_result.has_tls_data
        ]
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
        badge = self._mail_tls_badge(
            mx_result.starttls_supported, mx_result.certificate_valid
        )
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
                    make_field(
                        "Status do certificado",
                        expiry_status_badge(mx_result.expiry_status)["label"],
                    ),
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
        if not self._registration_available(result.domain_registration):
            return {
                "id": "domain-registration",
                "title": "Domain Registration",
                "description": "Dados principais de WHOIS e expiracao do dominio.",
                "cards": [],
                "empty_text": "Dados de registro indisponiveis para este dominio.",
            }

        status_badge = self._registration_expiry_badge(
            result.domain_registration.expiry_status
        )
        return {
            "id": "domain-registration",
            "title": "Domain Registration",
            "description": "Dados principais de WHOIS e expiracao do dominio.",
            "cards": [
                {
                    "title": "Registro do dominio",
                    "summary": "Informacoes basicas do registro do dominio.",
                    "badge": status_badge,
                    "fields": compact_fields(
                        [
                            make_field(
                                "Registrar",
                                result.domain_registration.registrar,
                                skip_if_empty=False,
                                empty="—",
                            ),
                            make_field(
                                "Criado em",
                                self._format_date_long(
                                    result.domain_registration.created_at
                                ),
                                skip_if_empty=False,
                                empty="—",
                            ),
                            make_field(
                                "Expira em",
                                self._format_date_long(
                                    result.domain_registration.expires_at
                                ),
                                tone=self._expiry_tone(
                                    result.domain_registration.expiry_status
                                ),
                                skip_if_empty=False,
                                empty="—",
                            ),
                            make_field(
                                "Status de expiracao",
                                expiry_status_badge(
                                    result.domain_registration.expiry_status
                                )["label"],
                            ),
                            make_field(
                                "Status de expiracao",
                                status_badge["label"],
                                tone=status_badge["tone"],
                                skip_if_empty=False,
                                empty="—",
                                badge=status_badge,
                            ),
                        ]
                    ),
                    "lists": [],
                    "note": None,
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
                    "lists": compact_list_blocks(
                        [make_list_block("Technical Notes", notes)]
                    ),
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
                        make_field(
                            "Tempo total",
                            f"{result.performance.total_ms} ms",
                            skip_if_empty=False,
                        ),
                        make_field(
                            "DNS", f"{result.performance.mx_ms} ms", skip_if_empty=False
                        ),
                        make_field(
                            "SPF",
                            f"{result.performance.spf_ms} ms",
                            skip_if_empty=False,
                        ),
                        make_field(
                            "DKIM",
                            f"{result.performance.dkim_ms} ms",
                            skip_if_empty=False,
                        ),
                        make_field(
                            "DMARC",
                            f"{result.performance.dmarc_ms} ms",
                            skip_if_empty=False,
                        ),
                        make_field(
                            "TLS do website",
                            f"{result.performance.website_tls_ms} ms",
                            skip_if_empty=False,
                        ),
                        make_field(
                            "TLS de e-mail",
                            f"{result.performance.email_tls_ms} ms",
                            skip_if_empty=False,
                        ),
                        make_field(
                            "Registro do dominio",
                            f"{result.performance.domain_registration_ms or result.performance.rdap_ms} ms",
                            skip_if_empty=False,
                        ),
                        make_field(
                            "IP intelligence",
                            f"{result.performance.ip_intelligence_ms} ms",
                            skip_if_empty=False,
                        ),
                        make_field(
                            "Cache hit",
                            result.performance.cache_hit,
                            skip_if_empty=False,
                        ),
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

    def _build_executive_ip_block(self, result: AnalysisResponse) -> dict:
        ip_info = result.ip_intelligence
        return {
            "title": "IP principal",
            "icon": "ip",
            "badge": self._ip_badge(ip_info.has_public_ip),
            "fields": compact_fields(
                [
                    make_field(
                        "IP principal",
                        ip_info.primary_ip,
                        skip_if_empty=False,
                        empty="Indisponivel",
                    ),
                    make_field(
                        "ASN",
                        self._join_non_empty(
                            ip_info.asn,
                            ip_info.asn_name or ip_info.asn_org,
                            separator=" / ",
                        ),
                        skip_if_empty=False,
                        empty="Indisponivel",
                    ),
                    make_field(
                        "Pais",
                        self._country_display(
                            ip_info.country_name,
                            ip_info.country_code,
                            fallback=ip_info.country,
                        ),
                        skip_if_empty=False,
                        empty="Indisponivel",
                    ),
                ]
            ),
            "note": self._ip_source_note(ip_info),
        }

    def _build_website_tls_section(self, result: AnalysisResponse) -> dict:
        status_badge = self._tls_certificate_status_badge(
            result.website_tls.expiry_status, result.website_tls.ssl_active
        )
        return {
            "id": "website-tls",
            "title": "Website TLS/SSL",
            "description": "Visao objetiva do certificado HTTPS observado no website.",
            "cards": [
                {
                    "title": "TLS do website",
                    "summary": "Estado atual da conexao segura do site.",
                    "badge": status_badge,
                    "fields": compact_fields(
                        [
                            make_field(
                                "TLS ativo",
                                yes_no(result.website_tls.ssl_active),
                                skip_if_empty=False,
                                empty="-",
                            ),
                            make_field(
                                "Versao TLS",
                                result.website_tls.tls_version,
                                skip_if_empty=False,
                                empty="-",
                            ),
                            make_field(
                                "Emissor",
                                result.website_tls.issuer,
                                skip_if_empty=False,
                                empty="-",
                            ),
                            make_field(
                                "Validade",
                                self._format_date_long(result.website_tls.not_after),
                                skip_if_empty=False,
                                empty="-",
                            ),
                            make_field(
                                "Dias restantes",
                                result.website_tls.days_to_expire,
                                skip_if_empty=False,
                                empty="-",
                            ),
                            make_field(
                                "Status",
                                status_badge["label"],
                                tone=status_badge["tone"],
                                skip_if_empty=False,
                                empty="-",
                                badge=status_badge,
                            ),
                        ]
                    ),
                    "lists": [],
                    "note": None,
                }
            ],
            "empty_text": "",
        }

    def _build_ip_intelligence_section(self, result: AnalysisResponse) -> dict:
        resolved_labels = [
            f"{item.ip} | {item.source_record_type} | PTR {item.reverse_dns or '-'}"
            for item in result.ip_intelligence.resolved_ips
        ]
        return {
            "id": "ip-intelligence",
            "title": "IP Intelligence",
            "description": "Contexto resumido do IP principal observado para o website.",
            "cards": [
                {
                    "title": "IP resolvido para o website",
                    "summary": self._ip_summary(result.ip_intelligence),
                    "badge": self._ip_badge(result.ip_intelligence.has_public_ip),
                    "fields": compact_fields(
                        [
                            make_field(
                                "IP principal",
                                result.ip_intelligence.primary_ip,
                                skip_if_empty=False,
                                empty="-",
                            ),
                            make_field(
                                "Versao",
                                result.ip_intelligence.ip_version,
                                skip_if_empty=False,
                                empty="-",
                            ),
                            make_field(
                                "ASN",
                                result.ip_intelligence.asn,
                                skip_if_empty=False,
                                empty="-",
                            ),
                            make_field(
                                "Nome do AS",
                                result.ip_intelligence.asn_name
                                or result.ip_intelligence.asn_org,
                                skip_if_empty=False,
                                empty="-",
                            ),
                            make_field(
                                "Organizacao",
                                result.ip_intelligence.organization,
                                skip_if_empty=False,
                                empty="-",
                            ),
                            make_field(
                                "Pais",
                                self._country_display(
                                    result.ip_intelligence.country_name,
                                    result.ip_intelligence.country_code,
                                    fallback=result.ip_intelligence.country,
                                ),
                                skip_if_empty=False,
                                empty="-",
                            ),
                            make_field(
                                "Cidade",
                                result.ip_intelligence.city,
                                skip_if_empty=False,
                                empty="-",
                            ),
                            make_field(
                                "ISP",
                                result.ip_intelligence.isp,
                                skip_if_empty=False,
                                empty="-",
                            ),
                            make_field(
                                "Reverse DNS",
                                result.ip_intelligence.reverse_dns,
                                skip_if_empty=False,
                                empty="-",
                            ),
                            make_field(
                                "Tipo de uso",
                                result.ip_intelligence.usage_type,
                                skip_if_empty=False,
                                empty="-",
                            ),
                        ]
                    ),
                    "lists": compact_list_blocks(
                        [make_list_block("IPs resolvidos", resolved_labels)]
                    ),
                    "note": self._ip_source_note(result.ip_intelligence),
                }
            ],
            "empty_text": "",
        }

    def _build_domain_registration_section(self, result: AnalysisResponse) -> dict:
        if not self._registration_available(result.domain_registration):
            return {
                "id": "domain-registration",
                "title": "Domain Registration",
                "description": "Dados principais de WHOIS e expiracao do dominio.",
                "cards": [],
                "empty_text": "Dados de registro indisponiveis para este dominio.",
            }

        status_badge = self._registration_expiry_badge(
            result.domain_registration.expiry_status
        )
        return {
            "id": "domain-registration",
            "title": "Domain Registration",
            "description": "Dados principais de WHOIS e expiracao do dominio.",
            "cards": [
                {
                    "title": "Registro do dominio",
                    "summary": "Informacoes basicas do registro do dominio.",
                    "badge": status_badge,
                    "fields": compact_fields(
                        [
                            make_field(
                                "Registrar",
                                result.domain_registration.registrar,
                                skip_if_empty=False,
                                empty="-",
                            ),
                            make_field(
                                "Criado em",
                                self._format_date_long(
                                    result.domain_registration.created_at
                                ),
                                skip_if_empty=False,
                                empty="-",
                            ),
                            make_field(
                                "Expira em",
                                self._format_date_long(
                                    result.domain_registration.expires_at
                                ),
                                tone=self._expiry_tone(
                                    result.domain_registration.expiry_status
                                ),
                                skip_if_empty=False,
                                empty="-",
                            ),
                            make_field(
                                "Status de expiracao",
                                status_badge["label"],
                                tone=status_badge["tone"],
                                skip_if_empty=False,
                                empty="-",
                                badge=status_badge,
                            ),
                        ]
                    ),
                    "lists": [],
                    "note": None,
                }
            ],
            "empty_text": "",
        }

    @staticmethod
    def _format_date_only(value: datetime | None) -> str | None:
        if value is None:
            return None
        return ReportPresenter._format_date_long(value)

    @staticmethod
    def _format_date_long(value: datetime | None) -> str | None:
        if value is None:
            return None
        return f"{value.day:02d} {_MONTH_ABBR[value.month]} {value.year}"

    @staticmethod
    def _expiry_tone(expiry_status: str) -> str:
        if expiry_status == "expirado":
            return "danger"
        if expiry_status == "proximo_expiracao":
            return "warning"
        if expiry_status == "ok":
            return "success"
        return "neutral"

    @staticmethod
    def _expiry_detail(days_to_expire: int | None) -> str | None:
        if days_to_expire is None:
            return None
        if days_to_expire < 0:
            return f"Expirou ha {abs(days_to_expire)} dia(s)"
        return f"Expira em {days_to_expire} dia(s)"

    @staticmethod
    def _days_remaining_label(days_to_expire: int | None) -> str | None:
        if days_to_expire is None:
            return None
        if days_to_expire < 0:
            return f"Expirou ha {abs(days_to_expire)} dia(s)"
        return f"{days_to_expire} dia(s) restantes"

    @staticmethod
    def _registration_available(registration) -> bool:
        return bool(
            registration.available
            or registration.whois_available
            or registration.rdap_available
        )

    def _build_domain_status_banner(self, result: AnalysisResponse) -> dict | None:
        status_alert = self._registration_status_alert(
            result.domain_registration.status
        )
        if not status_alert:
            return None
        return {
            "title": "Dominio possivelmente congelado ou suspenso",
            "detail": (
                f"O status WHOIS indica restricao ativa: {status_alert['matched_status']}. "
                "Dominios neste estado podem parar de funcionar ou ja estar inacessiveis."
            ),
        }

    @staticmethod
    def _registration_status_alert(statuses: list[str]) -> dict[str, object] | None:
        for status in statuses:
            normalized = status.lower()
            if not any(
                marker in normalized for marker in _FROZEN_DOMAIN_STATUS_MARKERS
            ):
                continue
            label = (
                "SUSPENSO"
                if any(
                    marker in normalized for marker in _SUSPENDED_DOMAIN_STATUS_MARKERS
                )
                else "CONGELADO"
            )
            return {
                "matched_status": status,
                "badge": {"value": label.lower(), "label": label, "tone": "danger"},
            }
        return None

    @staticmethod
    def _registration_status_value(statuses: list[str]) -> str | None:
        if not statuses:
            return None
        return ", ".join(statuses)

    @staticmethod
    def _expiry_inline_badge(
        days_to_expire: int | None, *, threshold: int
    ) -> dict[str, str] | None:
        if days_to_expire is None:
            return None
        if days_to_expire < 0:
            return {"value": "expirado", "label": "Expirado", "tone": "danger"}
        if days_to_expire <= threshold:
            return {
                "value": "expira_em_breve",
                "label": f"Expira em {days_to_expire} dias",
                "tone": "warning",
            }
        return None

    def _registration_source_note(self, registration) -> str | None:
        parts = []
        if registration.source:
            parts.append(f"Fonte: {registration.source}.")
        if (
            registration.expiry_status == "expirado"
            and registration.days_to_expire is not None
        ):
            parts.append(
                f"Alerta: o dominio expirou ha {abs(registration.days_to_expire)} dia(s)."
            )
        elif (
            registration.expiry_status == "proximo_expiracao"
            and registration.days_to_expire is not None
        ):
            parts.append(
                f"Alerta: o dominio expira em {registration.days_to_expire} dia(s)."
            )
        elif not self._registration_available(registration):
            parts.append("Os dados de registro ficaram indisponiveis neste snapshot.")
        return " ".join(parts).strip() or None

    @staticmethod
    def _country_display(
        country_name: str | None,
        country_code: str | None,
        *,
        fallback: str | None = None,
    ) -> str | None:
        if country_name and country_code:
            return f"{country_name} - {country_code}"
        if country_name:
            return country_name
        if country_code:
            return country_code
        return fallback

    @staticmethod
    def _join_non_empty(*values: str | None, separator: str = " ") -> str | None:
        cleaned = [value for value in values if value]
        if not cleaned:
            return None
        return separator.join(cleaned)

    @staticmethod
    def _ip_source_note(ip_info) -> str | None:
        if not ip_info.source:
            return None
        if "ipwhois" in ip_info.source:
            return "Dados via RDAP/ipwhois"
        if ip_info.source.startswith("maxmind"):
            return "Dados via MaxMind"
        return None

    @staticmethod
    def _website_tls_note(website_tls) -> str | None:
        return None

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
    def _finding_badge(item: Finding) -> dict[str, str]:
        if item.severity == "baixo":
            return {"value": "ok", "label": "OK", "tone": "success"}
        return finding_severity_badge(item.severity)

    @staticmethod
    def _tls_badge(
        ssl_active: bool,
        certificate_valid: bool | None,
        expiry_status: str = "desconhecido",
    ) -> dict[str, str]:
        if not ssl_active:
            return {"value": "ausente", "label": "Sem HTTPS", "tone": "danger"}
        if expiry_status == "expirado":
            return {"value": "expirado", "label": "SSL expirado", "tone": "danger"}
        if certificate_valid is False:
            return {
                "value": "invalido",
                "label": "Certificado invalido",
                "tone": "warning",
            }
        if expiry_status == "proximo_expiracao":
            return {
                "value": "proximo_expiracao",
                "label": "Expira em breve",
                "tone": "warning",
            }
        return {"value": "presente", "label": "HTTPS ativo", "tone": "success"}

    @staticmethod
    def _tls_certificate_status_badge(
        expiry_status: str, ssl_active: bool
    ) -> dict[str, str]:
        if not ssl_active:
            return {"value": "ausente", "label": "Sem HTTPS", "tone": "danger"}
        if expiry_status == "expirado":
            return {"value": "expirado", "label": "Expirado", "tone": "danger"}
        if expiry_status == "proximo_expiracao":
            return {
                "value": "proximo_expiracao",
                "label": "Expirando",
                "tone": "warning",
            }
        if expiry_status == "ok":
            return {"value": "ok", "label": "Valido", "tone": "success"}
        return {"value": "desconhecido", "label": "Desconhecido", "tone": "neutral"}

    @staticmethod
    def _mail_tls_badge(
        starttls_supported: bool | None, certificate_valid: bool | None
    ) -> dict[str, str]:
        if starttls_supported is False:
            return {"value": "ausente", "label": "Sem STARTTLS", "tone": "warning"}
        if certificate_valid is False:
            return {
                "value": "invalido",
                "label": "Certificado invalido",
                "tone": "warning",
            }
        return {"value": "presente", "label": "TLS observado", "tone": "success"}

    @staticmethod
    def _registration_badge(available: bool, expiry_status: str) -> dict[str, str]:
        if expiry_status == "expirado":
            return {"value": "expirado", "label": "Expirado", "tone": "danger"}
        if expiry_status == "proximo_expiracao":
            return {
                "value": "proximo_expiracao",
                "label": "Expira em breve",
                "tone": "warning",
            }
        if available:
            return {
                "value": "presente",
                "label": "Registro consultado",
                "tone": "success",
            }
        return {"value": "ausente", "label": "Registro indisponivel", "tone": "warning"}

    @staticmethod
    def _registration_expiry_badge(expiry_status: str) -> dict[str, str]:
        if expiry_status == "expirado":
            return {"value": "expirado", "label": "Expirado", "tone": "danger"}
        if expiry_status == "proximo_expiracao":
            return {
                "value": "proximo_expiracao",
                "label": "Expirando",
                "tone": "warning",
            }
        if expiry_status == "ok":
            return {"value": "ok", "label": "OK", "tone": "success"}
        return {"value": "desconhecido", "label": "Desconhecido", "tone": "neutral"}

    @staticmethod
    def _ip_badge(has_public_ip: bool) -> dict[str, str]:
        if has_public_ip:
            return {
                "value": "presente",
                "label": "IP publico observado",
                "tone": "success",
            }
        return {
            "value": "desconhecido",
            "label": "Sem IP publico util",
            "tone": "warning",
        }

    @staticmethod
    def _ip_summary(ip_info) -> str:
        if ip_info.primary_ip:
            return "Contexto do IP principal observado para o website."
        if ip_info.resolved_ips:
            return "Os IPs resolvidos nao oferecem contexto publico suficiente."
        return "Nenhum IP foi resolvido para o website."
