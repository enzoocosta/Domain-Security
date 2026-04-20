from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.presenters.ui_formatters import (
    dmarc_strength_label,
    format_datetime,
    humanize_token,
    is_blank,
    spf_posture_label,
    yes_no,
)
from app.schemas.analysis import AnalysisResponse


class PDFReportPresenter:
    """Builds a print-oriented view model from the normalized analysis result."""

    def present(self, result: AnalysisResponse, *, exported_at: datetime | None = None) -> dict[str, Any]:
        rendered_at = exported_at or datetime.now(tz=UTC)
        return {
            "executive": self._build_executive(result, exported_at=rendered_at),
            "findings": [self._present_finding(item) for item in result.findings[:8]],
            "recommendations": [self._present_recommendation(item) for item in result.recommendations[:8]],
            "sections": self._build_sections(result),
            "notes": list(result.notes),
        }

    def _build_executive(self, result: AnalysisResponse, *, exported_at: datetime) -> dict[str, Any]:
        return {
            "domain": result.normalized.analysis_domain,
            "target_type": humanize_token(result.normalized.target_type),
            "analyzed_at": format_datetime(exported_at),
            "score": result.score,
            "severity": humanize_token(result.severity),
            "summary": result.summary,
            "overview": self._build_overview(result),
        }

    def _build_sections(self, result: AnalysisResponse) -> list[dict[str, Any]]:
        sections = [
            self._build_email_auth_section(result),
            self._build_email_policy_section(result),
            self._build_transport_section(result),
            self._build_registration_section(result),
            self._build_ip_section(result),
            self._build_changes_section(result),
        ]
        return [section for section in sections if section is not None]

    def _build_email_auth_section(self, result: AnalysisResponse) -> dict[str, Any]:
        report_destinations = [f"rua: {item}" for item in result.checks.dmarc.rua] + [
            f"ruf: {item}" for item in result.checks.dmarc.ruf
        ]
        return {
            "title": "DNS, MX e Politicas de E-mail",
            "summary": "Fatos observados nas publicacoes DNS relacionadas a roteamento e autenticacao de e-mail.",
            "items": self._compact(
                [
                    self._item("MX", result.checks.mx.message),
                    self._item("SPF", result.checks.spf.message),
                    self._item("Postura SPF", spf_posture_label(result.checks.spf.posture)),
                    self._item("Lookups SPF", result.checks.spf.lookup_count, kind="confirmed"),
                    self._item("Void lookups SPF", result.checks.spf.void_lookup_count, kind="confirmed"),
                    self._item("Status DKIM", result.checks.dkim.message),
                    self._item("DMARC", result.checks.dmarc.message),
                    self._item("Forca DMARC", dmarc_strength_label(result.checks.dmarc.policy_strength)),
                    self._item("Politica DMARC", result.checks.dmarc.policy),
                ]
            ),
            "lists": self._compact(
                [
                    self._list("Registros MX", [f"{item.preference} {item.exchange}" for item in result.checks.mx.records]),
                    self._list("Registros SPF", result.checks.spf.records),
                    self._list("Cadeia de lookups SPF", result.checks.spf.lookup_chain),
                    self._list("Riscos SPF", result.checks.spf.risks),
                    self._list("Seletores DKIM observados", result.checks.dkim.selectors_with_records),
                    self._list("Registros DMARC", result.checks.dmarc.records),
                    self._list("Destinos de relatorio DMARC", report_destinations),
                    self._list("Riscos DMARC", result.checks.dmarc.risks),
                ]
            ),
            "note": result.checks.dkim.confidence_note,
        }

    def _build_transport_section(self, result: AnalysisResponse) -> dict[str, Any]:
        mx_tls_lines = []
        for item in result.email_tls.mx_results:
            if not item.has_tls_data:
                continue
            details = [
                f"porta {item.port}",
                f"STARTTLS: {yes_no(item.starttls_supported)}",
            ]
            if item.certificate_valid is not None:
                details.append(f"certificado valido: {yes_no(item.certificate_valid)}")
            if item.tls_version:
                details.append(f"TLS: {item.tls_version}")
            mx_tls_lines.append(f"{item.host} ({'; '.join(details)})")

        return {
            "title": "Seguranca de Transporte",
            "summary": "Website TLS e, quando util, o comportamento TLS observado nos servidores MX.",
            "items": self._compact(
                [
                    self._item("TLS do website", result.website_tls.message),
                    self._item("Certificado do website valido", yes_no(result.website_tls.certificate_valid)),
                    self._item("Versao TLS do website", result.website_tls.tls_version),
                    self._item("Issuer do website", result.website_tls.issuer),
                    self._item("Provider guess do website", result.website_tls.provider_guess, kind="inference"),
                    self._item("TLS de e-mail", result.email_tls.message),
                ]
            ),
            "lists": self._compact(
                [
                    self._list("SAN do certificado do website", result.website_tls.san),
                    self._list("MX com TLS observado", mx_tls_lines),
                ]
            ),
            "note": result.email_tls.note if result.email_tls.has_email_tls_data else None,
        }

    def _build_email_policy_section(self, result: AnalysisResponse) -> dict[str, Any]:
        mta_sts = result.email_policies.mta_sts
        tls_rpt = result.email_policies.tls_rpt
        bimi = result.email_policies.bimi
        dnssec = result.email_policies.dnssec
        return {
            "title": "Politicas Complementares de E-mail",
            "summary": "MTA-STS, TLS-RPT, BIMI e o estado atual da base para DNSSEC.",
            "items": self._compact(
                [
                    self._item("MTA-STS", mta_sts.message),
                    self._item("Modo MTA-STS", mta_sts.mode),
                    self._item("SMTP TLS Reporting", tls_rpt.message),
                    self._item("Destinos TLS-RPT", ", ".join(tls_rpt.rua) if tls_rpt.rua else None),
                    self._item("BIMI", bimi.message),
                    self._item("BIMI readiness", humanize_token(bimi.readiness), kind="inference"),
                    self._item("DNSSEC", dnssec.message),
                ]
            ),
            "lists": self._compact(
                [
                    self._list("MTA-STS warnings", mta_sts.warnings),
                    self._list("MTA-STS recomendacoes", mta_sts.recommendations),
                    self._list("TLS-RPT warnings", tls_rpt.warnings),
                    self._list("TLS-RPT recomendacoes", tls_rpt.recommendations),
                    self._list("BIMI warnings", bimi.warnings),
                    self._list("BIMI recomendacoes", bimi.recommendations),
                    self._list("DNSSEC notas", dnssec.notes),
                ]
            ),
            "note": self._join_notes(
                [mta_sts.fetch_error, mta_sts.lookup_error, tls_rpt.lookup_error, bimi.dmarc_dependency, bimi.lookup_error]
            ),
        }

    def _build_registration_section(self, result: AnalysisResponse) -> dict[str, Any]:
        if not result.domain_registration.rdap_available and not result.domain_registration.error:
            note = "Dados de registro podem estar indisponiveis ou parciais dependendo do TLD e do registrador."
        else:
            note = None

        return {
            "title": "Registro do Dominio",
            "summary": "Dados de RDAP exibidos apenas quando a origem respondeu com informacao util.",
            "items": self._compact(
                [
                    self._item("Mensagem RDAP", result.domain_registration.message),
                    self._item("Fonte", result.domain_registration.source),
                    self._item("Registrar", result.domain_registration.registrar),
                    self._item("Criado em", format_datetime(result.domain_registration.created_at) if result.domain_registration.created_at else None),
                    self._item("Expira em", format_datetime(result.domain_registration.expires_at) if result.domain_registration.expires_at else None),
                    self._item("Dias para expirar", result.domain_registration.days_to_expire),
                ]
            ),
            "lists": self._compact(
                [
                    self._list("Status do registro", result.domain_registration.status),
                ]
            ),
            "note": result.domain_registration.error or note,
        }

    def _build_ip_section(self, result: AnalysisResponse) -> dict[str, Any]:
        geo_value = ", ".join(
            part for part in (
                result.ip_intelligence.city,
                result.ip_intelligence.region,
                result.ip_intelligence.country,
            )
            if part
        )
        resolved_ips = [
            f"{item.ip} ({item.version.upper()} / {item.source_record_type} / {'publico' if item.is_public else 'nao publico'})"
            for item in result.ip_intelligence.resolved_ips
        ]
        return {
            "title": "Inteligencia de IP",
            "summary": "Contexto aproximado do IP observado para o website, sem presumir origem definitiva da infraestrutura.",
            "items": self._compact(
                [
                    self._item("Mensagem", result.ip_intelligence.message),
                    self._item("IP principal", result.ip_intelligence.primary_ip),
                    self._item("Versao", result.ip_intelligence.ip_version),
                    self._item("IP publico", yes_no(result.ip_intelligence.is_public)),
                    self._item("Reverse DNS", result.ip_intelligence.reverse_dns),
                    self._item("ASN", result.ip_intelligence.asn),
                    self._item("ASN org", result.ip_intelligence.asn_org),
                    self._item("ISP", result.ip_intelligence.isp),
                    self._item("Organizacao", result.ip_intelligence.organization),
                    self._item("Provider guess", result.ip_intelligence.provider_guess, kind="inference"),
                    self._item("Geolocalizacao aproximada", geo_value, kind="approximate"),
                    self._item("Timezone", result.ip_intelligence.timezone, kind="approximate"),
                    self._item("Proxy ou hosting guess", yes_no(result.ip_intelligence.is_proxy_or_hosting_guess), kind="inference"),
                    self._item("Fonte", result.ip_intelligence.source),
                ]
            ),
            "lists": self._compact(
                [
                    self._list("IPs resolvidos", resolved_ips),
                    self._list("Flags de anonimidade", result.ip_intelligence.anonymous_ip_flags),
                    self._list("Tags de reputacao", result.ip_intelligence.reputation_tags),
                ]
            ),
            "note": self._join_notes(
                list(result.ip_intelligence.notes)
                + ([result.ip_intelligence.confidence_note] if result.ip_intelligence.confidence_note else [])
            ),
        }

    def _build_changes_section(self, result: AnalysisResponse) -> dict[str, Any] | None:
        if not result.changes.has_previous_snapshot:
            return None
        changed_checks = [
            f"{item.label}: {item.previous} -> {item.current}"
            for item in result.changes.changed_checks
        ]
        return {
            "title": "Mudancas Relevantes",
            "summary": "Comparacao com o snapshot anterior salvo para o mesmo dominio.",
            "items": self._compact(
                [
                    self._item("Mensagem", result.changes.message),
                    self._item("Score anterior", result.changes.previous_score),
                    self._item("Score atual", result.changes.current_score),
                    self._item("Severity anterior", result.changes.previous_severity),
                    self._item("Severity atual", result.changes.current_severity),
                ]
            ),
            "lists": self._compact(
                [
                    self._list("Checks alterados", changed_checks),
                    self._list("Findings novos", result.changes.added_findings),
                    self._list("Findings resolvidos", result.changes.removed_findings),
                ]
            ),
            "note": None,
        }

    @staticmethod
    def _build_overview(result: AnalysisResponse) -> str:
        if result.findings:
            return result.findings[0].detail
        if result.recommendations:
            return result.recommendations[0].action
        return result.summary

    @staticmethod
    def _present_finding(item) -> dict[str, str]:
        return {
            "title": item.title,
            "detail": item.detail,
            "severity": humanize_token(item.severity),
            "category": humanize_token(item.category),
        }

    @staticmethod
    def _present_recommendation(item) -> dict[str, str]:
        return {
            "title": item.title,
            "action": item.action,
            "rationale": item.rationale,
            "priority": humanize_token(item.priority),
            "category": humanize_token(item.category),
        }

    @staticmethod
    def _item(label: str, value: Any, *, kind: str = "confirmed") -> dict[str, str] | None:
        if is_blank(value):
            return None
        return {
            "label": label,
            "value": str(value),
            "kind": kind,
        }

    @staticmethod
    def _list(title: str, items: list[Any]) -> dict[str, Any] | None:
        cleaned = [str(item) for item in items if not is_blank(item)]
        if not cleaned:
            return None
        return {"title": title, "items": cleaned}

    @staticmethod
    def _compact(items: list[Any]) -> list[Any]:
        return [item for item in items if item is not None]

    @staticmethod
    def _join_notes(notes: list[str]) -> str | None:
        cleaned = [item.strip() for item in notes if item and item.strip()]
        if not cleaned:
            return None
        return " ".join(cleaned)
