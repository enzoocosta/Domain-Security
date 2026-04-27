from app.schemas.analysis import (
    AnalysisChecks,
    DomainRegistrationResult,
    Finding,
    Recommendation,
    WebsiteTLSResult,
)


class RecommendationService:
    """Builds the reduced finding set and strictly conditional recommendations."""

    def build_findings(self, checks: AnalysisChecks) -> list[Finding]:
        return [
            self._mx_finding(checks),
            self._spf_finding(checks),
            self._dkim_finding(checks),
            self._dmarc_finding(checks),
        ]

    def build_recommendations(
        self,
        checks: AnalysisChecks,
        *,
        website_tls: WebsiteTLSResult,
        domain_registration: DomainRegistrationResult,
    ) -> list[Recommendation]:
        recommendations: list[Recommendation] = []
        recommendations.extend(self._mx_recommendations(checks))
        recommendations.extend(self._spf_recommendations(checks))
        recommendations.extend(self._dmarc_recommendations(checks))
        recommendations.extend(self._dkim_recommendations(checks))
        recommendations.extend(self._website_tls_recommendations(website_tls))
        recommendations.extend(
            self._domain_registration_recommendations(domain_registration)
        )
        return sorted(recommendations, key=self._priority_sort_key)

    @staticmethod
    def _mx_finding(checks: AnalysisChecks) -> Finding:
        if checks.mx.lookup_error:
            return Finding(
                category="mx",
                severity="medio",
                title="MX nao verificado",
                detail="Nao foi possivel confirmar os registros MX neste momento.",
            )
        if checks.mx.is_null_mx:
            return Finding(
                category="mx",
                severity="baixo",
                title="MX publicado",
                detail="O dominio informa explicitamente que nao recebe e-mails.",
            )
        if checks.mx.status == "ausente":
            return Finding(
                category="mx",
                severity="alto",
                title="MX ausente",
                detail="Sem registros MX, seu dominio nao consegue receber e-mails.",
            )
        return Finding(
            category="mx",
            severity="baixo",
            title="MX publicado",
            detail="O dominio publica registros MX para recebimento de e-mails.",
        )

    @staticmethod
    def _spf_finding(checks: AnalysisChecks) -> Finding:
        spf = checks.spf
        if spf.lookup_error:
            return Finding(
                category="spf",
                severity="medio",
                title="SPF nao verificado",
                detail="Nao foi possivel confirmar a politica SPF neste momento.",
            )
        if spf.status == "ausente":
            return Finding(
                category="spf",
                severity="alto",
                title="SPF ausente",
                detail="Sem SPF, qualquer servidor pode enviar e-mails pelo seu dominio.",
            )
        if spf.status == "invalido":
            return Finding(
                category="spf",
                severity="alto",
                title="SPF invalido",
                detail="O SPF publicado tem erro e pode nao proteger o dominio.",
            )
        if spf.final_all == "~all":
            return Finding(
                category="spf",
                severity="medio",
                title="SPF em softfail",
                detail="Qualquer servidor pode enviar e-mail pelo seu dominio sem ser bloqueado.",
            )
        if spf.final_all == "-all":
            return Finding(
                category="spf",
                severity="baixo",
                title="SPF em hardfail",
                detail="O dominio rejeita remetentes nao autorizados com SPF.",
            )
        return Finding(
            category="spf",
            severity="alto" if spf.final_all in {"+all", "?all"} else "medio",
            title="SPF presente",
            detail="O dominio publica SPF, mas a politica ainda pode ser fortalecida.",
        )

    @staticmethod
    def _dkim_finding(checks: AnalysisChecks) -> Finding:
        dkim = checks.dkim
        if dkim.status in {"confirmado_presente", "provavelmente_presente"}:
            return Finding(
                category="dkim",
                severity="baixo",
                title="DKIM encontrado",
                detail="Assinatura digital de e-mail detectada. Boa protecao.",
            )
        return Finding(
            category="dkim",
            severity="alto" if dkim.status == "invalido" else "medio",
            title="DKIM nao encontrado",
            detail="Nenhuma assinatura digital de e-mail foi encontrada no dominio.",
        )

    @staticmethod
    def _dmarc_finding(checks: AnalysisChecks) -> Finding:
        dmarc = checks.dmarc
        if dmarc.lookup_error:
            return Finding(
                category="dmarc",
                severity="medio",
                title="DMARC nao verificado",
                detail="Nao foi possivel confirmar a politica DMARC neste momento.",
            )
        if dmarc.status == "ausente":
            return Finding(
                category="dmarc",
                severity="alto",
                title="DMARC ausente",
                detail="Sem DMARC, e-mails falsos no seu nome nao sao detectados.",
            )
        if dmarc.status == "invalido":
            return Finding(
                category="dmarc",
                severity="alto",
                title="DMARC invalido",
                detail="O registro DMARC tem erro e pode nao aplicar protecao.",
            )
        if dmarc.policy == "none":
            return Finding(
                category="dmarc",
                severity="medio",
                title="DMARC em none",
                detail="Sua politica DMARC esta em modo de monitoramento e ainda nao bloqueia abuso.",
            )
        if dmarc.policy == "quarantine":
            return Finding(
                category="dmarc",
                severity="baixo",
                title="DMARC em quarantine",
                detail="Mensagens suspeitas podem ser enviadas para quarentena. Boa protecao.",
            )
        return Finding(
            category="dmarc",
            severity="baixo",
            title="DMARC em reject",
            detail="Mensagens suspeitas sao rejeitadas. Boa protecao.",
        )

    @staticmethod
    def _mx_recommendations(checks: AnalysisChecks) -> list[Recommendation]:
        if checks.mx.lookup_error or checks.mx.status != "ausente":
            return []
        return [
            Recommendation(
                category="mx",
                priority="alta",
                title="Configurar e-mail",
                action="Sem registros MX, seu dominio nao consegue receber e-mails.",
                rationale="Publique registros MX validos para a infraestrutura de e-mail.",
            )
        ]

    @staticmethod
    def _spf_recommendations(checks: AnalysisChecks) -> list[Recommendation]:
        if checks.spf.lookup_error:
            return []
        if checks.spf.status == "ausente":
            return [
                Recommendation(
                    category="spf",
                    priority="alta",
                    title="Publicar SPF",
                    action="Sem SPF, qualquer servidor pode enviar e-mails pelo seu dominio.",
                    rationale="Publique um unico registro SPF com os remetentes autorizados.",
                )
            ]
        if checks.spf.final_all == "~all":
            return [
                Recommendation(
                    category="spf",
                    priority="media",
                    title="Fortalecer SPF",
                    action="Troque ~all por -all para rejeitar e-mails nao autorizados.",
                    rationale="Revise os remetentes legitimos antes de endurecer a politica SPF.",
                )
            ]
        return []

    @staticmethod
    def _dmarc_recommendations(checks: AnalysisChecks) -> list[Recommendation]:
        if checks.dmarc.lookup_error:
            return []
        if checks.dmarc.status == "ausente":
            return [
                Recommendation(
                    category="dmarc",
                    priority="alta",
                    title="Publicar DMARC",
                    action="DMARC protege contra falsificacao de e-mail. Comece com p=quarantine.",
                    rationale="Publique um registro DMARC em _dmarc.",
                )
            ]
        if checks.dmarc.policy == "none":
            return [
                Recommendation(
                    category="dmarc",
                    priority="media",
                    title="Ativar DMARC",
                    action="Sua politica DMARC esta em modo monitoramento. Eleve para quarantine.",
                    rationale="Depois de validar os fluxos legitimos, avance para enforcement.",
                )
            ]
        return []

    @staticmethod
    def _dkim_recommendations(checks: AnalysisChecks) -> list[Recommendation]:
        if checks.dkim.status in {"confirmado_presente", "provavelmente_presente"}:
            return []
        return [
            Recommendation(
                category="dkim",
                priority="media",
                title="Verificar DKIM",
                action="Nenhuma assinatura digital de e-mail foi encontrada no dominio.",
                rationale="Confirme o seletor usado pelo provedor e publique um registro DKIM valido.",
            )
        ]

    @staticmethod
    def _website_tls_recommendations(
        website_tls: WebsiteTLSResult,
    ) -> list[Recommendation]:
        if not website_tls.ssl_active:
            return [
                Recommendation(
                    category="tls_site",
                    priority="alta",
                    title="Ativar HTTPS",
                    action="Seu site nao usa conexao segura. Configure um certificado SSL.",
                    rationale="Publique o website em HTTPS com um certificado valido.",
                )
            ]

        if website_tls.days_to_expire is None:
            return []
        if website_tls.days_to_expire <= 30:
            return [
                Recommendation(
                    category="tls_site",
                    priority="alta",
                    title="Renovar SSL",
                    action=f"Certificado {RecommendationService._expiry_sentence(website_tls.days_to_expire)}. Renove para nao afetar o site.",
                    rationale="Evite indisponibilidade por expiracao do certificado HTTPS.",
                )
            ]
        return []

    @staticmethod
    def _domain_registration_recommendations(
        domain_registration: DomainRegistrationResult,
    ) -> list[Recommendation]:
        if domain_registration.days_to_expire is None:
            return []
        if domain_registration.days_to_expire <= 60:
            return [
                Recommendation(
                    category="registro_dominio",
                    priority="alta",
                    title="Renovar dominio",
                    action=f"O registro do dominio {RecommendationService._expiry_sentence(domain_registration.days_to_expire)}. Renove para nao perde-lo.",
                    rationale="Evite indisponibilidade e risco de perda do dominio.",
                )
            ]
        return []

    @staticmethod
    def _expiry_sentence(days_to_expire: int) -> str:
        if days_to_expire < 0:
            return f"expirou ha {abs(days_to_expire)} dia(s)"
        return f"expira em {days_to_expire} dia(s)"

    @staticmethod
    def _priority_sort_key(recommendation: Recommendation) -> tuple[int, str]:
        weights = {"alta": 0, "media": 1, "baixa": 2}
        return (weights[recommendation.priority], recommendation.title)
