from app.schemas.analysis import (
    AnalysisChecks,
    DomainRegistrationResult,
    EmailPolicyResult,
    EmailTLSResult,
    Finding,
    OverallSeverity,
    Recommendation,
    ScoreBreakdown,
    WebsiteTLSResult,
)


class RecommendationService:
    """Builds structured findings and prioritized recommendations."""

    def build_findings(
        self,
        checks: AnalysisChecks,
        breakdown: ScoreBreakdown,
        overall_score: int,
        severity: OverallSeverity,
        *,
        website_tls: WebsiteTLSResult,
        email_tls: EmailTLSResult,
        domain_registration: DomainRegistrationResult,
        email_policies: EmailPolicyResult | None = None,
    ) -> list[Finding]:
        findings = [
            self._mx_finding(checks),
            self._spf_finding(checks),
            self._dmarc_finding(checks),
            self._dkim_finding(checks),
            self._mta_sts_finding(email_policies),
            self._tls_rpt_finding(email_policies),
            self._bimi_finding(email_policies),
            self._website_tls_finding(website_tls),
            self._email_tls_finding(email_tls),
            self._domain_registration_finding(domain_registration),
            self._consistency_finding(checks, breakdown.consistency_score, overall_score, severity),
        ]
        return [finding for finding in findings if finding is not None]

    def build_recommendations(
        self,
        checks: AnalysisChecks,
        *,
        website_tls: WebsiteTLSResult,
        email_tls: EmailTLSResult,
        domain_registration: DomainRegistrationResult,
        email_policies: EmailPolicyResult | None = None,
    ) -> list[Recommendation]:
        recommendations: list[Recommendation] = []

        recommendations.extend(self._mx_recommendations(checks))
        recommendations.extend(self._spf_recommendations(checks))
        recommendations.extend(self._dmarc_recommendations(checks))
        recommendations.extend(self._dkim_recommendations(checks))
        recommendations.extend(self._mta_sts_recommendations(email_policies))
        recommendations.extend(self._tls_rpt_recommendations(email_policies))
        recommendations.extend(self._bimi_recommendations(email_policies))
        recommendations.extend(self._website_tls_recommendations(website_tls))
        recommendations.extend(self._email_tls_recommendations(email_tls))
        recommendations.extend(self._domain_registration_recommendations(domain_registration))

        if not recommendations:
            recommendations.append(
                Recommendation(
                    category="consistencia",
                    priority="baixa",
                    title="Manter monitoramento",
                    action="Continue revisando SPF, DMARC, DKIM, HTTPS e vencimento do dominio a cada mudanca de infraestrutura.",
                    rationale="A postura atual parece consistente nesta analise inicial.",
                )
            )

        return sorted(recommendations, key=self._priority_sort_key)

    @staticmethod
    def _mx_recommendations(checks: AnalysisChecks) -> list[Recommendation]:
        if checks.mx.lookup_error:
            return []
        if checks.mx.status != "ausente":
            return []
        return [
            Recommendation(
                category="mx",
                priority="media",
                title="Definir estrategia de recebimento",
                action="Publique um MX valido ou um Null MX se o dominio nao deve receber e-mails.",
                rationale="Sem MX, o dominio nao comunica claramente a politica de recebimento.",
            )
        ]

    @staticmethod
    def _spf_recommendations(checks: AnalysisChecks) -> list[Recommendation]:
        recommendations: list[Recommendation] = []
        if checks.spf.lookup_error:
            return recommendations
        if checks.spf.status == "ausente":
            recommendations.append(
                Recommendation(
                    category="spf",
                    priority="alta",
                    title="Publicar SPF",
                    action="Crie um unico registro SPF listando os remetentes autorizados.",
                    rationale="Sem SPF, servidores externos nao conseguem validar remetentes autorizados.",
                )
            )
        elif checks.spf.status == "invalido":
            recommendations.append(
                Recommendation(
                    category="spf",
                    priority="alta",
                    title="Corrigir SPF invalido",
                    action="Consolide o SPF em um unico registro TXT valido.",
                    rationale="Multiplos registros SPF quebram a avaliacao do dominio.",
                )
            )
        elif checks.spf.final_all in {"+all", "?all"}:
            recommendations.append(
                Recommendation(
                    category="spf",
                    priority="alta",
                    title="Tornar SPF restritivo",
                    action="Troque o final do SPF para ~all ou -all depois de validar os remetentes.",
                    rationale="Politicas permissivas deixam a porta aberta para spoofing simples.",
                )
            )
        elif checks.spf.final_all == "~all":
            recommendations.append(
                Recommendation(
                    category="spf",
                    priority="media",
                    title="Avaliar migracao para -all",
                    action="Revise os remetentes autorizados e avance de ~all para -all quando possivel.",
                    rationale="Softfail protege menos do que uma politica de rejeicao explicita.",
                )
            )
        return recommendations

    @staticmethod
    def _dmarc_recommendations(checks: AnalysisChecks) -> list[Recommendation]:
        recommendations: list[Recommendation] = []
        if checks.dmarc.lookup_error:
            return recommendations
        if checks.dmarc.status == "ausente":
            recommendations.append(
                Recommendation(
                    category="dmarc",
                    priority="alta",
                    title="Publicar DMARC",
                    action="Crie um registro DMARC em _dmarc com p=none como ponto de partida seguro.",
                    rationale="Sem DMARC, SPF e DKIM nao sao convertidos em politica de protecao operacional.",
                )
            )
        elif checks.dmarc.status == "invalido":
            recommendations.append(
                Recommendation(
                    category="dmarc",
                    priority="alta",
                    title="Corrigir DMARC invalido",
                    action="Mantenha apenas um registro DMARC valido com p=none, quarantine ou reject.",
                    rationale="Erros de sintaxe ou duplicidade anulam a protecao esperada.",
                )
            )
        elif checks.dmarc.policy == "none":
            recommendations.append(
                Recommendation(
                    category="dmarc",
                    priority="media",
                    title="Elevar a politica DMARC",
                    action="Depois de observar os relatorios, avance de p=none para quarantine ou reject.",
                    rationale="p=none monitora, mas nao aplica acao sobre mensagens suspeitas.",
                )
            )
        elif checks.dmarc.pct is not None and checks.dmarc.pct < 100:
            recommendations.append(
                Recommendation(
                    category="dmarc",
                    priority="media",
                    title="Aumentar o pct do DMARC",
                    action="Leve o pct para 100 assim que a politica estiver validada.",
                    rationale="Aplicacao parcial reduz a cobertura real da politica.",
                )
            )
        return recommendations

    @staticmethod
    def _dkim_recommendations(checks: AnalysisChecks) -> list[Recommendation]:
        if checks.dkim.status == "desconhecido":
            return [
                Recommendation(
                    category="dkim",
                    priority="media",
                    title="Validar DKIM com headers reais",
                    action="Capture uma mensagem assinada e confirme selector e alinhamento DKIM pelos headers.",
                    rationale="A heuristica por dominio nao consegue confirmar DKIM com confianca total.",
                )
            ]
        if checks.dkim.status == "invalido":
            return [
                Recommendation(
                    category="dkim",
                    priority="alta",
                    title="Revisar registros DKIM",
                    action="Verifique os selectors encontrados e corrija registros com formato inconsistente.",
                    rationale="Registros DKIM malformados podem quebrar a assinatura ou a verificacao.",
                )
            ]
        return []

    @staticmethod
    def _website_tls_recommendations(website_tls: WebsiteTLSResult) -> list[Recommendation]:
        recommendations: list[Recommendation] = []
        if not website_tls.ssl_active:
            recommendations.append(
                Recommendation(
                    category="tls_site",
                    priority="alta",
                    title="Ativar HTTPS no site",
                    action="Publique o website na porta 443 com um certificado valido e renovacao monitorada.",
                    rationale="Sem HTTPS ativo, o trafego web fica sem protecao de transporte.",
                )
            )
            return recommendations

        if website_tls.certificate_valid is False:
            recommendations.append(
                Recommendation(
                    category="tls_site",
                    priority="alta",
                    title="Corrigir o certificado do site",
                    action="Substitua o certificado apresentado por um certificado valido para o hostname analisado.",
                    rationale="Falhas de validacao reduzem a confianca do canal HTTPS.",
                )
            )
        if website_tls.expiry_status == "expirado":
            recommendations.append(
                Recommendation(
                    category="tls_site",
                    priority="alta",
                    title="Renovar certificado expirado",
                    action="Renove imediatamente o certificado HTTPS e valide a cadeia apresentada.",
                    rationale="Certificado expirado compromete o acesso seguro ao website.",
                )
            )
        elif website_tls.expiry_status == "proximo_expiracao":
            recommendations.append(
                Recommendation(
                    category="tls_site",
                    priority="media",
                    title="Planejar renovacao do certificado",
                    action="Antecipe a renovacao do certificado HTTPS antes da data de expiracao.",
                    rationale="Certificados perto do vencimento aumentam risco operacional e indisponibilidade.",
                )
            )
        return recommendations

    @staticmethod
    def _email_tls_recommendations(email_tls: EmailTLSResult) -> list[Recommendation]:
        recommendations: list[Recommendation] = []
        if not email_tls.mx_results:
            return recommendations

        unsupported = [item.host for item in email_tls.mx_results if item.starttls_supported is False]
        invalid_cert = [item.host for item in email_tls.mx_results if item.certificate_valid is False]
        hostname_mismatch = [item.host for item in email_tls.mx_results if item.hostname_match is False]
        expiring = [
            item.host
            for item in email_tls.mx_results
            if item.expiry_status in {"expirado", "proximo_expiracao"}
        ]

        if unsupported:
            recommendations.append(
                Recommendation(
                    category="tls_email",
                    priority="alta",
                    title="Habilitar STARTTLS nos MX",
                    action="Ative STARTTLS nos servidores MX sem suporte e valide a negociacao apos a mudanca.",
                    rationale="Sem STARTTLS, o transporte de e-mail pode ocorrer sem criptografia oportunista.",
                )
            )
        if invalid_cert:
            recommendations.append(
                Recommendation(
                    category="tls_email",
                    priority="alta",
                    title="Corrigir certificados dos MX",
                    action="Revise os certificados apresentados pelos MX e corrija cadeia, validade e confianca.",
                    rationale="Certificados invalidos nos MX enfraquecem a protecao do canal de e-mail.",
                )
            )
        if hostname_mismatch:
            recommendations.append(
                Recommendation(
                    category="tls_email",
                    priority="media",
                    title="Ajustar nomes dos certificados dos MX",
                    action="Garanta que o nome apresentado no certificado corresponda ao hostname do servidor MX testado.",
                    rationale="Divergencia de nome reduz a confianca na autenticidade do servidor SMTP.",
                )
            )
        if expiring:
            recommendations.append(
                Recommendation(
                    category="tls_email",
                    priority="media",
                    title="Renovar certificados de e-mail proximos do vencimento",
                    action="Antecipe a renovacao dos certificados dos MX que estao expirados ou proximos da expiracao.",
                    rationale="Certificados vencidos ou perto do vencimento aumentam risco de falha no transporte seguro.",
                )
            )
        return recommendations

    @staticmethod
    def _domain_registration_recommendations(
        domain_registration: DomainRegistrationResult,
    ) -> list[Recommendation]:
        if not domain_registration.rdap_available:
            return [
                Recommendation(
                    category="registro_dominio",
                    priority="media",
                    title="Validar dados de registro do dominio",
                    action="Confira manualmente a expiracao e o registrador do dominio caso o RDAP nao tenha retornado dados suficientes.",
                    rationale="Visibilidade parcial do registro dificulta prevenir expiracao acidental do dominio.",
                )
            ]

        if domain_registration.expiry_status == "expirado":
            return [
                Recommendation(
                    category="registro_dominio",
                    priority="alta",
                    title="Regularizar dominio expirado",
                    action="Acione o registrador para renovar ou recuperar o dominio imediatamente.",
                    rationale="Dominio expirado pode interromper website, e-mail e a continuidade operacional.",
                )
            ]

        if domain_registration.expiry_status == "proximo_expiracao":
            return [
                Recommendation(
                    category="registro_dominio",
                    priority="alta",
                    title="Renovar o dominio com antecedencia",
                    action="Renove o dominio antes da expiracao e confirme a ativacao de renovacao automatica.",
                    rationale="Prazo curto para expiracao aumenta risco de indisponibilidade e perda de posse do dominio.",
                )
            ]

        return []

    @staticmethod
    def _mta_sts_recommendations(email_policies: EmailPolicyResult | None) -> list[Recommendation]:
        if email_policies is None:
            return []
        mta_sts = email_policies.mta_sts
        if mta_sts.status == "ausente":
            return [
                Recommendation(
                    category="mta_sts",
                    priority="media",
                    title="Publicar MTA-STS",
                    action="Publique MTA-STS com politica HTTPS valida para reforcar o transporte entre MTAs.",
                    rationale="Sem MTA-STS, o dominio depende apenas de STARTTLS oportunista sem politica declarada.",
                )
            ]
        if mta_sts.mode == "testing":
            return [
                Recommendation(
                    category="mta_sts",
                    priority="media",
                    title="Evoluir MTA-STS para enforce",
                    action="Depois de validar a cobertura dos MX, avance de testing para enforce.",
                    rationale="MTA-STS em testing ainda nao aplica enforcement real de politica.",
                )
            ]
        return []

    @staticmethod
    def _tls_rpt_recommendations(email_policies: EmailPolicyResult | None) -> list[Recommendation]:
        if email_policies is None:
            return []
        tls_rpt = email_policies.tls_rpt
        if tls_rpt.status == "ausente":
            return [
                Recommendation(
                    category="tls_rpt",
                    priority="media",
                    title="Publicar TLS-RPT",
                    action="Adicione um registro TLS-RPT com destinos rua validos para acompanhar falhas de transporte TLS.",
                    rationale="Sem TLS-RPT, fica mais dificil observar problemas de entrega segura entre servidores de e-mail.",
                )
            ]
        if tls_rpt.status == "invalido":
            return [
                Recommendation(
                    category="tls_rpt",
                    priority="media",
                    title="Corrigir TLS-RPT",
                    action="Revise o formato do registro e os destinos rua para manter relatorios utilizaveis.",
                    rationale="TLS-RPT malformado reduz a visibilidade sobre falhas de transporte TLS.",
                )
            ]
        return []

    @staticmethod
    def _bimi_recommendations(email_policies: EmailPolicyResult | None) -> list[Recommendation]:
        if email_policies is None:
            return []
        bimi = email_policies.bimi
        if bimi.status != "presente":
            return []
        if bimi.readiness in {"nao_pronto", "desconhecido"}:
            return [
                Recommendation(
                    category="bimi",
                    priority="baixa",
                    title="Revisar readiness de BIMI",
                    action="Confirme enforcement de DMARC, metadados BIMI e requisitos do provedor de mailbox antes de considerar BIMI pronto.",
                    rationale="A presenca do registro BIMI sozinha nao garante suporte efetivo no ecossistema.",
                )
            ]
        return []

    @staticmethod
    def _mx_finding(checks: AnalysisChecks) -> Finding:
        if checks.mx.lookup_error:
            return Finding(
                category="mx",
                severity="medio",
                title="MX inconclusivo",
                detail=checks.mx.message,
            )
        if checks.mx.is_null_mx:
            return Finding(
                category="mx",
                severity="baixo",
                title="Null MX declarado",
                detail="O dominio informa explicitamente que nao recebe e-mails.",
            )
        if checks.mx.status == "ausente":
            return Finding(
                category="mx",
                severity="medio",
                title="MX ausente",
                detail="O dominio nao publica MX e nao declara Null MX.",
            )
        return Finding(
            category="mx",
            severity="baixo",
            title="MX publicado",
            detail=checks.mx.message,
        )

    @staticmethod
    def _spf_finding(checks: AnalysisChecks) -> Finding:
        spf = checks.spf
        if spf.lookup_error:
            return Finding(
                category="spf",
                severity="medio",
                title="SPF inconclusivo",
                detail=spf.message,
            )
        if spf.status == "ausente":
            return Finding(
                category="spf",
                severity="alto",
                title="SPF ausente",
                detail="Nenhum SPF foi encontrado para limitar remetentes autorizados.",
            )
        if spf.status == "invalido":
            return Finding(
                category="spf",
                severity="alto",
                title="SPF invalido",
                detail=spf.message,
            )
        if spf.final_all == "+all":
            return Finding(
                category="spf",
                severity="critico",
                title="SPF permissivo demais",
                detail="O registro termina em +all, aceitando qualquer remetente.",
            )
        if spf.final_all == "?all":
            return Finding(
                category="spf",
                severity="alto",
                title="SPF neutro",
                detail="O registro termina em ?all e nao bloqueia efetivamente remetentes nao autorizados.",
            )
        if spf.final_all == "~all":
            return Finding(
                category="spf",
                severity="medio",
                title="SPF em softfail",
                detail="O SPF existe, mas usa ~all, oferecendo protecao parcial.",
            )
        if spf.final_all == "-all":
            return Finding(
                category="spf",
                severity="baixo",
                title="SPF restritivo",
                detail="O SPF termina em -all e restringe remetentes nao autorizados.",
            )
        return Finding(
            category="spf",
            severity="medio",
            title="SPF sem all terminal",
            detail=spf.message,
        )

    @staticmethod
    def _dmarc_finding(checks: AnalysisChecks) -> Finding:
        dmarc = checks.dmarc
        if dmarc.lookup_error:
            return Finding(
                category="dmarc",
                severity="medio",
                title="DMARC inconclusivo",
                detail=dmarc.message,
            )
        if dmarc.status == "ausente":
            return Finding(
                category="dmarc",
                severity="alto",
                title="DMARC ausente",
                detail="O dominio ainda nao publica politica DMARC.",
            )
        if dmarc.status == "invalido":
            return Finding(
                category="dmarc",
                severity="alto",
                title="DMARC invalido",
                detail=dmarc.message,
            )
        if dmarc.policy == "none":
            return Finding(
                category="dmarc",
                severity="medio",
                title="DMARC em monitoramento",
                detail="O dominio publica DMARC com p=none, sem acao de enforcement.",
            )
        if dmarc.policy == "quarantine":
            return Finding(
                category="dmarc",
                severity="baixo",
                title="DMARC intermediario",
                detail="O dominio aplica quarentena para mensagens suspeitas.",
            )
        return Finding(
            category="dmarc",
            severity="baixo",
            title="DMARC forte",
            detail="O dominio aplica rejeicao com politica DMARC forte.",
        )

    @staticmethod
    def _dkim_finding(checks: AnalysisChecks) -> Finding:
        dkim = checks.dkim
        if dkim.status == "provavelmente_presente":
            return Finding(
                category="dkim",
                severity="baixo",
                title="DKIM provavelmente presente",
                detail=dkim.message,
            )
        if dkim.status == "invalido":
            return Finding(
                category="dkim",
                severity="alto",
                title="DKIM inconsistente",
                detail=dkim.message,
            )
        if dkim.status == "provavelmente_ausente":
            return Finding(
                category="dkim",
                severity="medio",
                title="DKIM provavelmente ausente",
                detail="Os sinais observados sugerem ausencia de DKIM, mas sem certeza total.",
            )
        return Finding(
            category="dkim",
            severity="medio",
            title="DKIM inconclusivo",
            detail=dkim.confidence_note,
        )

    @staticmethod
    def _website_tls_finding(website_tls: WebsiteTLSResult) -> Finding:
        if not website_tls.ssl_active:
            return Finding(
                category="tls_site",
                severity="alto",
                title="HTTPS nao confirmado",
                detail=website_tls.message,
            )
        if website_tls.expiry_status == "expirado":
            return Finding(
                category="tls_site",
                severity="critico",
                title="Certificado do site expirado",
                detail=website_tls.message,
            )
        if website_tls.certificate_valid is False:
            return Finding(
                category="tls_site",
                severity="alto",
                title="Certificado do site invalido",
                detail=website_tls.message,
            )
        if website_tls.expiry_status == "proximo_expiracao":
            return Finding(
                category="tls_site",
                severity="medio",
                title="Certificado do site proximo da expiracao",
                detail=website_tls.message,
            )
        return Finding(
            category="tls_site",
            severity="baixo",
            title="HTTPS ativo",
            detail=website_tls.message,
        )

    @staticmethod
    def _email_tls_finding(email_tls: EmailTLSResult) -> Finding:
        if not email_tls.mx_results:
            return Finding(
                category="tls_email",
                severity="medio",
                title="STARTTLS nao testado",
                detail=email_tls.message,
            )

        unsupported = [item for item in email_tls.mx_results if item.starttls_supported is False]
        invalid_cert = [item for item in email_tls.mx_results if item.certificate_valid is False]
        expired = [item for item in email_tls.mx_results if item.expiry_status == "expirado"]
        hostname_mismatch = [item for item in email_tls.mx_results if item.hostname_match is False]

        if expired:
            hosts = ", ".join(item.host for item in expired[:3])
            return Finding(
                category="tls_email",
                severity="alto",
                title="Certificado expirado em MX",
                detail=f"Os MX {hosts} apresentaram certificado expirado durante o STARTTLS.",
            )
        if unsupported:
            hosts = ", ".join(item.host for item in unsupported[:3])
            return Finding(
                category="tls_email",
                severity="alto",
                title="MX sem STARTTLS",
                detail=f"Os MX {hosts} nao anunciaram STARTTLS durante o teste.",
            )
        if invalid_cert:
            hosts = ", ".join(item.host for item in invalid_cert[:3])
            return Finding(
                category="tls_email",
                severity="alto",
                title="Certificado de e-mail nao validado",
                detail=f"Os MX {hosts} anunciaram STARTTLS, mas o certificado nao foi validado com sucesso.",
            )
        if hostname_mismatch:
            hosts = ", ".join(item.host for item in hostname_mismatch[:3])
            return Finding(
                category="tls_email",
                severity="medio",
                title="Hostname do MX nao confere com o certificado",
                detail=f"O certificado apresentado por {hosts} nao corresponde ao hostname testado.",
            )
        return Finding(
            category="tls_email",
            severity="baixo",
            title="STARTTLS observado nos MX",
            detail=email_tls.message,
        )

    @staticmethod
    def _domain_registration_finding(domain_registration: DomainRegistrationResult) -> Finding:
        if not domain_registration.rdap_available:
            return Finding(
                category="registro_dominio",
                severity="medio",
                title="RDAP indisponivel",
                detail=domain_registration.message,
            )
        if domain_registration.expiry_status == "expirado":
            return Finding(
                category="registro_dominio",
                severity="critico",
                title="Dominio expirado",
                detail="Os dados de registro indicam que o dominio ja expirou.",
            )
        if domain_registration.expiry_status == "proximo_expiracao":
            return Finding(
                category="registro_dominio",
                severity="alto",
                title="Dominio proximo da expiracao",
                detail="Os dados de registro indicam prazo curto para vencimento do dominio.",
            )
        return Finding(
            category="registro_dominio",
            severity="baixo",
            title="Registro de dominio consultado",
            detail=domain_registration.message,
        )

    @staticmethod
    def _mta_sts_finding(email_policies: EmailPolicyResult | None) -> Finding | None:
        if email_policies is None:
            return None
        mta_sts = email_policies.mta_sts
        if mta_sts.status == "ausente":
            return Finding(
                category="mta_sts",
                severity="medio",
                title="MTA-STS ausente",
                detail="O dominio nao publica politica MTA-STS para transporte entre MTAs.",
            )
        if mta_sts.mode == "enforce" and mta_sts.status == "presente":
            return Finding(
                category="mta_sts",
                severity="baixo",
                title="MTA-STS em enforce",
                detail="O dominio publica MTA-STS com modo enforce.",
            )
        if mta_sts.status == "invalido":
            return Finding(
                category="mta_sts",
                severity="medio",
                title="MTA-STS inconsistente",
                detail=mta_sts.message,
            )
        return None

    @staticmethod
    def _tls_rpt_finding(email_policies: EmailPolicyResult | None) -> Finding | None:
        if email_policies is None:
            return None
        tls_rpt = email_policies.tls_rpt
        if tls_rpt.status == "ausente":
            return Finding(
                category="tls_rpt",
                severity="baixo",
                title="TLS-RPT ausente",
                detail="O dominio nao publica SMTP TLS Reporting para acompanhar falhas de transporte seguro.",
            )
        if tls_rpt.status == "invalido":
            return Finding(
                category="tls_rpt",
                severity="medio",
                title="TLS-RPT inconsistente",
                detail=tls_rpt.message,
            )
        return None

    @staticmethod
    def _bimi_finding(email_policies: EmailPolicyResult | None) -> Finding | None:
        if email_policies is None:
            return None
        bimi = email_policies.bimi
        if bimi.status != "presente":
            return None
        if bimi.readiness == "provavel":
            return Finding(
                category="bimi",
                severity="baixo",
                title="BIMI com readiness promissora",
                detail=bimi.message,
            )
        return Finding(
            category="bimi",
            severity="baixo",
            title="BIMI localizado",
            detail=bimi.message,
        )

    @staticmethod
    def _consistency_finding(
        checks: AnalysisChecks,
        consistency_score: int,
        overall_score: int,
        severity: OverallSeverity,
    ) -> Finding:
        if consistency_score >= 85:
            detail = (
                f"O conjunto MX, SPF, DKIM e DMARC parece coerente para o uso atual do dominio. "
                f"Score geral {overall_score}/100 ({severity})."
            )
            return Finding(
                category="consistencia",
                severity="baixo",
                title="Controles coerentes",
                detail=detail,
            )
        if checks.mx.accepts_mail:
            detail = "O dominio recebe e-mails, mas os controles de autenticacao nao estao totalmente alinhados."
        else:
            detail = "A politica de recebimento e autenticacao ainda nao esta totalmente coerente."
        return Finding(
            category="consistencia",
            severity="alto" if consistency_score < 50 else "medio",
            title="Consistencia parcial",
            detail=detail,
        )

    @staticmethod
    def _priority_sort_key(recommendation: Recommendation) -> tuple[int, str]:
        weights = {"alta": 0, "media": 1, "baixa": 2}
        return (weights[recommendation.priority], recommendation.title)
