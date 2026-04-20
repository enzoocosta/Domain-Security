from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from urllib import error, request

from app.core.config import settings
from app.core.exceptions import DNSLookupError
from app.schemas.analysis import BIMIResult, DMARCCheckResult, DNSSECResult, EmailPolicyResult, MTASTSResult, TLSRPTResult
from app.services.dns_service import DNSLookupService


class EmailPolicyService:
    """Evaluates transport and readiness policies that complement SPF/DKIM/DMARC."""

    def __init__(
        self,
        *,
        dns_service: DNSLookupService | None = None,
        policy_fetcher: Callable[[str, float], str] | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        self.dns_service = dns_service or DNSLookupService()
        self.policy_fetcher = policy_fetcher or self._default_fetch_policy
        self.timeout_seconds = timeout_seconds or settings.website_tls_timeout_seconds

    def analyze(self, domain: str, *, dmarc_result: DMARCCheckResult) -> EmailPolicyResult:
        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="dsc-email-policy") as executor:
            mta_sts_future = executor.submit(self._analyze_mta_sts, domain)
            tls_rpt_future = executor.submit(self._analyze_tls_rpt, domain)
            bimi_future = executor.submit(self._analyze_bimi, domain, dmarc_result=dmarc_result)

            return EmailPolicyResult(
                mta_sts=mta_sts_future.result(),
                tls_rpt=tls_rpt_future.result(),
                bimi=bimi_future.result(),
                dnssec=self._analyze_dnssec(domain),
            )

    def _analyze_mta_sts(self, domain: str) -> MTASTSResult:
        checked_name = f"_mta-sts.{domain}"
        try:
            txt_records = self.dns_service.get_txt_records(checked_name, missing_on_nxdomain=True)
        except DNSLookupError as exc:
            return MTASTSResult(
                checked_name=checked_name,
                status="desconhecido",
                lookup_error=str(exc),
                message="A consulta de MTA-STS nao foi concluida por indisponibilidade temporaria de DNS.",
            )

        records = [item.strip() for item in txt_records if item.strip().lower().startswith("v=stsv1")]
        if not records:
            return MTASTSResult(
                checked_name=checked_name,
                status="ausente",
                policy_url=f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                message="Nenhum registro MTA-STS foi encontrado.",
                recommendations=["Publique MTA-STS para reforcar a seguranca de transporte de e-mail entre MTAs."],
            )
        if len(records) > 1:
            return MTASTSResult(
                checked_name=checked_name,
                status="invalido",
                dns_record=records[0],
                message="Foram encontrados multiplos registros MTA-STS, o que e inconsistente.",
                warnings=["Mantenha apenas um registro TXT valido em _mta-sts."],
                recommendations=["Consolide o MTA-STS em um unico registro TXT valido."],
            )

        dns_tags = self._parse_semicolon_tags(records[0], expected_prefix="v=stsv1")
        policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        warnings: list[str] = []
        recommendations: list[str] = []

        try:
            policy_text = self.policy_fetcher(policy_url, self.timeout_seconds)
        except Exception as exc:
            return MTASTSResult(
                checked_name=checked_name,
                status="invalido",
                dns_record=records[0],
                policy_url=policy_url,
                policy_id=dns_tags.get("id"),
                fetch_error=str(exc),
                message="O registro MTA-STS existe, mas a politica HTTPS nao foi obtida com sucesso.",
                warnings=["Sem politica HTTPS valida, o MTA-STS permanece incompleto."],
                recommendations=["Publique a politica MTA-STS em HTTPS no caminho padrao .well-known."],
            )

        parsed_policy = self._parse_line_tags(policy_text)
        version = parsed_policy.get("version")
        mode = parsed_policy.get("mode")
        max_age = self._parse_int(parsed_policy.get("max_age"))
        mx_patterns = parsed_policy.get("mx", [])

        if version != "STSv1":
            warnings.append("A politica MTA-STS deveria declarar version: STSv1.")
        if mode not in {"none", "testing", "enforce"}:
            warnings.append("A politica MTA-STS deveria declarar mode valido.")
        if max_age is None:
            warnings.append("A politica MTA-STS deveria declarar max_age numerico.")
        if mode in {"testing", "enforce"} and not mx_patterns:
            warnings.append("Politicas MTA-STS em testing/enforce deveriam listar ao menos um padrao mx.")
        if mode == "testing":
            recommendations.append("Quando a validacao estiver estavel, avance o MTA-STS de testing para enforce.")
        elif mode == "none":
            recommendations.append("Considere evoluir o MTA-STS para testing ou enforce quando houver cobertura suficiente.")

        status = "presente" if not warnings else "invalido"
        message = (
            f"MTA-STS publicado com modo {mode}."
            if mode in {"none", "testing", "enforce"}
            else "A politica MTA-STS foi localizada, mas esta incompleta ou inconsistente."
        )
        return MTASTSResult(
            checked_name=checked_name,
            status=status,
            dns_record=records[0],
            policy_url=policy_url,
            policy_id=dns_tags.get("id"),
            mode=mode if mode in {"none", "testing", "enforce"} else None,
            max_age=max_age,
            mx_patterns=mx_patterns,
            message=message,
            warnings=warnings,
            recommendations=recommendations,
        )

    def _analyze_tls_rpt(self, domain: str) -> TLSRPTResult:
        checked_name = f"_smtp._tls.{domain}"
        try:
            txt_records = self.dns_service.get_txt_records(checked_name, missing_on_nxdomain=True)
        except DNSLookupError as exc:
            return TLSRPTResult(
                checked_name=checked_name,
                status="desconhecido",
                lookup_error=str(exc),
                message="A consulta de SMTP TLS Reporting nao foi concluida por indisponibilidade temporaria de DNS.",
            )

        records = [item.strip() for item in txt_records if item.strip().lower().startswith("v=tlsrptv1")]
        if not records:
            return TLSRPTResult(
                checked_name=checked_name,
                status="ausente",
                message="Nenhum registro SMTP TLS Reporting foi encontrado.",
                recommendations=["Publique TLS-RPT para receber visibilidade sobre falhas de transporte TLS em e-mail."],
            )
        if len(records) > 1:
            return TLSRPTResult(
                checked_name=checked_name,
                status="invalido",
                records=records,
                message="Foram encontrados multiplos registros TLS-RPT, o que e inconsistente.",
                warnings=["Mantenha apenas um registro TLS-RPT valido em _smtp._tls."],
                recommendations=["Consolide o TLS-RPT em um unico registro TXT valido."],
            )

        tags = self._parse_semicolon_tags(records[0], expected_prefix="v=tlsrptv1")
        rua = [item.strip() for item in (tags.get("rua") or "").split(",") if item.strip()]
        warnings: list[str] = []
        if not rua:
            warnings.append("O TLS-RPT existe, mas nao define destinos rua.")
        invalid_uris = [item for item in rua if not item.startswith(("mailto:", "https://"))]
        if invalid_uris:
            warnings.append("O TLS-RPT deveria usar destinos mailto: ou https://.")

        return TLSRPTResult(
            checked_name=checked_name,
            status="presente" if not warnings else "invalido",
            records=records,
            effective_record=records[0],
            rua=rua,
            message=(
                "SMTP TLS Reporting publicado com destinos de relatorio configurados."
                if rua and not invalid_uris
                else "O registro TLS-RPT foi localizado, mas precisa de revisao."
            ),
            warnings=warnings,
            recommendations=(
                ["Confirme que os destinos TLS-RPT realmente recebem relatorios agregados."]
                if rua
                else ["Adicione ao menos um destino rua valido ao TLS-RPT."]
            ),
        )

    def _analyze_bimi(self, domain: str, *, dmarc_result: DMARCCheckResult) -> BIMIResult:
        checked_name = f"default._bimi.{domain}"
        try:
            txt_records = self.dns_service.get_txt_records(checked_name, missing_on_nxdomain=True)
        except DNSLookupError as exc:
            return BIMIResult(
                checked_name=checked_name,
                status="desconhecido",
                lookup_error=str(exc),
                message="A consulta de BIMI nao foi concluida por indisponibilidade temporaria de DNS.",
            )

        records = [item.strip() for item in txt_records if item.strip().lower().startswith("v=bimi1")]
        if not records:
            return BIMIResult(
                checked_name=checked_name,
                status="ausente",
                readiness="desconhecido",
                message="Nenhum registro BIMI foi encontrado no selector default.",
            )
        if len(records) > 1:
            return BIMIResult(
                checked_name=checked_name,
                status="invalido",
                readiness="desconhecido",
                message="Foram encontrados multiplos registros BIMI, o que e inconsistente.",
                warnings=["Mantenha apenas um registro BIMI valido por selector."],
            )

        tags = self._parse_semicolon_tags(records[0], expected_prefix="v=bimi1")
        location = tags.get("l")
        authority = tags.get("a")
        warnings: list[str] = []
        recommendations: list[str] = []

        if not location:
            warnings.append("O BIMI deveria declarar l= com a localizacao do logotipo.")
        dmarc_dependency = self._bimi_dmarc_dependency(dmarc_result)
        readiness = self._bimi_readiness(location=location, authority=authority, dmarc_result=dmarc_result)

        if readiness in {"nao_pronto", "desconhecido"}:
            recommendations.append("BIMI depende de DMARC com enforcement consistente e pct efetivo.")
        elif readiness == "parcial":
            recommendations.append("Revise VMC/authority e requisitos do provedor de mailbox antes de considerar BIMI pronto.")

        return BIMIResult(
            checked_name=checked_name,
            status="presente" if not warnings else "invalido",
            effective_record=records[0],
            location=location,
            authority=authority,
            readiness=readiness,
            dmarc_dependency=dmarc_dependency,
            message=self._bimi_message(readiness),
            warnings=warnings,
            recommendations=recommendations,
        )

    @staticmethod
    def _analyze_dnssec(domain: str) -> DNSSECResult:
        return DNSSECResult(
            checked_name=domain,
            status="nao_implementado",
            message="A checagem DNSSEC ainda nao esta integrada de forma coesa ao fluxo principal.",
            notes=["A base de schema e apresentacao ja esta pronta para uma etapa futura dedicada."],
        )

    @staticmethod
    def _parse_semicolon_tags(record: str, *, expected_prefix: str) -> dict[str, str]:
        tags: dict[str, str] = {}
        parts = [part.strip() for part in record.split(";") if part.strip()]
        for part in parts:
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
        if "v" not in tags and record.lower().startswith(expected_prefix):
            prefix_key, prefix_value = expected_prefix.split("=", 1)
            tags[prefix_key] = prefix_value.upper()
        return tags

    @staticmethod
    def _parse_line_tags(policy_text: str) -> dict[str, str | list[str]]:
        parsed: dict[str, str | list[str]] = {}
        mx_patterns: list[str] = []
        for raw_line in policy_text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            key, value = line.split(":", 1)
            normalized_key = key.strip().lower()
            normalized_value = value.strip()
            if normalized_key == "mx":
                mx_patterns.append(normalized_value)
                continue
            parsed[normalized_key] = normalized_value
        if mx_patterns:
            parsed["mx"] = mx_patterns
        return parsed

    @staticmethod
    def _parse_int(value: str | None) -> int | None:
        if value is None or not value:
            return None
        try:
            return int(value)
        except ValueError:
            return None

    @staticmethod
    def _default_fetch_policy(url: str, timeout_seconds: float) -> str:
        req = request.Request(url, headers={"Accept": "text/plain"})
        try:
            with request.urlopen(req, timeout=timeout_seconds) as response:
                return response.read().decode("utf-8", errors="replace")
        except error.HTTPError as exc:
            raise RuntimeError(f"HTTP {exc.code}") from exc
        except error.URLError as exc:
            raise RuntimeError(str(exc.reason)) from exc

    @staticmethod
    def _bimi_readiness(*, location: str | None, authority: str | None, dmarc_result: DMARCCheckResult) -> str:
        if dmarc_result.status != "presente" or dmarc_result.policy not in {"quarantine", "reject"}:
            return "nao_pronto"
        if dmarc_result.pct is not None and dmarc_result.pct < 100:
            return "nao_pronto"
        if location and authority:
            return "provavel"
        if location:
            return "parcial"
        return "desconhecido"

    @staticmethod
    def _bimi_dmarc_dependency(dmarc_result: DMARCCheckResult) -> str:
        if dmarc_result.status != "presente":
            return "BIMI depende de um registro DMARC valido."
        if dmarc_result.policy not in {"quarantine", "reject"}:
            return "BIMI normalmente requer DMARC com p=quarantine ou p=reject."
        if dmarc_result.pct is not None and dmarc_result.pct < 100:
            return "BIMI costuma exigir DMARC com pct=100 para readiness real."
        return "Dependencia DMARC atendida de forma basica."

    @staticmethod
    def _bimi_message(readiness: str) -> str:
        if readiness == "provavel":
            return "BIMI parece encaminhado para readiness, mas ainda depende do ecossistema de mailbox e de validacoes externas."
        if readiness == "parcial":
            return "BIMI foi localizado, mas a readiness ainda e parcial."
        if readiness == "nao_pronto":
            return "BIMI foi localizado, mas ainda nao parece pronto por dependencia de DMARC ou metadados ausentes."
        return "BIMI foi localizado, mas o estado ainda e inconclusivo."
