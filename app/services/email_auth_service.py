import re
from dataclasses import dataclass

from app.schemas.analysis import DMARCCheckResult, DKIMCheckResult, SPFCheckResult
from app.services.dns_service import DNSLookupService


SPF_ALL_RE = re.compile(r"^(?P<qualifier>[+\-~?])?all$", re.IGNORECASE)
COMMON_DKIM_SELECTORS = (
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "dkim",
    "mail",
    "s1",
)


@dataclass
class SPFLookupAnalysis:
    lookup_count: int = 0
    void_lookup_count: int = 0
    status: str = "exato"
    limit_exceeded: bool = False
    lookup_chain: list[str] | None = None
    risks: list[str] | None = None

    def __post_init__(self) -> None:
        if self.lookup_chain is None:
            self.lookup_chain = []
        if self.risks is None:
            self.risks = []


class EmailAuthenticationService:
    """Parses and classifies email-authentication records."""

    def __init__(self, dkim_selectors: tuple[str, ...] | None = None) -> None:
        self.dkim_selectors = dkim_selectors or COMMON_DKIM_SELECTORS

    def analyze_spf(
        self,
        domain: str,
        txt_records: list[str],
        dns_service: DNSLookupService | None = None,
    ) -> SPFCheckResult:
        spf_records = self._filter_policy_records(txt_records, "v=spf1")
        if not spf_records:
            return SPFCheckResult(
                checked_name=domain,
                status="ausente",
                message="Nenhum registro SPF foi encontrado no dominio.",
            )
        if len(spf_records) > 1:
            return SPFCheckResult(
                checked_name=domain,
                status="invalido",
                message="Foram encontrados multiplos registros SPF, o que e invalido.",
                records=spf_records,
                risks=["Multiplos registros SPF publicados."],
            )

        record = spf_records[0]
        terms = self._split_terms(record)
        final_all = self._extract_terminal_all(terms)
        lookup_candidates = self._extract_lookup_candidates(terms)
        risks = self._collect_spf_risks(terms, final_all)
        posture = self._classify_spf_posture(final_all)
        lookup_analysis = (
            self._analyze_spf_lookups(domain, record, dns_service)
            if dns_service is not None
            else SPFLookupAnalysis(status="nao_implementado")
        )
        risks.extend(lookup_analysis.risks)
        message = self._build_spf_message(
            final_all,
            posture,
            risks,
            lookup_analysis=lookup_analysis,
        )

        return SPFCheckResult(
            checked_name=domain,
            status="presente",
            message=message,
            records=spf_records,
            effective_record=record,
            final_all=final_all,
            posture=posture,
            risks=risks,
            lookup_count=lookup_analysis.lookup_count if lookup_analysis.status != "nao_implementado" else None,
            lookup_count_status=lookup_analysis.status,
            void_lookup_count=(
                lookup_analysis.void_lookup_count
                if lookup_analysis.status != "nao_implementado"
                else None
            ),
            void_lookup_count_status=lookup_analysis.status,
            lookup_limit_exceeded=lookup_analysis.limit_exceeded,
            lookup_candidates=lookup_candidates,
            lookup_chain=lookup_analysis.lookup_chain,
        )

    def analyze_dmarc(self, checked_name: str, txt_records: list[str]) -> DMARCCheckResult:
        dmarc_records = self._filter_policy_records(txt_records, "v=dmarc1")
        if not dmarc_records:
            return DMARCCheckResult(
                checked_name=checked_name,
                status="ausente",
                message="Nenhum registro DMARC foi encontrado.",
            )
        if len(dmarc_records) > 1:
            return DMARCCheckResult(
                checked_name=checked_name,
                status="invalido",
                message="Foram encontrados multiplos registros DMARC, o que e invalido.",
                records=dmarc_records,
                risks=["Multiplos registros DMARC publicados."],
            )

        record = dmarc_records[0]
        try:
            tags = self._parse_dmarc_tags(record)
            policy = self._validate_dmarc_policy(tags.get("p"))
            pct = self._parse_dmarc_pct(tags.get("pct"))
            adkim = self._parse_alignment_mode(tags.get("adkim"), default="r")
            aspf = self._parse_alignment_mode(tags.get("aspf"), default="r")
        except ValueError as exc:
            return DMARCCheckResult(
                checked_name=checked_name,
                status="invalido",
                message=str(exc),
                records=dmarc_records,
                effective_record=record,
                risks=[str(exc)],
            )

        rua = self._split_dmarc_uri_list(tags.get("rua"))
        ruf = self._split_dmarc_uri_list(tags.get("ruf"))
        policy_strength = self._classify_dmarc_strength(policy, pct)
        risks = self._collect_dmarc_risks(policy, rua, ruf, pct, adkim, aspf)

        return DMARCCheckResult(
            checked_name=checked_name,
            status="presente",
            message=self._build_dmarc_message(policy, policy_strength, pct),
            records=dmarc_records,
            effective_record=record,
            policy=policy,
            rua=rua,
            ruf=ruf,
            pct=pct,
            adkim=adkim,
            aspf=aspf,
            policy_strength=policy_strength,
            risks=risks,
        )

    def analyze_dkim(self, domain: str, dns_service: DNSLookupService) -> DKIMCheckResult:
        checked_names: list[str] = []
        selectors_with_records: list[str] = []
        valid_records: list[str] = []
        invalid_records: list[str] = []

        for selector in self.dkim_selectors:
            name = f"{selector}._domainkey.{domain}"
            checked_names.append(name)
            txt_records = dns_service.get_txt_records(name, missing_on_nxdomain=True)
            if not txt_records:
                continue

            selectors_with_records.append(selector)
            for record in txt_records:
                normalized = record.strip()
                if normalized.lower().startswith("v=dkim1"):
                    valid_records.append(normalized)
                elif self._looks_like_dkim_material(normalized):
                    invalid_records.append(normalized)

        if valid_records:
            return DKIMCheckResult(
                checked_name=domain,
                status="provavelmente_presente",
                message="A heuristica encontrou registros DKIM em selectors comuns.",
                checked_selectors=checked_names,
                selectors_with_records=selectors_with_records,
                records=valid_records,
                heuristic=True,
                confidence_note=(
                    "A deteccao foi feita por heuristica de selectors comuns; "
                    "a confirmacao plena depende de headers reais de e-mail."
                ),
            )

        if invalid_records:
            return DKIMCheckResult(
                checked_name=domain,
                status="invalido",
                message="Foram encontrados registros candidatos a DKIM com formato inconsistente.",
                checked_selectors=checked_names,
                selectors_with_records=selectors_with_records,
                records=invalid_records,
                heuristic=True,
                confidence_note=(
                    "Sem headers reais, o diagnostico continua heuristico; "
                    "os registros encontrados merecem revisao manual."
                ),
            )

        return DKIMCheckResult(
            checked_name=domain,
            status="desconhecido",
            message="Nenhum selector comum confirmou DKIM; a ausencia nao pode ser assumida.",
            checked_selectors=checked_names,
            selectors_with_records=[],
            records=[],
            heuristic=True,
            confidence_note=(
                "DKIM depende do selector usado na assinatura. Sem headers reais, "
                "o resultado permanece inconclusivo."
            ),
        )

    @staticmethod
    def _filter_policy_records(records: list[str], prefix: str) -> list[str]:
        normalized_prefix = prefix.lower()
        return [record.strip() for record in records if record.strip().lower().startswith(normalized_prefix)]

    @staticmethod
    def _split_terms(record: str) -> list[str]:
        return [part.strip() for part in record.split() if part.strip()]

    @staticmethod
    def _extract_terminal_all(terms: list[str]):
        if len(terms) < 2:
            return None
        match = SPF_ALL_RE.fullmatch(terms[-1])
        if match is None:
            return None
        qualifier = match.group("qualifier") or "+"
        return f"{qualifier}all"

    @staticmethod
    def _extract_lookup_candidates(terms: list[str]) -> list[str]:
        candidates: list[str] = []
        for term in terms:
            normalized = term.lower()
            if normalized.startswith(("include:", "redirect=", "exists:")):
                candidates.append(term)
                continue
            if normalized in {"a", "mx", "ptr"}:
                candidates.append(term)
                continue
            if normalized.startswith(("a:", "a/", "mx:", "mx/")):
                candidates.append(term)
        return candidates

    def _collect_spf_risks(self, terms: list[str], final_all: str | None) -> list[str]:
        risks: list[str] = []
        all_terms = [term for term in terms[1:] if SPF_ALL_RE.fullmatch(term)]

        if final_all is None:
            if all_terms:
                risks.append("O mecanismo all existe, mas nao aparece na posicao final do SPF.")
            else:
                risks.append("O registro SPF nao termina com um mecanismo all.")

        if len(all_terms) > 1:
            risks.append("O registro SPF contem mais de um mecanismo all.")
        if final_all == "+all":
            risks.append("O SPF permite qualquer remetente (+all).")
        elif final_all == "?all":
            risks.append("O SPF usa neutral (?all), sem bloqueio efetivo.")
        elif final_all == "~all":
            risks.append("O SPF usa softfail (~all), com aplicacao parcial.")
        if any(term.lower() == "ptr" for term in terms):
            risks.append("O SPF usa ptr, mecanismo desencorajado.")
        return risks

    @staticmethod
    def _classify_spf_posture(final_all: str | None) -> str:
        if final_all in {"-all", "~all"}:
            return "restritivo"
        if final_all in {"+all", "?all"}:
            return "permissivo"
        return "desconhecido"

    @staticmethod
    def _build_spf_message(
        final_all: str | None,
        posture: str,
        risks: list[str],
        *,
        lookup_analysis: SPFLookupAnalysis,
    ) -> str:
        lookup_suffix = ""
        if lookup_analysis.status != "nao_implementado":
            lookup_suffix = f" Foram contadas {lookup_analysis.lookup_count} consulta(s) SPF."
            if lookup_analysis.void_lookup_count:
                lookup_suffix += f" Void lookups observados: {lookup_analysis.void_lookup_count}."
            if lookup_analysis.limit_exceeded:
                lookup_suffix += " O limite de 10 consultas DNS foi excedido."
            elif lookup_analysis.status == "estimado":
                lookup_suffix += " A contagem ficou parcialmente estimada por macros ou ptr."
        if final_all is None:
            return "O dominio publica SPF, mas sem um mecanismo all terminal claramente definido." + lookup_suffix
        if posture in {"restritivo", "permissivo"}:
            return f"O dominio publica SPF {final_all} com postura {posture}." + lookup_suffix
        if risks:
            return risks[0] + lookup_suffix
        return "O dominio publica SPF." + lookup_suffix

    @staticmethod
    def _parse_dmarc_tags(record: str) -> dict[str, str]:
        tags: dict[str, str] = {}
        parts = [part.strip() for part in record.split(";") if part.strip()]
        for part in parts:
            if "=" not in part:
                raise ValueError("O registro DMARC possui tags malformadas.")
            key, value = part.split("=", 1)
            normalized_key = key.strip().lower()
            normalized_value = value.strip()
            if normalized_key in tags:
                raise ValueError("O registro DMARC possui tags duplicadas.")
            tags[normalized_key] = normalized_value
        return tags

    @staticmethod
    def _validate_dmarc_policy(policy: str | None) -> str:
        if policy is None:
            raise ValueError("O registro DMARC existe, mas nao define a politica obrigatoria p=.")
        normalized_policy = policy.lower()
        if normalized_policy not in {"none", "quarantine", "reject"}:
            raise ValueError("O registro DMARC possui uma politica p= invalida.")
        return normalized_policy

    @staticmethod
    def _parse_dmarc_pct(value: str | None) -> int:
        if value is None or not value:
            return 100
        try:
            pct = int(value)
        except ValueError as exc:
            raise ValueError("O registro DMARC possui pct invalido.") from exc
        if pct < 0 or pct > 100:
            raise ValueError("O registro DMARC possui pct fora do intervalo 0-100.")
        return pct

    @staticmethod
    def _parse_alignment_mode(value: str | None, *, default: str) -> str:
        if value is None or not value:
            return default
        normalized = value.lower()
        if normalized not in {"r", "s"}:
            raise ValueError("O registro DMARC possui modo de alinhamento invalido.")
        return normalized

    @staticmethod
    def _split_dmarc_uri_list(value: str | None) -> list[str]:
        if value is None or not value:
            return []
        return [item.strip() for item in value.split(",") if item.strip()]

    @staticmethod
    def _classify_dmarc_strength(policy: str, pct: int) -> str:
        if policy == "none":
            return "fraco"
        if policy == "quarantine":
            return "intermediario"
        if policy == "reject" and pct == 100:
            return "forte"
        if policy == "reject":
            return "intermediario"
        return "desconhecido"

    @staticmethod
    def _collect_dmarc_risks(
        policy: str,
        rua: list[str],
        ruf: list[str],
        pct: int,
        adkim: str,
        aspf: str,
    ) -> list[str]:
        risks: list[str] = []
        if policy == "none":
            risks.append("A politica DMARC esta apenas em modo de monitoramento (p=none).")
        if pct < 100:
            risks.append("A politica DMARC se aplica apenas a parte das mensagens (pct<100).")
        if not rua and not ruf:
            risks.append("O DMARC nao publica destinos de relatorio rua ou ruf.")
        if adkim == "r" and aspf == "r":
            risks.append("O DMARC usa alinhamento relaxado para SPF e DKIM.")
        return risks

    @staticmethod
    def _build_dmarc_message(policy: str, strength: str, pct: int) -> str:
        return f"O dominio publica DMARC com p={policy}, forca {strength} e pct={pct}."

    @staticmethod
    def _looks_like_dkim_material(record: str) -> bool:
        normalized = record.lower()
        return "dkim" in normalized or "p=" in normalized or "k=" in normalized

    def _analyze_spf_lookups(
        self,
        domain: str,
        record: str,
        dns_service: DNSLookupService,
    ) -> SPFLookupAnalysis:
        analysis = SPFLookupAnalysis()
        self._walk_spf_record(
            domain,
            record,
            dns_service,
            analysis=analysis,
            visited_domains=set(),
        )
        if analysis.lookup_count > 10:
            analysis.limit_exceeded = True
            analysis.risks.append("O SPF excede o limite de 10 consultas DNS.")
        if analysis.void_lookup_count > 2:
            analysis.risks.append("O SPF gera mais de dois void lookups, o que aumenta risco de falha.")
        return analysis

    def _walk_spf_record(
        self,
        domain: str,
        record: str,
        dns_service: DNSLookupService,
        *,
        analysis: SPFLookupAnalysis,
        visited_domains: set[str],
    ) -> None:
        normalized_domain = domain.lower()
        if normalized_domain in visited_domains:
            analysis.risks.append(f"O SPF referencia novamente {domain}, sugerindo loop de avaliacao.")
            analysis.status = "estimado"
            return
        visited_domains.add(normalized_domain)

        terms = self._split_terms(record)
        for term in terms[1:]:
            mechanism = term.lstrip("+-~?")
            lowered = mechanism.lower()
            if lowered.startswith("include:"):
                include_domain = mechanism.split(":", 1)[1]
                analysis.lookup_count += 1
                analysis.lookup_chain.append(f"include:{include_domain}")
                if self._has_macro(include_domain):
                    analysis.status = "estimado"
                    continue
                included_record = self._get_single_spf_record(include_domain, dns_service)
                if included_record is None:
                    analysis.void_lookup_count += 1
                    analysis.risks.append(f"O include {include_domain} nao retornou um SPF utilizavel.")
                    continue
                self._walk_spf_record(
                    include_domain,
                    included_record,
                    dns_service,
                    analysis=analysis,
                    visited_domains=visited_domains.copy(),
                )
                continue

            if lowered.startswith("redirect="):
                redirect_domain = mechanism.split("=", 1)[1]
                analysis.lookup_count += 1
                analysis.lookup_chain.append(f"redirect={redirect_domain}")
                if self._has_macro(redirect_domain):
                    analysis.status = "estimado"
                    continue
                redirected_record = self._get_single_spf_record(redirect_domain, dns_service)
                if redirected_record is None:
                    analysis.void_lookup_count += 1
                    analysis.risks.append(f"O redirect {redirect_domain} nao retornou um SPF utilizavel.")
                    continue
                self._walk_spf_record(
                    redirect_domain,
                    redirected_record,
                    dns_service,
                    analysis=analysis,
                    visited_domains=visited_domains.copy(),
                )
                continue

            if lowered.startswith("exists:"):
                exists_domain = mechanism.split(":", 1)[1]
                analysis.lookup_count += 1
                analysis.lookup_chain.append(f"exists:{exists_domain}")
                if self._has_macro(exists_domain):
                    analysis.status = "estimado"
                    continue
                if not self._has_ip_records(exists_domain, dns_service):
                    analysis.void_lookup_count += 1
                continue

            if lowered == "a" or lowered.startswith("a:") or lowered.startswith("a/"):
                target_domain = self._extract_mechanism_domain(mechanism, fallback_domain=domain, prefix="a")
                analysis.lookup_count += 1
                analysis.lookup_chain.append(f"a:{target_domain}")
                if not self._has_ip_records(target_domain, dns_service):
                    analysis.void_lookup_count += 1
                continue

            if lowered == "mx" or lowered.startswith("mx:") or lowered.startswith("mx/"):
                target_domain = self._extract_mechanism_domain(mechanism, fallback_domain=domain, prefix="mx")
                analysis.lookup_count += 1
                analysis.lookup_chain.append(f"mx:{target_domain}")
                if not self._has_mx_records(target_domain, dns_service):
                    analysis.void_lookup_count += 1
                continue

            if lowered == "ptr" or lowered.startswith("ptr:"):
                analysis.lookup_count += 1
                analysis.lookup_chain.append(mechanism)
                analysis.status = "estimado"

    def _get_single_spf_record(self, domain: str, dns_service: DNSLookupService) -> str | None:
        try:
            records = dns_service.get_txt_records(domain, missing_on_nxdomain=True)
        except DNSLookupError:
            return None
        spf_records = self._filter_policy_records(records, "v=spf1")
        if len(spf_records) != 1:
            return None
        return spf_records[0]

    @staticmethod
    def _has_ip_records(domain: str, dns_service: DNSLookupService) -> bool:
        try:
            return bool(dns_service.get_ip_records(domain))
        except DNSLookupError:
            return False

    @staticmethod
    def _has_mx_records(domain: str, dns_service: DNSLookupService) -> bool:
        try:
            return bool(dns_service.get_mx_records(domain))
        except DNSLookupError:
            return False

    @staticmethod
    def _extract_mechanism_domain(term: str, *, fallback_domain: str, prefix: str) -> str:
        if ":" not in term:
            return fallback_domain
        remainder = term.split(":", 1)[1]
        return remainder.split("/", 1)[0] or fallback_domain

    @staticmethod
    def _has_macro(value: str) -> bool:
        return "%" in value or "{" in value or "}" in value
