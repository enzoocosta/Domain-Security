from app.services.email_auth_service import EmailAuthenticationService
from tests.fakes import StubDNSService


def test_spf_analysis_extracts_final_all_and_lookup_candidates():
    service = EmailAuthenticationService()

    result = service.analyze_spf(
        "example.com",
        ["v=spf1 include:_spf.example.net mx -all"],
    )

    assert result.status == "presente"
    assert result.final_all == "-all"
    assert result.posture == "restritivo"
    assert result.lookup_count_status == "nao_implementado"
    assert result.lookup_candidates == ["include:_spf.example.net", "mx"]


def test_dmarc_analysis_extracts_tags_and_strength():
    service = EmailAuthenticationService()

    result = service.analyze_dmarc(
        "_dmarc.example.com",
        ["v=DMARC1; p=quarantine; pct=100; rua=mailto:d@example.com; adkim=s; aspf=r"],
    )

    assert result.status == "presente"
    assert result.policy == "quarantine"
    assert result.policy_strength == "intermediario"
    assert result.pct == 100
    assert result.rua == ["mailto:d@example.com"]
    assert result.adkim == "s"
    assert result.aspf == "r"


def test_dkim_analysis_is_honest_when_selector_is_unknown():
    service = EmailAuthenticationService(dkim_selectors=("default", "selector1"))
    dns_service = StubDNSService(txt_records={})

    result = service.analyze_dkim("example.com", dns_service)

    assert result.status == "desconhecido"
    assert result.heuristic is True
    assert "nao pode ser assumida" in result.message
