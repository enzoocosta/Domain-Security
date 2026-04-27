from app.services.email_auth_service import EmailAuthenticationService
from app.services.email_policy_service import EmailPolicyService
from tests.fakes import StubDNSService


def test_spf_lookup_counting_tracks_nested_include_and_mechanisms():
    service = EmailAuthenticationService()
    dns_service = StubDNSService(
        mx_records=[],
        ip_records=[],
        txt_records={
            "_spf.example.net": ["v=spf1 include:_spf.child.example.net -all"],
            "_spf.child.example.net": ["v=spf1 a:mail.example.net -all"],
        },
    )

    result = service.analyze_spf(
        "example.com",
        ["v=spf1 include:_spf.example.net mx -all"],
        dns_service=dns_service,
    )

    assert result.lookup_count_status == "exato"
    assert result.lookup_count == 4
    assert result.void_lookup_count == 2
    assert result.lookup_limit_exceeded is False
    assert result.lookup_chain[:3] == [
        "include:_spf.example.net",
        "include:_spf.child.example.net",
        "a:mail.example.net",
    ]


def test_mta_sts_analysis_parses_dns_and_policy():
    dns_service = StubDNSService(
        txt_records={
            "_mta-sts.example.com": ["v=STSv1; id=20260420"],
        },
    )
    service = EmailPolicyService(
        dns_service=dns_service,
        policy_fetcher=lambda url, timeout: (
            "version: STSv1\nmode: enforce\nmax_age: 86400\nmx: mail.example.com\n"
        ),
    )

    result = service.analyze(
        "example.com",
        dmarc_result=EmailAuthenticationService().analyze_dmarc(
            "_dmarc.example.com",
            ["v=DMARC1; p=reject; pct=100"],
        ),
    )

    assert result.mta_sts.status == "presente"
    assert result.mta_sts.mode == "enforce"
    assert result.mta_sts.policy_id == "20260420"
    assert result.mta_sts.mx_patterns == ["mail.example.com"]


def test_tls_rpt_and_bimi_readiness_are_reported_honestly():
    dns_service = StubDNSService(
        txt_records={
            "_smtp._tls.example.com": [
                "v=TLSRPTv1; rua=mailto:tls@example.com,https://reports.example.com"
            ],
            "default._bimi.example.com": ["v=BIMI1; l=https://example.com/logo.svg"],
        },
    )
    dmarc = EmailAuthenticationService().analyze_dmarc(
        "_dmarc.example.com",
        ["v=DMARC1; p=quarantine; pct=100"],
    )
    service = EmailPolicyService(dns_service=dns_service)

    result = service.analyze("example.com", dmarc_result=dmarc)

    assert result.tls_rpt.status == "presente"
    assert result.tls_rpt.rua == [
        "mailto:tls@example.com",
        "https://reports.example.com",
    ]
    assert result.bimi.status == "presente"
    assert result.bimi.readiness == "parcial"
    assert "DMARC" in result.bimi.dmarc_dependency
