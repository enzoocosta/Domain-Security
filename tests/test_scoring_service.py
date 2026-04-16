from app.schemas.analysis import (
    AnalysisChecks,
    DKIMCheckResult,
    DMARCCheckResult,
    MXCheckResult,
    SPFCheckResult,
)
from app.services.scoring_service import ScoringService


def test_scoring_service_weights_categories_and_classifies_severity():
    checks = AnalysisChecks(
        mx=MXCheckResult(
            checked_name="example.com",
            status="presente",
            message="MX ok",
            accepts_mail=True,
        ),
        spf=SPFCheckResult(
            checked_name="example.com",
            status="presente",
            message="SPF ok",
            final_all="-all",
            posture="restritivo",
        ),
        dkim=DKIMCheckResult(
            checked_name="example.com",
            status="provavelmente_presente",
            message="DKIM heuristico",
            confidence_note="heuristica",
        ),
        dmarc=DMARCCheckResult(
            checked_name="_dmarc.example.com",
            status="presente",
            message="DMARC ok",
            policy="reject",
            pct=100,
            adkim="s",
            aspf="s",
            policy_strength="forte",
        ),
    )

    result = ScoringService().calculate(checks)

    assert result.breakdown.spf_score >= 90
    assert result.breakdown.dkim_score == 75
    assert result.breakdown.dmarc_score >= 90
    assert result.score >= 85
    assert result.severity in {"bom", "excelente"}
