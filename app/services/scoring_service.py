from dataclasses import dataclass

from app.schemas.analysis import AnalysisChecks, OverallSeverity, ScoreBreakdown


@dataclass(frozen=True)
class ScoreOutcome:
    score: int
    severity: OverallSeverity
    breakdown: ScoreBreakdown


class ScoringService:
    """Calculates the weighted overall score for the analysis."""

    WEIGHTS = {
        "dns_score": 10,
        "mx_score": 15,
        "spf_score": 20,
        "dkim_score": 20,
        "dmarc_score": 25,
        "consistency_score": 10,
    }

    def calculate(self, checks: AnalysisChecks) -> ScoreOutcome:
        breakdown = ScoreBreakdown(
            dns_score=self._score_dns(),
            mx_score=self._score_mx(checks),
            spf_score=self._score_spf(checks),
            dkim_score=self._score_dkim(checks),
            dmarc_score=self._score_dmarc(checks),
            consistency_score=self._score_consistency(checks),
        )
        weighted_sum = sum(
            getattr(breakdown, field_name) * weight
            for field_name, weight in self.WEIGHTS.items()
        )
        overall_score = round(weighted_sum / sum(self.WEIGHTS.values()))
        return ScoreOutcome(
            score=overall_score,
            severity=self._classify_severity(overall_score),
            breakdown=breakdown,
        )

    @staticmethod
    def _score_dns() -> int:
        return 100

    @staticmethod
    def _score_mx(checks: AnalysisChecks) -> int:
        if checks.mx.lookup_error:
            return 50
        if checks.mx.status == "presente":
            return 100
        if checks.mx.status == "ausente":
            return 35
        return 10

    @staticmethod
    def _score_spf(checks: AnalysisChecks) -> int:
        spf = checks.spf
        if spf.lookup_error:
            return 50
        if spf.status == "ausente":
            return 0
        if spf.status == "invalido":
            return 10
        if spf.final_all == "+all":
            return 5
        if spf.final_all == "?all":
            return 30
        if spf.final_all == "~all":
            return 70
        if spf.final_all == "-all":
            if any("ptr" in risk.lower() for risk in spf.risks):
                return 90
            return 95
        return 40

    @staticmethod
    def _score_dkim(checks: AnalysisChecks) -> int:
        dkim = checks.dkim
        if dkim.status == "confirmado_presente":
            return 100
        if dkim.status == "provavelmente_presente":
            return 75
        if dkim.status == "desconhecido":
            return 50
        if dkim.status == "provavelmente_ausente":
            return 25
        return 10

    @staticmethod
    def _score_dmarc(checks: AnalysisChecks) -> int:
        dmarc = checks.dmarc
        if dmarc.lookup_error:
            return 50
        if dmarc.status == "ausente":
            return 0
        if dmarc.status == "invalido":
            return 10
        if dmarc.policy == "none":
            score = 45
            if dmarc.rua or dmarc.ruf:
                score += 5
            if dmarc.pct == 100:
                score += 5
            return min(score, 55)
        if dmarc.policy == "quarantine":
            score = 70
            if dmarc.rua or dmarc.ruf:
                score += 5
            if dmarc.pct == 100:
                score += 5
            if dmarc.adkim == "s" or dmarc.aspf == "s":
                score += 5
            return min(score, 85)
        if dmarc.policy == "reject":
            score = 90
            if dmarc.rua or dmarc.ruf:
                score += 4
            if dmarc.pct == 100:
                score += 3
            if dmarc.adkim == "s":
                score += 1
            if dmarc.aspf == "s":
                score += 2
            return min(score, 100)
        return 10

    def _score_consistency(self, checks: AnalysisChecks) -> int:
        if checks.mx.lookup_error or checks.spf.lookup_error or checks.dmarc.lookup_error:
            return 60
        score = 100

        if checks.mx.is_null_mx:
            if checks.spf.status == "ausente":
                score -= 20
            elif checks.spf.final_all in {"+all", "?all"}:
                score -= 40
            elif checks.spf.final_all == "~all":
                score -= 10
            elif checks.spf.final_all is None:
                score -= 15

            if checks.dmarc.policy == "none":
                score -= 15
            elif checks.dmarc.status == "ausente":
                score -= 25
            elif checks.dmarc.status == "invalido":
                score -= 20

            if checks.dkim.status == "invalido":
                score -= 10
            elif checks.dkim.status == "desconhecido":
                score -= 5
            return self._clamp_score(score)

        if checks.mx.accepts_mail:
            score -= self._spf_consistency_penalty(checks)
            score -= self._dmarc_consistency_penalty(checks)
            score -= self._dkim_consistency_penalty(checks)
            return self._clamp_score(score)

        score = 60
        if checks.spf.status == "ausente":
            score -= 20
        elif checks.spf.final_all in {"+all", "?all"}:
            score -= 15
        if checks.dmarc.status == "ausente":
            score -= 20
        elif checks.dmarc.status == "invalido":
            score -= 15
        return self._clamp_score(score)

    @staticmethod
    def _spf_consistency_penalty(checks: AnalysisChecks) -> int:
        if checks.spf.status == "ausente":
            return 35
        if checks.spf.status == "invalido":
            return 30
        if checks.spf.final_all == "+all":
            return 45
        if checks.spf.final_all == "?all":
            return 30
        if checks.spf.final_all == "~all":
            return 15
        if checks.spf.final_all is None:
            return 25
        return 0

    @staticmethod
    def _dmarc_consistency_penalty(checks: AnalysisChecks) -> int:
        if checks.dmarc.status == "ausente":
            return 35
        if checks.dmarc.status == "invalido":
            return 30
        if checks.dmarc.policy == "none":
            return 20
        if checks.dmarc.policy == "quarantine":
            return 10
        return 0

    @staticmethod
    def _dkim_consistency_penalty(checks: AnalysisChecks) -> int:
        if checks.dkim.status == "invalido":
            return 20
        if checks.dkim.status == "provavelmente_ausente":
            return 25
        if checks.dkim.status == "desconhecido":
            return 10
        return 0

    @staticmethod
    def _clamp_score(score: int) -> int:
        return max(0, min(100, score))

    @staticmethod
    def _classify_severity(score: int) -> OverallSeverity:
        if score >= 90:
            return "excelente"
        if score >= 75:
            return "bom"
        if score >= 60:
            return "atencao"
        if score >= 40:
            return "alto"
        return "critico"
