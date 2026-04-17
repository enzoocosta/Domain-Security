from app.services.dns_service import MXRecordValue
from app.schemas.analysis import AnalysisResponse, DomainRegistrationResult, EmailTLSResult, WebsiteTLSResult
from app.schemas.history import AnalysisDiffSummary, DomainHistoryResponse


class StubDNSService:
    def __init__(
        self,
        *,
        mx_records: list[MXRecordValue] | None = None,
        txt_records: dict[str, list[str]] | None = None,
        mx_exception: Exception | None = None,
        txt_exceptions: dict[str, Exception] | None = None,
    ) -> None:
        self.mx_records = mx_records or []
        self.txt_records = txt_records or {}
        self.mx_exception = mx_exception
        self.txt_exceptions = txt_exceptions or {}
        self.mx_call_count = 0
        self.txt_call_count = 0

    def get_mx_records(self, domain: str) -> list[MXRecordValue]:
        self.mx_call_count += 1
        if self.mx_exception is not None:
            raise self.mx_exception
        return list(self.mx_records)

    def get_txt_records(self, name: str, *, missing_on_nxdomain: bool = False) -> list[str]:
        self.txt_call_count += 1
        exception = self.txt_exceptions.get(name)
        if exception is not None:
            raise exception
        return list(self.txt_records.get(name, []))


class StubWebsiteTLSService:
    def __init__(self, result: WebsiteTLSResult) -> None:
        self.result = result
        self.call_count = 0

    def analyze(self, domain: str) -> WebsiteTLSResult:
        self.call_count += 1
        return self.result


class StubEmailTLSService:
    def __init__(self, result: EmailTLSResult) -> None:
        self.result = result
        self.call_count = 0

    def analyze(self, mx_records: list[MXRecordValue]) -> EmailTLSResult:
        self.call_count += 1
        return self.result


class StubDomainRegistrationService:
    def __init__(self, result: DomainRegistrationResult) -> None:
        self.result = result
        self.call_count = 0

    def analyze(self, domain: str) -> DomainRegistrationResult:
        self.call_count += 1
        return self.result


class StubAnalysisHistoryService:
    def __init__(
        self,
        *,
        diff: AnalysisDiffSummary | None = None,
        history_response: DomainHistoryResponse | None = None,
    ) -> None:
        self.diff = diff
        self.history_response = history_response
        self.record_call_count = 0

    def record_analysis(self, result: AnalysisResponse, *, input_target: str) -> AnalysisResponse:
        self.record_call_count += 1
        diff = self.diff or AnalysisDiffSummary(
            has_previous_snapshot=False,
            message="Esta e a primeira analise salva para este dominio.",
            current_score=result.score,
            current_severity=result.severity,
        )
        return result.model_copy(update={"changes": diff})

    def list_history(self, domain: str, *, limit: int = 20) -> DomainHistoryResponse:
        if self.history_response is not None:
            return self.history_response
        return DomainHistoryResponse(domain=domain, items=[])
