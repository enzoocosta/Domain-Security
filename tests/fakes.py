from app.services.dns_service import MXRecordValue
from app.schemas.analysis import DomainRegistrationResult, EmailTLSResult, WebsiteTLSResult


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

    def get_mx_records(self, domain: str) -> list[MXRecordValue]:
        if self.mx_exception is not None:
            raise self.mx_exception
        return list(self.mx_records)

    def get_txt_records(self, name: str, *, missing_on_nxdomain: bool = False) -> list[str]:
        exception = self.txt_exceptions.get(name)
        if exception is not None:
            raise exception
        return list(self.txt_records.get(name, []))


class StubWebsiteTLSService:
    def __init__(self, result: WebsiteTLSResult) -> None:
        self.result = result

    def analyze(self, domain: str) -> WebsiteTLSResult:
        return self.result


class StubEmailTLSService:
    def __init__(self, result: EmailTLSResult) -> None:
        self.result = result

    def analyze(self, mx_records: list[MXRecordValue]) -> EmailTLSResult:
        return self.result


class StubDomainRegistrationService:
    def __init__(self, result: DomainRegistrationResult) -> None:
        self.result = result

    def analyze(self, domain: str) -> DomainRegistrationResult:
        return self.result
