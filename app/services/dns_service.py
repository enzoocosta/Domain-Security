from dataclasses import dataclass

from dns.exception import DNSException
from dns.resolver import LifetimeTimeout, NXDOMAIN, NoNameservers, Resolver

from app.core.config import settings
from app.core.exceptions import DNSDomainNotFoundError, DNSNoResponseError, DNSTimeoutError


@dataclass(frozen=True)
class MXRecordValue:
    preference: int
    exchange: str


class DNSLookupService:
    """Access layer for DNS lookups via dnspython."""

    def __init__(self, timeout_seconds: float | None = None) -> None:
        self.resolver = Resolver(configure=True)
        timeout = timeout_seconds or settings.dns_timeout_seconds
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def get_mx_records(self, domain: str) -> list[MXRecordValue]:
        answer = self._resolve(domain, "MX")
        if answer is None or answer.rrset is None:
            return []

        records = [
            MXRecordValue(
                preference=record.preference,
                exchange=self._exchange_to_text(record.exchange),
            )
            for record in answer
        ]
        return sorted(records, key=lambda item: (item.preference, item.exchange))

    def get_txt_records(self, name: str, *, missing_on_nxdomain: bool = False) -> list[str]:
        answer = self._resolve(name, "TXT", missing_on_nxdomain=missing_on_nxdomain)
        if answer is None or answer.rrset is None:
            return []
        return [self._txt_record_to_text(record) for record in answer]

    def _resolve(self, name: str, record_type: str, *, missing_on_nxdomain: bool = False):
        try:
            return self.resolver.resolve(
                name,
                record_type,
                search=False,
                raise_on_no_answer=False,
            )
        except NXDOMAIN as exc:
            if missing_on_nxdomain:
                return None
            raise DNSDomainNotFoundError(
                f"O dominio '{name}' nao foi encontrado no DNS."
            ) from exc
        except LifetimeTimeout as exc:
            raise DNSTimeoutError(
                f"A consulta DNS para '{name}' excedeu o tempo limite configurado."
            ) from exc
        except NoNameservers as exc:
            raise DNSNoResponseError(
                f"O dominio '{name}' nao retornou uma resposta DNS utilizavel."
            ) from exc
        except DNSException as exc:
            raise DNSNoResponseError(
                f"Nao foi possivel obter resposta DNS para '{name}'."
            ) from exc

    @staticmethod
    def _txt_record_to_text(record) -> str:
        strings = getattr(record, "strings", None)
        if strings is not None:
            return "".join(part.decode("utf-8", errors="replace") for part in strings)
        return record.to_text().replace('" "', "").strip('"')

    @staticmethod
    def _exchange_to_text(exchange) -> str:
        raw_value = exchange.to_text()
        if raw_value == ".":
            return "."
        return exchange.to_text(omit_final_dot=True)
