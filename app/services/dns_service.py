from dataclasses import dataclass
from ipaddress import ip_address

from dns.exception import DNSException
from dns.reversename import from_address
from dns.resolver import LifetimeTimeout, NXDOMAIN, NoNameservers, Resolver

from app.core.config import settings
from app.core.exceptions import (
    DNSDomainNotFoundError,
    DNSNoResponseError,
    DNSTimeoutError,
)


@dataclass(frozen=True)
class MXRecordValue:
    preference: int
    exchange: str


@dataclass(frozen=True)
class IPAddressValue:
    address: str
    version: str
    source_record_type: str
    is_public: bool


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

    def get_txt_records(
        self, name: str, *, missing_on_nxdomain: bool = False
    ) -> list[str]:
        answer = self._resolve(name, "TXT", missing_on_nxdomain=missing_on_nxdomain)
        if answer is None or answer.rrset is None:
            return []
        return [self._txt_record_to_text(record) for record in answer]

    def get_ip_records(self, domain: str) -> list[IPAddressValue]:
        records: list[IPAddressValue] = []
        for record_type, version in (("A", "ipv4"), ("AAAA", "ipv6")):
            answer = self._resolve(domain, record_type)
            if answer is None or answer.rrset is None:
                continue
            for record in answer:
                address = record.to_text()
                parsed = ip_address(address)
                records.append(
                    IPAddressValue(
                        address=address,
                        version=version,
                        source_record_type=record_type,
                        is_public=parsed.is_global,
                    )
                )
        return records

    def get_reverse_dns(self, address: str) -> str | None:
        answer = self._resolve(
            str(from_address(address)), "PTR", missing_on_nxdomain=True
        )
        if answer is None or answer.rrset is None:
            return None
        for record in answer:
            value = record.to_text().rstrip(".")
            if value:
                return value
        return None

    def _resolve(
        self, name: str, record_type: str, *, missing_on_nxdomain: bool = False
    ):
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
