from socket import timeout as SocketTimeout
import smtplib
import socket
import ssl

from app.core.config import settings
from app.schemas.analysis import EmailTLSMXResult, EmailTLSResult
from app.services.dns_service import MXRecordValue
from app.utils.tls_helpers import (
    calculate_days_to_expire,
    certificate_expiry_label,
    format_name,
    parse_certificate_datetime,
)


class EmailTLSService:
    """Checks STARTTLS support on MX hosts."""

    CERTIFICATE_NOTE = "O certificado de e-mail pertence ao servidor MX, nao necessariamente ao dominio principal."

    def __init__(
        self,
        probe_func=None,
        timeout_seconds: float | None = None,
        mx_probe_limit: int | None = None,
    ) -> None:
        self.probe_func = probe_func or self._probe_mx
        self.timeout_seconds = timeout_seconds or settings.email_tls_timeout_seconds
        self.mx_probe_limit = mx_probe_limit or settings.mx_probe_limit

    def analyze(self, mx_records: list[MXRecordValue]) -> EmailTLSResult:
        if not mx_records:
            return EmailTLSResult(
                mx_results=[],
                has_email_tls_data=False,
                total_mx_count=0,
                tested_mx_count=0,
                probe_limited=False,
                message="Nenhum MX foi encontrado para testar STARTTLS.",
                note=self.CERTIFICATE_NOTE,
            )

        prioritized_records = self._select_prioritized_records(mx_records)
        probe_limited = len(prioritized_records) < len(mx_records)
        probe_note = self._build_probe_note(len(prioritized_records), len(mx_records), probe_limited)
        results = [self.probe_func(record.exchange, 25) for record in prioritized_records]
        return EmailTLSResult(
            mx_results=results,
            has_email_tls_data=any(item.has_tls_data for item in results),
            total_mx_count=len(mx_records),
            tested_mx_count=len(prioritized_records),
            probe_limited=probe_limited,
            probe_note=probe_note,
            message=self._build_message(results, len(prioritized_records), len(mx_records), probe_limited),
            note=self.CERTIFICATE_NOTE,
        )

    def _probe_mx(self, host: str, port: int) -> EmailTLSMXResult:
        try:
            return self._run_starttls_probe(host, port, verify=True)
        except ssl.SSLCertVerificationError as exc:
            fallback = self._run_starttls_probe(host, port, verify=False)
            hostname_match = self._hostname_matches(fallback, host)
            return self._serialize_result(
                host=host,
                port=port,
                starttls_supported=True,
                certificate_valid=False,
                certificate=fallback["certificate"],
                tls_version=fallback["tls_version"],
                hostname_match=hostname_match,
                error=f"Falha de validacao do certificado: {exc}",
            )
        except (SocketTimeout, TimeoutError, socket.timeout) as exc:
            return EmailTLSMXResult(
                host=host,
                port=port,
                error=f"Timeout ao testar STARTTLS: {exc}",
            )
        except (ConnectionRefusedError, OSError, smtplib.SMTPException, ssl.SSLError) as exc:
            return EmailTLSMXResult(
                host=host,
                port=port,
                error=f"Falha ao testar STARTTLS: {exc}",
            )

    def _run_starttls_probe(self, host: str, port: int, *, verify: bool) -> dict:
        context = ssl.create_default_context() if verify else ssl._create_unverified_context()
        with smtplib.SMTP(host=host, port=port, timeout=self.timeout_seconds) as client:
            client.ehlo_or_helo_if_needed()
            if not client.has_extn("starttls"):
                return {
                    "starttls_supported": False,
                    "certificate": None,
                    "tls_version": None,
                }

            client.starttls(context=context)
            client.ehlo()
            return {
                "starttls_supported": True,
                "certificate": client.sock.getpeercert() if client.sock else None,
                "tls_version": client.sock.version() if client.sock else None,
            }

    def _serialize_result(
        self,
        *,
        host: str,
        port: int,
        starttls_supported: bool,
        certificate_valid: bool | None,
        certificate,
        tls_version: str | None,
        hostname_match: bool | None,
        error: str | None = None,
    ) -> EmailTLSMXResult:
        if not starttls_supported or certificate is None:
            return EmailTLSMXResult(
                host=host,
                port=port,
                starttls_supported=False,
                error=error,
            )

        issuer = format_name(certificate.get("issuer"))
        subject = format_name(certificate.get("subject"))
        not_before = parse_certificate_datetime(certificate.get("notBefore"))
        not_after = parse_certificate_datetime(certificate.get("notAfter"))
        days_to_expire = calculate_days_to_expire(not_after)

        return EmailTLSMXResult(
            host=host,
            port=port,
            starttls_supported=True,
            has_tls_data=self._has_useful_tls_data(
                certificate_valid=certificate_valid,
                issuer=issuer,
                subject=subject,
                not_before=not_before,
                not_after=not_after,
                days_to_expire=days_to_expire,
                tls_version=tls_version,
                hostname_match=hostname_match,
            ),
            certificate_valid=certificate_valid,
            issuer=issuer,
            subject=subject,
            not_before=not_before,
            not_after=not_after,
            days_to_expire=days_to_expire,
            expiry_status=certificate_expiry_label(days_to_expire),
            tls_version=tls_version,
            hostname_match=hostname_match,
            error=error,
        )

    @staticmethod
    def _has_useful_tls_data(
        *,
        certificate_valid: bool | None,
        issuer: str | None,
        subject: str | None,
        not_before,
        not_after,
        days_to_expire: int | None,
        tls_version: str | None,
        hostname_match: bool | None,
    ) -> bool:
        return any(
            [
                certificate_valid is not None,
                issuer is not None,
                subject is not None,
                not_before is not None,
                not_after is not None,
                days_to_expire is not None,
                tls_version is not None,
                hostname_match is not None,
            ]
        )

    def _hostname_matches(self, probe_data: dict, host: str) -> bool | None:
        certificate = probe_data.get("certificate")
        if not certificate:
            return None
        try:
            ssl.match_hostname(certificate, host)
            return True
        except ssl.CertificateError:
            return False

    def _select_prioritized_records(self, mx_records: list[MXRecordValue]) -> list[MXRecordValue]:
        sorted_records = sorted(mx_records, key=lambda item: (item.preference, item.exchange))
        return sorted_records[: self.mx_probe_limit]

    @staticmethod
    def _build_probe_note(tested_count: int, total_count: int, probe_limited: bool) -> str | None:
        if not probe_limited:
            return None
        return (
            f"A analise de STARTTLS foi limitada aos {tested_count} MX prioritarios "
            f"de um total de {total_count} para otimizacao de performance."
        )

    @staticmethod
    def _build_message(
        results: list[EmailTLSMXResult],
        tested_count: int,
        total_count: int,
        probe_limited: bool,
    ) -> str:
        supported = [item for item in results if item.starttls_supported]
        suffix = ""
        if probe_limited:
            suffix = f" Foram testados {tested_count} de {total_count} MX prioritarios."
        if not supported:
            return f"Nenhum MX testado anunciou STARTTLS com sucesso.{suffix}".strip()
        valid = [item for item in supported if item.certificate_valid]
        if len(valid) == len(supported):
            return f"Os MX testados anunciaram STARTTLS e apresentaram certificados validos.{suffix}".strip()
        return f"STARTTLS foi encontrado em parte dos MX, mas nem todos os certificados foram validados.{suffix}".strip()
