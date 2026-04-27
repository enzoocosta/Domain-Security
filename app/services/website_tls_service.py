from socket import create_connection, timeout as SocketTimeout
import socket
import ssl

from app.core.config import settings
from app.schemas.analysis import WebsiteTLSResult
from app.utils.tls_helpers import (
    TLSProbeData,
    calculate_days_to_expire,
    certificate_expiry_label,
    extract_san,
    format_name,
    guess_certificate_provider,
    parse_certificate_datetime,
)


class WebsiteTLSService:
    """Checks HTTPS availability and the presented website certificate."""

    def __init__(self, probe_func=None, timeout_seconds: float | None = None) -> None:
        self.probe_func = probe_func or self._probe_https
        self.timeout_seconds = timeout_seconds or settings.website_tls_timeout_seconds

    def analyze(self, domain: str) -> WebsiteTLSResult:
        probe = self.probe_func(domain, 443)
        if not probe.tls_available or probe.certificate is None:
            return WebsiteTLSResult(
                ssl_active=False,
                message="Nao foi possivel confirmar HTTPS ativo na porta 443.",
                error=probe.error,
            )

        issuer = format_name(probe.certificate.get("issuer"))
        subject = format_name(probe.certificate.get("subject"))
        san = extract_san(probe.certificate)
        not_before = parse_certificate_datetime(probe.certificate.get("notBefore"))
        not_after = parse_certificate_datetime(probe.certificate.get("notAfter"))
        days_to_expire = calculate_days_to_expire(not_after)
        provider_guess, confidence = guess_certificate_provider(issuer, subject, san)

        return WebsiteTLSResult(
            ssl_active=True,
            certificate_valid=probe.certificate_valid,
            issuer=issuer,
            subject=subject,
            san=san,
            not_before=not_before,
            not_after=not_after,
            days_to_expire=days_to_expire,
            expiry_status=certificate_expiry_label(days_to_expire),
            tls_version=probe.tls_version,
            provider_guess=provider_guess,
            confidence=confidence,
            message=self._build_message(probe.certificate_valid, days_to_expire),
            error=probe.error,
        )

    def _probe_https(self, host: str, port: int) -> TLSProbeData:
        try:
            return self._perform_tls_handshake(host, port, verify=True)
        except ssl.SSLCertVerificationError as exc:
            fallback = self._perform_tls_handshake(host, port, verify=False)
            return TLSProbeData(
                tls_available=True,
                certificate_valid=False,
                certificate=fallback.certificate,
                tls_version=fallback.tls_version,
                error=f"Falha de validacao do certificado: {exc}",
            )
        except (SocketTimeout, TimeoutError, socket.timeout) as exc:
            return TLSProbeData(
                tls_available=False,
                certificate_valid=None,
                certificate=None,
                tls_version=None,
                error=f"Timeout ao conectar na porta 443: {exc}",
            )
        except (ConnectionRefusedError, OSError, ssl.SSLError) as exc:
            return TLSProbeData(
                tls_available=False,
                certificate_valid=None,
                certificate=None,
                tls_version=None,
                error=f"Falha ao negociar HTTPS: {exc}",
            )

    def _perform_tls_handshake(
        self, host: str, port: int, *, verify: bool
    ) -> TLSProbeData:
        context = (
            ssl.create_default_context() if verify else ssl._create_unverified_context()
        )
        with create_connection(
            (host, port), timeout=self.timeout_seconds
        ) as tcp_socket:
            with context.wrap_socket(tcp_socket, server_hostname=host) as tls_socket:
                certificate = tls_socket.getpeercert()
                return TLSProbeData(
                    tls_available=True,
                    certificate_valid=verify,
                    certificate=certificate,
                    tls_version=tls_socket.version(),
                )

    @staticmethod
    def _build_message(
        certificate_valid: bool | None, days_to_expire: int | None
    ) -> str:
        if certificate_valid is False:
            return "HTTPS esta ativo, mas o certificado nao foi validado com sucesso."
        if days_to_expire is None:
            return (
                "HTTPS esta ativo, mas a validade do certificado nao foi determinada."
            )
        if days_to_expire < 0:
            return "HTTPS esta ativo, mas o certificado do site esta expirado."
        if days_to_expire <= 30:
            return (
                "HTTPS esta ativo, mas o certificado do site esta proximo da expiracao."
            )
        return "HTTPS esta ativo com certificado valido."
