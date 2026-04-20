from __future__ import annotations

from dataclasses import dataclass
from email.message import EmailMessage
import smtplib
import ssl

from app.core.config import settings


@dataclass(frozen=True)
class EmailMessagePayload:
    recipient: str
    subject: str
    text_body: str


@dataclass(frozen=True)
class EmailSendResult:
    attempted: bool
    delivered: bool
    provider: str
    error: str | None = None


class BaseEmailSender:
    provider_name = "disabled"

    def is_available(self) -> bool:
        return False

    def send(self, message: EmailMessagePayload) -> EmailSendResult:
        return EmailSendResult(
            attempted=False,
            delivered=False,
            provider=self.provider_name,
            error="Entrega de e-mail indisponivel ou nao configurada.",
        )


class SMTPEmailSender(BaseEmailSender):
    provider_name = "smtp"

    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str | None,
        password: str | None,
        use_tls: bool,
        use_ssl: bool,
        timeout_seconds: float,
        from_email: str,
        from_name: str | None,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.use_ssl = use_ssl
        self.timeout_seconds = timeout_seconds
        self.from_email = from_email
        self.from_name = from_name

    def is_available(self) -> bool:
        return bool(self.host and self.from_email)

    def send(self, message: EmailMessagePayload) -> EmailSendResult:
        mime_message = EmailMessage()
        mime_message["To"] = message.recipient
        mime_message["From"] = self._format_from_header()
        mime_message["Subject"] = message.subject
        mime_message.set_content(message.text_body)

        try:
            if self.use_ssl:
                client: smtplib.SMTP = smtplib.SMTP_SSL(
                    host=self.host,
                    port=self.port,
                    timeout=self.timeout_seconds,
                    context=ssl.create_default_context(),
                )
            else:
                client = smtplib.SMTP(
                    host=self.host,
                    port=self.port,
                    timeout=self.timeout_seconds,
                )

            with client:
                client.ehlo()
                if self.use_tls and not self.use_ssl:
                    client.starttls(context=ssl.create_default_context())
                    client.ehlo()
                if self.username:
                    client.login(self.username, self.password or "")
                client.send_message(mime_message)
        except Exception as exc:  # pragma: no cover - depende de SMTP real
            return EmailSendResult(
                attempted=True,
                delivered=False,
                provider=self.provider_name,
                error=str(exc),
            )

        return EmailSendResult(
            attempted=True,
            delivered=True,
            provider=self.provider_name,
        )

    def _format_from_header(self) -> str:
        if self.from_name:
            return f"{self.from_name} <{self.from_email}>"
        return self.from_email


class EmailDeliveryService:
    def __init__(self, sender: BaseEmailSender | None = None) -> None:
        self.sender = sender or self._build_sender()

    def send(self, message: EmailMessagePayload) -> EmailSendResult:
        return self.sender.send(message)

    @staticmethod
    def _build_sender() -> BaseEmailSender:
        if settings.email_delivery_enabled and settings.smtp_host and settings.smtp_from_email:
            return SMTPEmailSender(
                host=settings.smtp_host,
                port=settings.smtp_port,
                username=settings.smtp_username,
                password=settings.smtp_password,
                use_tls=settings.smtp_use_tls,
                use_ssl=settings.smtp_use_ssl,
                timeout_seconds=settings.smtp_timeout_seconds,
                from_email=settings.smtp_from_email,
                from_name=settings.smtp_from_name,
            )
        return BaseEmailSender()
