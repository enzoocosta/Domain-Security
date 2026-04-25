from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

UserRole = Literal["client", "developer", "admin"]


class UserSession(BaseModel):
    id: int
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime


class UserRegistrationInput(BaseModel):
    email: str = Field(..., min_length=3, max_length=320)
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if "@" not in cleaned or cleaned.startswith("@") or cleaned.endswith("@"):
            raise ValueError("Informe um e-mail valido.")
        return cleaned


class UserLoginInput(BaseModel):
    email: str = Field(..., min_length=3, max_length=320)
    password: str = Field(..., min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if "@" not in cleaned or cleaned.startswith("@") or cleaned.endswith("@"):
            raise ValueError("Informe um e-mail valido.")
        return cleaned
