from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class ApiTokenCreateInput(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Informe um nome para o token.")
        return cleaned


class ApiTokenSummary(BaseModel):
    id: int
    name: str
    token_prefix: str
    is_active: bool
    last_used_at: datetime | None = None
    created_at: datetime


class ApiTokenCreateResult(BaseModel):
    token: str
    token_item: ApiTokenSummary
