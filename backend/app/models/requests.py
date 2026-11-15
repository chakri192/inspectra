from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator
from app.config import settings


class InputType(str, Enum):
    MESSAGE = "message"
    URL = "url"
    APP_REQUEST = "app_request"


class AppContext(BaseModel):
    claimed_app_purpose: Optional[str] = Field(
        default=None,
        max_length=200,
        description="User-stated claimed purpose of the application (e.g. 'Calculator', 'PDF Reader')"
    )
    installation_source: Optional[str] = Field(
        default=None,
        max_length=200,
        description="Installation source (e.g. 'Google Play', 'Direct APK / Sideload')"
    )
    requested_permissions: List[str] = Field(
        default_factory=list,
        description="List of permissions or special access requested by the app"
    )

    @field_validator("requested_permissions", mode="before")
    def clean_permissions(cls, v):
        if v is None:
            return []
        if isinstance(v, list):
            return [str(p).strip() for p in v if str(p).strip()][:50]
        return []


class AnalyzeRequest(BaseModel):
    input_type: InputType = Field(
        default=InputType.MESSAGE,
        description="Category of analysis requested: 'message', 'url', or 'app_request'"
    )
    content: str = Field(
        ...,
        description="Raw user-submitted text, message, URL, or app request description"
    )
    context: Optional[AppContext] = Field(
        default_factory=AppContext,
        description="Optional contextual parameters for app request evaluations"
    )

    @field_validator("content")
    def validate_content_length(cls, v: str) -> str:
        if v is not None and len(v) > settings.MAX_CONTENT_LENGTH:
            raise ValueError(f"Input exceeds maximum allowed length of {settings.MAX_CONTENT_LENGTH:,} characters.")
        return v
