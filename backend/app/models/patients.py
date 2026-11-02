"""Patient Pydantic models for Sharma Dental AI."""

from datetime import datetime
from typing import Optional, Literal
from pydantic import BaseModel, Field, field_validator
import re


class PatientBase(BaseModel):
    full_name: str = Field(..., min_length=1, max_length=255)
    phone: str = Field(..., min_length=10, max_length=15)
    preferred_language: Literal["hinglish", "hindi", "english", "other"] = "hinglish"
    call_consent: Literal["given", "withdrawn", "none"] = "none"
    consent_type: Optional[Literal["verbal", "written", "recorded", "none"]] = None
    consent_source: Optional[str] = None
    do_not_call: bool = False

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v: str) -> str:
        # Allow Indian phone numbers with optional +91 prefix
        phone_pattern = r"^(\+91[\s-]?)?[6-9]\d{9}$"
        if not re.match(phone_pattern, v):
            raise ValueError("Invalid Indian phone number format")
        return v


class PatientCreate(PatientBase):
    pass


class PatientUpdate(BaseModel):
    full_name: Optional[str] = Field(None, min_length=1, max_length=255)
    phone: Optional[str] = Field(None, min_length=10, max_length=15)
    preferred_language: Optional[Literal["hinglish", "hindi", "english", "other"]] = None
    call_consent: Optional[Literal["given", "withdrawn", "none"]] = None
    consent_type: Optional[Literal["verbal", "written", "recorded", "none"]] = None
    consent_source: Optional[str] = None
    do_not_call: Optional[bool] = None

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            phone_pattern = r"^(\+91[\s-]?)?[6-9]\d{9}$"
            if not re.match(phone_pattern, v):
                raise ValueError("Invalid Indian phone number format")
        return v


class PatientResponse(PatientBase):
    id: str
    consent_at: Optional[datetime] = None
    consent_withdrawn_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class PatientListResponse(BaseModel):
    patients: list[PatientResponse]
    total: int
    page: int
    page_size: int