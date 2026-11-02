"""Settings Pydantic models for Sharma Dental AI."""

from typing import Optional, Literal, List
from pydantic import BaseModel, Field
from datetime import datetime


class ClinicSettingsBase(BaseModel):
    clinic_name: str = Field(default="Sharma Dental Clinic", min_length=1, max_length=255)
    city: str = Field(default="Delhi", min_length=1, max_length=100)
    timezone: str = Field(default="Asia/Kolkata")
    opening_time: str = Field(default="10:00", pattern=r"^([01]\d|2[0-3]):([0-5]\d)$")
    closing_time: str = Field(default="20:00", pattern=r"^([01]\d|2[0-3]):([0-5]\d)$")
    slot_duration_minutes: int = Field(default=30, ge=15, le=120)
    working_days: List[int] = Field(default=[1, 2, 3, 4, 5, 6])  # Mon-Sat
    holidays: List[str] = Field(default=[])


class ClinicSettingsUpdate(BaseModel):
    clinic_name: Optional[str] = Field(None, min_length=1, max_length=255)
    city: Optional[str] = Field(None, min_length=1, max_length=100)
    timezone: Optional[str] = None
    opening_time: Optional[str] = Field(None, pattern=r"^([01]\d|2[0-3]):([0-5]\d)$")
    closing_time: Optional[str] = Field(None, pattern=r"^([01]\d|2[0-3]):([0-5]\d)$")
    slot_duration_minutes: Optional[int] = Field(None, ge=15, le=120)
    working_days: Optional[List[int]] = None
    holidays: Optional[List[str]] = None


class ClinicSettingsResponse(ClinicSettingsBase):
    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True