"""Appointment Pydantic models for Sharma Dental AI."""

from datetime import datetime
from typing import Optional, Literal
from pydantic import BaseModel, Field


class AppointmentBase(BaseModel):
    patient_id: str
    starts_at: datetime
    ends_at: datetime
    status: Literal["scheduled", "completed", "cancelled", "no-show", "rescheduled"] = "scheduled"
    reason: Optional[str] = None
    internal_notes: Optional[str] = None


class AppointmentCreate(AppointmentBase):
    pass


class AppointmentUpdate(BaseModel):
    patient_id: Optional[str] = None
    starts_at: Optional[datetime] = None
    ends_at: Optional[datetime] = None
    status: Optional[Literal["scheduled", "completed", "cancelled", "no-show", "rescheduled"]] = None
    reason: Optional[str] = None
    internal_notes: Optional[str] = None


class AppointmentResponse(AppointmentBase):
    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AppointmentListResponse(BaseModel):
    appointments: list[AppointmentResponse]
    total: int
    page: int
    page_size: int


class AvailableSlot(BaseModel):
    slot_start: datetime
    slot_end: datetime


class AvailabilityResponse(BaseModel):
    date: str
    slots: list[AvailableSlot]
    timezone: str = "Asia/Kolkata"