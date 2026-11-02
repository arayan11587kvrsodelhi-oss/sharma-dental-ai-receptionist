"""Call Pydantic models for Sharma Dental AI."""

from datetime import datetime
from typing import Optional, Literal
from pydantic import BaseModel, Field


class CallBase(BaseModel):
    patient_id: Optional[str] = None
    provider_call_id: Optional[str] = None
    call_direction: Literal["outgoing", "incoming"] = "outgoing"
    status: Literal["queued", "in-progress", "completed", "failed", "busy", "no-answer"] = "queued"
    outcome: Optional[Literal["booked", "rescheduled", "cancelled", "failed", "human-followup"]] = None
    duration_seconds: Optional[int] = None
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    transcript: Optional[str] = None


class CallLogCreate(CallBase):
    pass


class CallLogResponse(CallBase):
    id: str
    created_at: datetime

    class Config:
        from_attributes = True


class CallLogListResponse(BaseModel):
    calls: list[CallLogResponse]
    total: int
    page: int
    page_size: int


class SimulateCallRequest(BaseModel):
    patient_id: str
    notes: Optional[str] = None


class SimulateCallResponse(BaseModel):
    status: str
    call_id: Optional[str] = None
    error: Optional[str] = None
    reason: Optional[str] = None


class QueueCallRequest(BaseModel):
    patient_id: str


class QueueCallResponse(BaseModel):
    status: str
    queue_entry_id: Optional[str] = None
    error: Optional[str] = None


class StartCallRequest(BaseModel):
    call_id: str


class StartCallResponse(BaseModel):
    status: str
    call_id: str