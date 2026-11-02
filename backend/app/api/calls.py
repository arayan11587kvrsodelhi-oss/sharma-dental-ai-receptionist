"""Call API routes for Sharma Dental AI."""

from fastapi import APIRouter, Body, Path, Query, HTTPException, Depends
from typing import List, Optional
from uuid import UUID

from ..db.supabase import table
from ..core.config import settings
from ..core.auth import require_auth, require_admin, User
from ..models.calls import (
    CallLogCreate,
    CallLogResponse,
    CallLogListResponse,
    SimulateCallRequest,
    SimulateCallResponse,
    QueueCallRequest,
    QueueCallResponse,
    StartCallRequest,
    StartCallResponse,
)

router = APIRouter(prefix="/api/calls", tags=["calls"])


@router.get("", response_model=CallLogListResponse, dependencies=[Depends(require_auth)])
async def list_calls(
  status: Optional[str] = Query(None, description="Filter by call status"),
  patient_id: Optional[str] = Query(None, description="Filter by patient UUID"),
  limit: int = Query(50, ge=1, le=500, description="Maximum results"),
  current_user: User = Depends(require_auth),
):
  """List calls with optional filtering."""
  query = table("call_logs").select("*")

  if status:
    query = query.eq("status", status)

  if patient_id:
    query = query.eq("patient_id", patient_id)

  result = query.order("started_at", desc=True).limit(limit).execute()
  data = result.data if result.data else []
  return {"calls": data, "total": len(data)}


@router.post("/simulate", response_model=SimulateCallResponse, dependencies=[Depends(require_admin)])
async def simulate_call(
  request: SimulateCallRequest,
  current_user: User = Depends(require_admin),
):
  """Simulate a call for a patient.

  Checks patient consent before creating a call log entry.
  This is a simulated call - no real phone calls are made.
  """
  from datetime import datetime, timezone

  # Check patient consent first
  patient_result = table("patients").select(
    "call_consent, do_not_call, full_name, phone"
  ).eq("id", request.patient_id).single().execute()

  patient = patient_result.data
  if not patient:
    return SimulateCallResponse(
      status="failed",
      error="Patient not found",
      reason="patient_not_found",
    )

  # Check consent - must be "given" to proceed
  if patient.get("call_consent") != "given":
    return SimulateCallResponse(
      status="blocked",
      error="Consent missing or withdrawn",
      reason=f"call_consent={patient.get('call_consent')}",
    )

  # Check do_not_call
  if patient.get("do_not_call"):
    return SimulateCallResponse(
      status="blocked",
      error="Patient marked do-not-call",
      reason="do_not_call=true",
    )

  # Create call log entry (simulated - no real call)
  now = datetime.now(timezone.utc).isoformat()

  call_result = table("call_logs").insert({
    "patient_id": request.patient_id,
    "call_direction": "outgoing",
    "status": "completed",  # Simulated call completes immediately
    "outcome": "booked",  # Simulated outcome
    "duration_seconds": 180,  # 3 minutes simulated
    "started_at": now,
    "ended_at": now,
    "transcript": f"Simulated call with {patient.get('full_name', 'patient')}. Appointment discussed and confirmed.",
  }).execute()

  if not call_result.data:
    return SimulateCallResponse(
      status="failed",
      error="Failed to create call log",
      reason="database_error",
    )

  return SimulateCallResponse(
    status="completed",
    call_id=call_result.data[0]["id"],
    reason="Simulated call completed successfully",
  )


@router.post("/queue", response_model=QueueCallResponse, dependencies=[Depends(require_admin)])
async def queue_call(
  request: QueueCallRequest,
  current_user: User = Depends(require_admin),
):
  """Queue a call for a patient.

  Checks consent and creates a call queue entry.
  The call will be processed later (simulated).
  """
  from datetime import datetime, timezone

  # Check consent
  patient_result = table("patients").select(
    "call_consent, do_not_call, full_name"
  ).eq("id", request.patient_id).single().execute()

  patient = patient_result.data
  if not patient:
    return QueueCallResponse(
      status="failed",
      error="Patient not found",
    )

  if patient.get("call_consent") != "given":
    return QueueCallResponse(
      status="blocked",
      error="Consent missing or withdrawn",
    )

  if patient.get("do_not_call"):
    return QueueCallResponse(
      status="blocked",
      error="Patient marked do-not-call",
    )

  # Create call queue entry
  now = datetime.now(timezone.utc).isoformat()

  queue_result = table("call_queue").insert({
    "patient_id": request.patient_id,
    "scheduled_at": now,
    "status": "queued",
    "attempts": 0,
    "last_attempt_at": None,
  }).execute()

  if not queue_result.data:
    return QueueCallResponse(
      status="failed",
      error="Failed to create queue entry",
    )

  return QueueCallResponse(
    status="queued",
    queue_entry_id=queue_result.data[0]["id"],
  )


@router.post("/start", response_model=StartCallResponse, dependencies=[Depends(require_admin)])
async def start_call(
  request: StartCallRequest,
  current_user: User = Depends(require_admin),
):
  """Start a simulated call by call log ID.

  Updates the call log status to in-progress.
  """
  from datetime import datetime, timezone

  now = datetime.now(timezone.utc).isoformat()

  result = table("call_logs").update({
    "status": "in-progress",
    "started_at": now,
  }).eq("id", request.call_id).execute()

  if not result.data:
    raise HTTPException(status_code=404, detail="Call log not found")

  return StartCallResponse(
    status="in-progress",
    call_id=request.call_id,
  )