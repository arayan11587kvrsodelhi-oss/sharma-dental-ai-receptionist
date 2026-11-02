"""Appointment API routes for Sharma Dental AI."""

from fastapi import APIRouter, Body, Path, Query, HTTPException, Depends
from typing import List, Optional
from datetime import date as date_type

from ..db.supabase import rpc, table, get_supabase_service_role_client
from ..core.config import settings
from ..core.auth import require_auth, require_admin, User
from ..models.appointments import AppointmentCreate, AppointmentUpdate, AppointmentResponse, AvailabilityResponse

router = APIRouter(prefix="/api/appointments", tags=["appointments"])


@router.get("", dependencies=[Depends(require_auth)])
async def list_appointments(
  status: Optional[str] = Query(None, description="Filter by appointment status"),
  patient_id: Optional[str] = Query(None, description="Filter by patient UUID"),
  current_user: User = Depends(require_auth),
):
  """List appointments with optional filtering."""
  query = table("appointments").select("*")

  if status:
    query = query.eq("status", status)

  if patient_id:
    query = query.eq("patient_id", patient_id)

  result = query.order("starts_at", desc=True).execute()
  data = result.data if result.data else []
  return {"appointments": data}


@router.get("/availability", response_model=AvailabilityResponse, dependencies=[Depends(require_auth)])
async def check_availability(
  date: str = Query(..., description="Date to check availability for YYYY-MM-DD"),
  current_user: User = Depends(require_auth),
):
  """Check available appointment slots for a given date."""
  try:
    d = date_type.fromisoformat(date)
    # Reject past dates
    if d < date_type.today():
      raise HTTPException(status_code=400, detail="Cannot check availability for past dates")
  except ValueError:
    raise HTTPException(status_code=400, detail="Invalid date format, use YYYY-MM-DD")

  # Use the database function to get available slots
  result = rpc("get_available_slots", {"p_date": date, "p_timezone": "Asia/Kolkata"}).execute()

  slots = result.data if result.data else []
  return {"date": date, "slots": slots, "timezone": "Asia/Kolkata"}


@router.post("", response_model=AppointmentResponse, status_code=201, dependencies=[Depends(require_admin)])
async def create_appointment(
  appointment: AppointmentCreate,
  current_user: User = Depends(require_admin),
):
  """Create a new appointment with atomic booking."""
  try:
    # Use the privileged service-role client for admin booking after authz check
    service_client = get_supabase_service_role_client()
    if service_client is None:
      raise HTTPException(status_code=500, detail="Service-role Supabase client not configured")
    result = service_client.rpc("book_appointment", {
        "p_patient_id": appointment.patient_id,
        "p_starts_at": appointment.starts_at.isoformat(),
        "p_ends_at": appointment.ends_at.isoformat(),
        "p_reason": appointment.reason,
        "p_internal_notes": appointment.internal_notes,
    }).execute()

    if result.data and len(result.data) > 0:
      return result.data[0]
    elif isinstance(result.data, dict) and "id" in result.data:
      return result.data
    else:
      raise HTTPException(status_code=400, detail="Booking failed - slot may be occupied")
  except HTTPException:
    raise
  except Exception as e:
    raise HTTPException(status_code=422, detail=str(e))


@router.patch("/{appointment_id}", response_model=AppointmentResponse, dependencies=[Depends(require_admin)])
async def update_appointment(
  appointment_id: str = Path(..., description="The appointment UUID"),
  appointment_update: AppointmentUpdate = Body(...),
  current_user: User = Depends(require_admin),
):
  """Update an appointment."""
  result = table("appointments").update(appointment_update.model_dump(exclude_unset=True)).eq(
    "id", appointment_id
  ).execute()
  if not result.data:
    raise HTTPException(status_code=404, detail="Appointment not found")
  return result.data[0]