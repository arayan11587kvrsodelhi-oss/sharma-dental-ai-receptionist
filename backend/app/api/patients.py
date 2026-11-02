"""Patient API routes for Sharma Dental AI."""

from fastapi import APIRouter, Body, Path, Query, HTTPException, Depends
from typing import List, Optional
from uuid import UUID

from ..db.supabase import table
from ..core.config import settings
from ..core.auth import require_auth, require_admin, User
from ..models.patients import PatientCreate, PatientUpdate, PatientResponse, PatientListResponse

router = APIRouter(prefix="/api/patients", tags=["patients"])


@router.get("", response_model=PatientListResponse, dependencies=[Depends(require_auth)])
async def list_patients(
  status: Optional[str] = Query(None, description="Filter by call consent status"),
  search: Optional[str] = Query(None, description="Search by name or phone"),
  page: int = Query(1, ge=1, description="Page number"),
  page_size: int = Query(50, ge=1, le=500, description="Items per page"),
  current_user: User = Depends(require_auth),
):
  """List patients with optional filtering and search."""
  query = table("patients").select("*", count="exact")

  # Filter by consent status
  if status == "consented":
    query = query.eq("call_consent", "consented")
  elif status == "withdrawn":
    query = query.eq("call_consent", "withdrawn")
  elif status == "do-not-call":
    query = query.eq("do_not_call", True)
  elif status == "pending":
    query = query.eq("call_consent", "pending")

  # Search by name or phone
  if search:
    query = query.or_(f"full_name.ilike.%{search}%,phone.ilike.%{search}%")

  # Apply pagination
  result = query.order("created_at", desc=True).limit(page_size).offset((page - 1) * page_size).execute()

  patients = result.data if result.data else []
  total = result.count if hasattr(result, "count") and result.count else len(patients)
  return {"patients": patients, "total": total, "page": page, "page_size": page_size}


@router.get("/{patient_id}", response_model=PatientResponse, dependencies=[Depends(require_auth)])
async def get_patient(
  patient_id: str = Path(..., description="The patient UUID"),
  current_user: User = Depends(require_auth),
):
  """Get a single patient by UUID."""
  result = table("patients").select("*").eq("id", patient_id).single().execute()
  if not result.data:
    raise HTTPException(status_code=404, detail="Patient not found")
  return result.data


@router.post("", response_model=PatientResponse, status_code=201, dependencies=[Depends(require_admin)])
async def create_patient(
  patient: PatientCreate,
  current_user: User = Depends(require_admin),
):
  """Create a new patient."""
  result = table("patients").insert(patient.model_dump()).execute()
  if not result.data:
    raise HTTPException(status_code=400, detail="Failed to create patient")
  return result.data[0]


@router.patch("/{patient_id}", response_model=PatientResponse, dependencies=[Depends(require_admin)])
async def update_patient(
  patient_id: str = Path(..., description="The patient UUID"),
  patient_update: PatientUpdate = Body(...),
  current_user: User = Depends(require_admin),
):
  """Update a patient."""
  # Check patient exists
  exists = table("patients").select("id").eq("id", patient_id).single().execute()
  if not exists.data:
    raise HTTPException(status_code=404, detail="Patient not found")

  result = table("patients").update(patient_update.model_dump(exclude_unset=True)).eq(
    "id", patient_id
  ).execute()
  if not result.data:
    raise HTTPException(status_code=400, detail="Failed to update patient")
  return result.data[0]