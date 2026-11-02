"""Clinic settings API routes for Sharma Dental AI."""

from fastapi import APIRouter, Body, HTTPException, Depends
from typing import Optional, List
from datetime import datetime

from ..db.supabase import table
from ..core.config import settings
from ..core.auth import require_auth, require_admin, User
from ..models.settings import ClinicSettingsUpdate, ClinicSettingsResponse

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("", response_model=ClinicSettingsResponse, dependencies=[Depends(require_auth)])
async def get_settings(
  current_user: User = Depends(require_auth),
):
  """Get clinic settings."""
  result = table("clinic_settings").select("*").single().execute()
  if not result.data:
    # Return default settings if none exist
    return ClinicSettingsResponse(
      id="1",
      clinic_name="Sharma Dental Clinic",
      city="Delhi",
      timezone="Asia/Kolkata",
      opening_time="10:00",
      closing_time="20:00",
      slot_duration_minutes=30,
      working_days=[1, 2, 3, 4, 5, 6],
      holidays=[],
      created_at=datetime.now().isoformat(),
      updated_at=datetime.now().isoformat(),
    )
  return result.data


@router.patch("", response_model=ClinicSettingsResponse, dependencies=[Depends(require_admin)])
async def update_settings(
  settings_update: ClinicSettingsUpdate = Body(...),
  current_user: User = Depends(require_admin),
):
  """Update clinic settings."""
  # Check if settings exist
  exists = table("clinic_settings").select("id").single().execute()
  if not exists.data:
    # Create default settings
    result = table("clinic_settings").insert(settings_update.model_dump(exclude_unset=True)).execute()
    if result.data:
      return result.data[0]
    raise HTTPException(status_code=400, detail="Failed to create settings")

  # Update existing settings
  result = table("clinic_settings").update(settings_update.model_dump(exclude_unset=True)).execute()
  if not result.data:
    raise HTTPException(status_code=404, detail="Settings not found")
  return result.data[0]