-- Migration: Secure book_appointment RPC authorization
-- Fixes: type error in clinic-hours comparison, closes direct RPC access vulnerability.
--
-- Changes:
--   1. Recreates book_appointment() with ::time cast for clinic-hours validation
--      and SET search_path = '' to prevent schema poisoning via SECURITY DEFINER
--   2. Revokes EXECUTE from PUBLIC, anon, and authenticated roles
--   3. Grants EXECUTE exclusively to service_role
--
-- This closes the direct RPC authorization vulnerability: anonymous users can no
-- longer call book_appointment() directly; only the backend service-role client can.

create or replace function public.book_appointment(
  p_patient_id uuid,
  p_starts_at timestamptz,
  p_ends_at timestamptz,
  p_reason text default null,
  p_internal_notes text default null
) returns uuid as $$
declare
  v_appointment_id uuid;
  v_starts_local timestamp without time zone;
  v_ends_local timestamp without time zone;
BEGIN
  -- Reject NULL start or end timestamps
  IF p_starts_at IS NULL OR p_ends_at IS NULL THEN
    RAISE EXCEPTION 'Appointment start and end timestamps must not be null';
  END IF;

  -- Reject where end is not after start
  IF p_ends_at <= p_starts_at THEN
    RAISE EXCEPTION 'Appointment end time must be after start time';
  END IF;

  -- Convert to Asia/Kolkata local time (without time zone) for validation
  v_starts_local := p_starts_at AT TIME ZONE 'Asia/Kolkata';
  v_ends_local := p_ends_at AT TIME ZONE 'Asia/Kolkata';

  -- Reject appointments that cross midnight (local dates differ)
  IF v_starts_local::date != v_ends_local::date THEN
    RAISE EXCEPTION 'Appointment cannot cross midnight';
  END IF;

  -- Validate exactly 30-minute duration
  IF extract(epoch from (p_ends_at - p_starts_at)) != 1800 THEN
    RAISE EXCEPTION 'Appointment must be exactly 30 minutes';
  END IF;

  -- Acquire a deterministic advisory lock to serialize booking requests.
  PERFORM pg_advisory_xact_lock(hashtextextended('booking_lock', 0));

  -- Reject past appointments
  IF p_starts_at < now() THEN
    RAISE EXCEPTION 'Appointment cannot be in the past';
  END IF;

  -- Validate clinic hours (10:00-20:00 Asia/Kolkata)
  -- Cast to ::time for comparison against TIME literals
  IF v_starts_local::time < TIME '10:00' THEN
    RAISE EXCEPTION 'Appointment start time must be at or after 10:00 Asia/Kolkata';
  END IF;
  IF v_ends_local::time > TIME '20:00' THEN
    RAISE EXCEPTION 'Appointment end time must be at or before 20:00 Asia/Kolkata';
  END IF;

  -- Verify patient exists in the system
  IF NOT EXISTS (SELECT 1 FROM public.patients WHERE id = p_patient_id) THEN
    RAISE EXCEPTION 'Patient not found';
  END IF;

  -- Check for overlapping active appointments (clinic-wide, single dentist)
  IF EXISTS (
    SELECT 1 FROM public.appointments
    WHERE status IN ('scheduled', 'rescheduled')
    AND starts_at < p_ends_at
    AND ends_at > p_starts_at
  ) THEN
    RAISE EXCEPTION 'Time slot already booked';
  END IF;

  -- Insert the appointment within the locked transaction
  INSERT INTO public.appointments (patient_id, starts_at, ends_at, reason, internal_notes, status)
  VALUES (p_patient_id, p_starts_at, p_ends_at, p_reason, p_internal_notes, 'scheduled')
  RETURNING id INTO v_appointment_id;

  RETURN v_appointment_id;
END;
$$ language plpgsql security definer set search_path = '';

-- Revoke execution from all public roles
REVOKE EXECUTE ON FUNCTION public.book_appointment(uuid, timestamptz, timestamptz, text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.book_appointment(uuid, timestamptz, timestamptz, text, text) FROM anon;
REVOKE EXECUTE ON FUNCTION public.book_appointment(uuid, timestamptz, timestamptz, text, text) FROM authenticated;

-- Grant execution only to service_role
GRANT EXECUTE ON FUNCTION public.book_appointment(uuid, timestamptz, timestamptz, text, text) TO service_role;
