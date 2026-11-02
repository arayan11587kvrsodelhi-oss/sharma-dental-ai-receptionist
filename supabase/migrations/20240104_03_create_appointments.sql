-- Migration: Create appointments table

create table if not exists public.appointments (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid not null references public.patients(id) on delete cascade,
  starts_at timestamptz not null,
  ends_at timestamptz not null,
  status text not null default 'scheduled' check (status in ('scheduled', 'completed', 'cancelled', 'no-show', 'rescheduled')),
  reason text null,
  internal_notes text null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Enable RLS
alter table public.appointments enable row level security;

-- Policy: Only authenticated users can read appointments
create policy "Appointments are viewable by authenticated users" on public.appointments
  for select using (exists (select 1 from public.profiles where id = auth.uid()));

-- Policy: Admins can insert appointments
create policy "Admins can insert appointments" on public.appointments
  for insert with check (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

-- Policy: Admins can update appointments
create policy "Admins can update appointments" on public.appointments
  for update using (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

-- Policy: Admins can delete appointments
create policy "Admins can delete appointments" on public.appointments
  for delete using (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

-- Indexes
create index if not exists idx_appointments_patient_id on public.appointments(patient_id);
create index if not exists idx_appointments_starts_at on public.appointments(starts_at);
create index if not exists idx_appointments_status on public.appointments(status);

-- GiST extension for timestamp range exclusion constraint
create extension if not exists btree_gist;

-- Clinic-wide exclusion constraint to prevent overlapping appointments.
-- Since this is a single-dentist clinic, no two active appointments may overlap
-- regardless of patient. Cancelled and completed appointments are excluded.
-- The constraint uses tstzrange for TIMESTAMPTZ columns with the '[)') bracket
-- convention: left-inclusive, right-exclusive interval.
-- Uses && (overlap) operator instead of = (equality) to detect range overlaps.
alter table public.appointments
add constraint no_clinic_appointment_overlap
exclude using gist (tstzrange(starts_at, ends_at, '[)') with &&)
where (status in ('scheduled', 'rescheduled'));

-- Atomic booking function to prevent double-booking
-- Uses an advisory lock to serialize booking requests and prevent race conditions.
-- Also enforces past-date rejection at the database level.
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
  -- hashtextextended produces a consistent bigint key from the lock name,
  -- avoiding any dependency on pg_advisory_xact_lock text-key behavior.
  PERFORM pg_advisory_xact_lock(hashtextextended('booking_lock', 0));

  -- Reject past appointments (comparing absolute instants; p_starts_at is TIMESTAMPTZ).
  IF p_starts_at < now() THEN
    RAISE EXCEPTION 'Appointment cannot be in the past';
  END IF;

  -- Validate clinic hours (10:00-20:00 Asia/Kolkata)
  IF v_starts_local < '10:00'::time THEN
    RAISE EXCEPTION 'Appointment start time must be at or after 10:00 Asia/Kolkata';
  END IF;
  IF v_ends_local > '20:00'::time THEN
    RAISE EXCEPTION 'Appointment end time must be at or before 20:00 Asia/Kolkata';
  END IF;

  -- Verify patient exists in the system
  IF NOT EXISTS (SELECT 1 FROM public.patients WHERE id = p_patient_id) THEN
    RAISE EXCEPTION 'Patient not found';
  END IF;

  -- Check for overlapping active appointments (clinic-wide, single dentist)
  -- Excludes cancelled and completed appointments from the check
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
$$ language plpgsql security definer;