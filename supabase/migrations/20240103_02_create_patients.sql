-- Migration: Create patients table

create table if not exists public.patients (
  id uuid primary key default gen_random_uuid(),
  full_name text not null,
  phone text not null,
  preferred_language text not null default 'hinglish' check (preferred_language in ('hinglish', 'hindi', 'english', 'other')),
  call_consent text not null default 'none' check (call_consent in ('given', 'withdrawn', 'none')),
  consent_type text null check (consent_type in ('verbal', 'written', 'recorded', 'none')),
  consent_source text null,
  consent_at timestamptz null,
  consent_withdrawn_at timestamptz null,
  do_not_call boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Enable RLS
alter table public.patients enable row level security;

-- Policy: Only authenticated users can read patients
create policy "Patients are viewable by authenticated users" on public.patients
  for select using (exists (select 1 from public.profiles where id = auth.uid()));

-- Policy: Admins can insert patients
create policy "Admins can insert patients" on public.patients
  for insert with check (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

-- Policy: Admins can update patients
create policy "Admins can update patients" on public.patients
  for update using (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

-- Policy: Admins can delete patients
create policy "Admins can delete patients" on public.patients
  for delete using (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

-- Indexes
create index if not exists idx_patients_phone on public.patients(phone);
create index if not exists idx_patients_consent on public.patients(call_consent);
create index if not exists idx_patients_do_not_call on public.patients(do_not_call);
