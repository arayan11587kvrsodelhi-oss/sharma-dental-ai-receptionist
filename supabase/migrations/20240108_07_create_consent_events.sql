-- Migration: Create consent_events table

create table if not exists public.consent_events (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid not null references public.patients(id) on delete cascade,
  consent_type text not null check (consent_type in ('verbal', 'written', 'recorded', 'none')),
  consent_given boolean not null default true,
  consent_at timestamptz not null default now(),
  consent_withdrawn_at timestamptz,
  source text not null default 'front_desk' check (source in ('front_desk', 'phone', 'online', 'parent', 'guardian')),
  notes text,
  created_at timestamptz not null default now()
);

-- Enable RLS
alter table public.consent_events enable row level security;

-- Policy: Users can read own consent events
create policy "Users can read own consent events" on public.consent_events
  for select using (exists (select 1 from public.profiles where id = auth.uid()));

-- Policy: Admins can insert consent events
create policy "Admins can insert consent events" on public.consent_events
  for insert with check (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

-- Policy: Admins can update consent events
create policy "Admins can update consent events" on public.consent_events
  for update using (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

-- Policy: Admins can delete consent events
create policy "Admins can delete consent events" on public.consent_events
  for delete using (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

-- Indexes
create index if not exists idx_consent_events_patient_id on public.consent_events(patient_id);
create index if not exists idx_consent_events_consent_type on public.consent_events(consent_type);
create index if not exists idx_consent_events_created_at on public.consent_events(created_at);
