-- Migration: Create call_logs table

create table if not exists public.call_logs (
  id uuid primary key default gen_random_uuid(),
  call_queue_id uuid not null references public.call_queue(id) on delete cascade,
  patient_id uuid not null references public.patients(id) on delete cascade,
  started_at timestamptz not null,
  ended_at timestamptz,
  status text not null default 'initiated' check (status in ('initiating', 'in-progress', 'completed', 'failed', 'busy', 'no-answer')),
  duration_seconds integer,
  notes text,
  created_at timestamptz not null default now()
);

-- Enable RLS
alter table public.call_logs enable row level security;

-- Policy: Only authenticated users can read call logs
create policy "Call logs are viewable by authenticated users" on public.call_logs
  for select using (exists (select 1 from public.profiles where id = auth.uid()));

-- Policy: Admins can insert call logs
create policy "Admins can insert call logs" on public.call_logs
  for insert with check (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

-- Policy: Admins can update call logs
create policy "Admins can update call logs" on public.call_logs
  for update using (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

-- Policy: Admins can delete call logs
create policy "Admins can delete call logs" on public.call_logs
  for delete using (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

-- Indexes
create index if not exists idx_call_logs_call_queue_id on public.call_logs(call_queue_id);
create index if not exists idx_call_logs_patient_id on public.call_logs(patient_id);
create index if not exists idx_call_logs_status on public.call_logs(status);
