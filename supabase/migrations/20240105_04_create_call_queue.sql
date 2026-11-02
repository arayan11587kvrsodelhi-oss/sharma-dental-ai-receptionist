-- Migration: Create call_queue table

create table if not exists public.call_queue (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid not null references public.patients(id) on delete cascade,
  scheduled_at timestamptz not null default now(),
  status text not null default 'queued' check (status in ('queued', 'in-progress', 'completed', 'failed', 'busy', 'no-answer')),
  attempts integer not null default 0,
  last_attempt_at timestamptz null,
  created_at timestamptz not null default now()
);

-- Enable RLS
alter table public.call_queue enable row level security;

-- Policy: Only authenticated users can read call queue
create policy "Call queue is viewable by authenticated users" on public.call_queue
  for select using (exists (select 1 from public.profiles where id = auth.uid()));

-- Policy: Admins can insert call queue entries
create policy "Admins can insert call queue entries" on public.call_queue
  for insert with check (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

-- Policy: Admins can update call queue entries
create policy "Admins can update call queue entries" on public.call_queue
  for update using (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

-- Policy: Admins can delete call queue entries
create policy "Admins can delete call queue entries" on public.call_queue
  for delete using (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

-- Indexes
create index if not exists idx_call_queue_patient_id on public.call_queue(patient_id);
create index if not exists idx_call_queue_status on public.call_queue(status);
create index if not exists idx_call_queue_scheduled_at on public.call_queue(scheduled_at);
