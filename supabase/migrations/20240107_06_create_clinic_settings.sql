-- Migration: Create clinic_settings table

create table if not exists public.clinic_settings (
  id uuid primary key default gen_random_uuid(),
  key text not null unique,
  value text not null,
  description text,
  updated_at timestamptz not null default now()
);

-- Enable RLS
alter table public.clinic_settings enable row level security;

-- Policy: Users can read active clinic settings
create policy "Clinic settings are viewable by authenticated users" on public.clinic_settings
  for select using (exists (select 1 from public.profiles where id = auth.uid()));

-- Policy: Admins can upsert clinic settings
create policy "Admins can upsert clinic settings" on public.clinic_settings
  for all using (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

-- Insert default values
insert into public.clinic_settings (key, value, description) values
  ('clinic_name', 'Sharma Dental Clinic', 'Name of the clinic'),
  ('clinic_timezone', 'Asia/Kolkata', 'Default timezone for the clinic'),
  ('clinic_open_hour', '10', 'Clinic opening hour (24h format)'),
  ('clinic_close_hour', '20', 'Clinic closing hour (24h format)'),
  ('appointment_duration_minutes', '30', 'Default appointment duration in minutes'),
  ('holidays_policy', '[]', 'JSON array of holiday dates (YYYY-MM-DD format)');
