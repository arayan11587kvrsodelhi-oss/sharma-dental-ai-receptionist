-- Migration: Create profiles table
-- Reference: auth.users

create table if not exists public.profiles (
  id uuid primary key references auth.users on delete cascade,
  email text not null,
  role text not null default 'user' check (role in ('admin', 'user')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Enable RLS
alter table public.profiles enable row level security;

-- Policy: Users can read own profile
create policy "Users can read own profile" on public.profiles
  for select using (auth.uid() = id);

-- Policy: Admins can read all profiles
create policy "Admins can read all profiles" on public.profiles
  for select using (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

-- Policy: Users can upsert own profile
create policy "Users can upsert own profile" on public.profiles
  for all using (auth.uid() = id) with check (auth.uid() = id);
