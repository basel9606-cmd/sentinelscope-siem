-- SentinelScope SIEM: secure starter schema for Supabase Postgres.
-- Apply from Supabase SQL Editor after reviewing the script.

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null unique,
  display_name text not null,
  role text not null default 'viewer' check (role in ('admin', 'analyst', 'viewer')),
  created_at timestamptz not null default now()
);

create table if not exists public.cases (
  id uuid primary key default gen_random_uuid(),
  case_number text not null unique,
  title text not null,
  severity text not null check (severity in ('critical', 'high', 'medium', 'low')),
  status text not null default 'new' check (status in ('new', 'investigating', 'contained', 'resolved', 'closed')),
  owner_id uuid references public.profiles(id) on delete set null,
  summary text,
  next_step text,
  opened_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  closed_at timestamptz
);

create table if not exists public.alerts (
  id uuid primary key default gen_random_uuid(),
  external_id text unique,
  rule_name text not null,
  severity text not null check (severity in ('critical', 'high', 'medium', 'low')),
  mitre_technique text,
  entity text not null,
  source text not null,
  observed_at timestamptz not null,
  raw_event jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.case_alerts (
  case_id uuid not null references public.cases(id) on delete cascade,
  alert_id uuid not null references public.alerts(id) on delete cascade,
  added_at timestamptz not null default now(),
  primary key (case_id, alert_id)
);

create table if not exists public.case_notes (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references public.cases(id) on delete cascade,
  author_id uuid references public.profiles(id) on delete set null,
  body text not null check (char_length(body) <= 10000),
  created_at timestamptz not null default now()
);

create table if not exists public.audit_log (
  id uuid primary key default gen_random_uuid(),
  actor_id uuid references public.profiles(id) on delete set null,
  case_id uuid references public.cases(id) on delete set null,
  action text not null,
  detail jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_cases_status_updated on public.cases(status, updated_at desc);
create index if not exists idx_alerts_entity_observed on public.alerts(entity, observed_at desc);
create index if not exists idx_case_notes_case_created on public.case_notes(case_id, created_at desc);
create index if not exists idx_audit_log_case_created on public.audit_log(case_id, created_at desc);

create or replace function public.set_updated_at()
returns trigger
language plpgsql
security invoker
set search_path = public
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists cases_set_updated_at on public.cases;
create trigger cases_set_updated_at
before update on public.cases
for each row execute procedure public.set_updated_at();

-- Every table is private by default. Policies are deliberately added only
-- after the application has Supabase Auth integrated.
alter table public.profiles enable row level security;
alter table public.cases enable row level security;
alter table public.alerts enable row level security;
alter table public.case_alerts enable row level security;
alter table public.case_notes enable row level security;
alter table public.audit_log enable row level security;
