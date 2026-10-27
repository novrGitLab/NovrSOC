-- Minimal baseline tables that are NOT defined anywhere in backend/novrsoc_supabase_schema.sql or
-- backend/sql/*.sql — they're legacy tables that only ever existed directly in the live Supabase
-- project, never captured as committed SQL (confirmed by a comment in
-- backend/src/routes/organisations.ts:299-305 noting the live `organisations` table "pre-dates"
-- several columns the repo's migrations try to ALTER onto it). Columns here are reverse-engineered
-- from every .select()/.insert() call against these tables across backend/src (not guessed), so
-- the rest of backend/sql/*.sql (which ALTERs/references them) can apply cleanly against this
-- fresh dev project. Lives in video-production/ only — never committed into backend/.
create extension if not exists pgcrypto;

create table if not exists public.organisations (
  id            uuid primary key default gen_random_uuid(),
  slug          text unique not null,
  name          text not null,
  is_active     boolean not null default true,
  contact_name  text,
  contact_email text,
  ciso_name     text,
  ciso_email    text,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

-- Real column set confirmed against the live organisations table by
-- backend/sql/2026-09-organisations-onboarding.sql's header comment (checked live 2026-09-05) —
-- added here instead of running that file, since its own INSERT hardcodes the real production
-- org's UUID and a named staff member we deliberately don't replicate into this dev project.
alter table public.organisations
  add column if not exists plan           text,
  add column if not exists industry       text,
  add column if not exists country        text,
  add column if not exists status         text default 'active',
  add column if not exists address        text,
  add column if not exists logo_url       text,
  add column if not exists wazuh_group    text,
  add column if not exists contact_phone  text,
  add column if not exists setup_complete boolean default false,
  add column if not exists domain         text;

create unique index if not exists organisations_slug_key on public.organisations (slug);

create table if not exists public.platform_users (
  id             uuid primary key default gen_random_uuid(),
  org_id         uuid references public.organisations(id) on delete cascade,
  email          text unique not null,
  name           text,
  role           text not null default 'analyst',
  status         text not null default 'active',
  password_hash  text,
  failed_logins  integer not null default 0,
  locked_until   timestamptz,
  last_login     timestamptz,
  last_active    timestamptz,
  is_online      boolean not null default false,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);

create sequence if not exists public.case_number_seq start 1000;

create table if not exists public.cases (
  id               uuid primary key default gen_random_uuid(),
  case_number      text not null default ('CASE-' || nextval('public.case_number_seq')::text),
  org_id           text not null,
  title            text not null,
  description      text,
  severity         text not null default 'medium',
  status           text not null default 'open',
  source           text not null default 'manual',
  source_id        text,
  agent_id         text,
  agent_name       text,
  source_ip        text,
  dest_ip          text,
  rule_id          text,
  rule_level       integer,
  mitre_technique  text,
  mitre_tactic     text,
  assigned_to      text,
  playbook_id      uuid,
  tags             text[] default '{}',
  tier             integer not null default 1,
  containment_done boolean not null default false,
  escalated        boolean not null default false,
  auto_closed      boolean not null default false,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  resolved_at      timestamptz,
  unique (org_id, source, source_id)
);

create table if not exists public.case_notes (
  id         uuid primary key default gen_random_uuid(),
  case_id    uuid references public.cases(id) on delete cascade,
  author     text,
  content    text,
  created_at timestamptz not null default now()
);

create table if not exists public.case_timeline (
  id         uuid primary key default gen_random_uuid(),
  case_id    uuid references public.cases(id) on delete cascade,
  actor      text,
  action     text,
  details    text,
  automated  boolean default false,
  created_at timestamptz not null default now()
);

create table if not exists public.playbooks (
  id             uuid primary key default gen_random_uuid(),
  org_id         text not null,
  name           text not null,
  icon           text default '📋',
  severity       text,
  description    text,
  steps          jsonb default '[]',
  estimated_time text,
  created_by     text,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);

create table if not exists public.email_logs (
  id           uuid primary key default gen_random_uuid(),
  org_id       text not null,
  message_id   text,
  to_address   text,
  verdict      text,
  received_at  timestamptz not null default now(),
  created_at   timestamptz not null default now()
);
alter table public.email_logs add column if not exists to_address text;

alter table public.organisations   enable row level security;
alter table public.platform_users  enable row level security;
alter table public.cases           enable row level security;
alter table public.case_notes      enable row level security;
alter table public.case_timeline   enable row level security;
alter table public.playbooks       enable row level security;
alter table public.email_logs      enable row level security;
