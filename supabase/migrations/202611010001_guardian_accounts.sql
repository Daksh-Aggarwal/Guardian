-- Apply once in the Supabase SQL editor as the project database owner.
-- The backend uses its server-only PostgreSQL connection. Browsers get read-only RLS access.
begin;
create table if not exists public.guardian_profiles (
 id uuid primary key references auth.users(id) on delete cascade,
 email text not null, display_name text not null, avatar_url text not null default '',
 created_at timestamptz not null default now()
);
create table if not exists public.guardian_devices (
 id uuid primary key, user_id uuid not null references public.guardian_profiles(id) on delete cascade,
 device_name text not null check(length(device_name) between 1 and 100),
 operating_system text not null, cli_version text not null, session_id uuid not null,
 created_at timestamptz not null default now(), last_seen_at timestamptz not null default now(),
 revoked_at timestamptz, unique(id,user_id)
);
create index if not exists guardian_devices_owner on public.guardian_devices(user_id,last_seen_at desc);
create table if not exists public.guardian_revoked_sessions (
 user_id uuid not null references public.guardian_profiles(id) on delete cascade,
 session_id uuid not null, revoked_at timestamptz not null default now(), primary key(user_id,session_id)
);
create table if not exists public.guardian_cloud_scans (
 id text not null check(length(id) between 1 and 64),
 user_id uuid not null references public.guardian_profiles(id) on delete cascade,
 device_id uuid not null, project_name text not null, ecosystem text not null check(ecosystem in ('npm','pypi')),
 decision text not null check(decision in ('ALLOW','WARN','BLOCK','REVIEW')),
 severity_summary jsonb not null, report_payload jsonb not null,
 payload_sha256 text not null check(length(payload_sha256)=64), engine_version text not null,
 scanned_at timestamptz not null, created_at timestamptz not null default now(),
 primary key(user_id,id), foreign key(device_id,user_id) references public.guardian_devices(id,user_id)
);
create index if not exists guardian_scans_owner on public.guardian_cloud_scans(user_id,created_at desc);
create table if not exists public.guardian_cli_authorizations (
 id text primary key, state text not null, challenge text not null, redirect_uri text not null,
 device_id uuid not null, device_name text not null, operating_system text not null, cli_version text not null,
 created_at bigint not null, expires_at bigint not null, code_hash text, consumed_at bigint
);
create index if not exists guardian_cli_authorizations_expiry on public.guardian_cli_authorizations(expires_at);
alter table public.guardian_profiles enable row level security;
alter table public.guardian_devices enable row level security;
alter table public.guardian_cloud_scans enable row level security;
alter table public.guardian_revoked_sessions enable row level security;
alter table public.guardian_cli_authorizations enable row level security;
revoke all on public.guardian_profiles,public.guardian_devices,public.guardian_cloud_scans,public.guardian_revoked_sessions,public.guardian_cli_authorizations from anon,authenticated;
grant select on public.guardian_profiles,public.guardian_cloud_scans to authenticated;
-- Device session bindings are server-only; expose only the nonsecret device columns through Guardian's API.
drop policy if exists guardian_profile_owner on public.guardian_profiles;
create policy guardian_profile_owner on public.guardian_profiles for select to authenticated using(id=(select auth.uid()));
drop policy if exists guardian_scan_owner on public.guardian_cloud_scans;
create policy guardian_scan_owner on public.guardian_cloud_scans for select to authenticated using(user_id=(select auth.uid()));
-- No direct browser/anon writes or authorization-code access. All mutations go through ownership-checked API routes.
commit;
