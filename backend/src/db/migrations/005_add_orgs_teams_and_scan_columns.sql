create table if not exists organizations (
  id uuid primary key default uuid_generate_v4(),
  name text not null,
  slug text not null unique,
  created_at timestamptz not null default now()
);

create table if not exists teams (
  id uuid primary key default uuid_generate_v4(),
  organization_id uuid not null references organizations(id) on delete cascade,
  name text not null,
  created_at timestamptz not null default now()
);

create table if not exists organization_members (
  organization_id uuid not null references organizations(id) on delete cascade,
  user_id text not null,
  role text not null default 'member',
  primary key (organization_id, user_id)
);

alter table scans
  add column organization_id uuid,
  add column team_id uuid;

create index if not exists idx_scans_organization_id on scans(organization_id);
create index if not exists idx_scans_team_id on scans(team_id);

-- Backfill: no-op for existing rows
