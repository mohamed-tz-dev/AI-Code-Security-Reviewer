create extension if not exists "uuid-ossp";

create table if not exists scans (
  id uuid primary key default uuid_generate_v4(),
  project_name text not null,
  source_type text not null check (source_type in ('zip', 'github')),
  source_reference text,
  status text not null check (status in ('queued', 'running', 'completed', 'failed')),
  security_score integer check (security_score between 0 and 100),
  error_message text,
  created_at timestamptz not null default now(),
  started_at timestamptz,
  completed_at timestamptz
);

create table if not exists vulnerabilities (
  id uuid primary key default uuid_generate_v4(),
  scan_id uuid not null references scans(id) on delete cascade,
  title text not null,
  category text not null,
  severity text not null check (severity in ('critical', 'high', 'medium', 'low', 'info')),
  file_path text not null,
  line_start integer,
  line_end integer,
  description text not null,
  recommendation text not null,
  evidence text,
  confidence numeric(4, 3) not null default 0.500,
  created_at timestamptz not null default now()
);

create index if not exists idx_scans_created_at on scans(created_at desc);
create index if not exists idx_vulnerabilities_scan_id on vulnerabilities(scan_id);
create index if not exists idx_vulnerabilities_severity on vulnerabilities(severity);
