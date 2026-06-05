create table if not exists users (
  id uuid primary key default uuid_generate_v4(),
  email text not null unique,
  password_hash text not null,
  role text not null check (role in ('user', 'admin')),
  created_at timestamptz not null default now(),
  last_login_at timestamptz
);

create index if not exists idx_users_role on users(role);
