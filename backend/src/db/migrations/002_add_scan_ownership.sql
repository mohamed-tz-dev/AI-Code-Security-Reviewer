alter table scans
add column if not exists user_id text,
add column if not exists user_email text;

create index if not exists idx_scans_user_id_created_at on scans(user_id, created_at desc);
