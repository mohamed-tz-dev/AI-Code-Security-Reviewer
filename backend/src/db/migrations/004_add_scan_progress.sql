alter table scans
  add column progress integer not null default 0;

update scans set progress = 100 where status in ('completed', 'failed');
