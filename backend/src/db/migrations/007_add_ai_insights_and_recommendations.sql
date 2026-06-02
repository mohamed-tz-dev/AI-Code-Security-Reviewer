alter table vulnerabilities
  add column if not exists ai_why text,
  add column if not exists attack_scenario text,
  add column if not exists secure_patch text;

alter table scans
  add column if not exists ai_recommendations text;
