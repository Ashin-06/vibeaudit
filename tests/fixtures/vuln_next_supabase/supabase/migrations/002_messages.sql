create table public.messages (
  id bigint generated always as identity primary key,
  body text,
  created_at timestamp default now() -- expect: DATA006
);
alter table public.messages enable row level security;
create policy "read all" on public.messages for select using (true); -- expect: DATA005
alter table public.profiles drop column role; -- expect: DATA003
