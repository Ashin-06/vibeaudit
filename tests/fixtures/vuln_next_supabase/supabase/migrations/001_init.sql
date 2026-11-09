create table public.profiles (
  id uuid primary key references auth.users,
  role text default 'user'
);
alter table public.profiles enable row level security;
create policy "anyone can update" on public.profiles for update using (true); -- expect: AUTH006

create table public.orders ( -- expect: AUTH005
  id bigint generated always as identity primary key,
  user_id uuid references auth.users,
  total numeric
);
