create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users,
  body text
);
alter table public.notes enable row level security;
create policy "owners read" on public.notes for select using (auth.uid() = user_id);
create policy "owners write" on public.notes for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
