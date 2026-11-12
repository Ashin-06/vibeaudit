create table accounts (id uuid primary key default gen_random_uuid(), email text unique);
create table invoices (
  id bigserial primary key,
  account_id uuid references accounts(id) on delete cascade, -- expect: DATA012
  created_at timestamptz default now()
);
