-- Ejecutar en Supabase -> SQL Editor
create table if not exists public.users (
  id            uuid primary key default gen_random_uuid(),
  email         text unique not null,
  password_hash text not null,
  mfa_status    text not null default 'DISABLED'
                check (mfa_status in ('DISABLED','PENDING_VERIFICATION','ACTIVE')),
  totp_secret   text,
  backup_codes  jsonb not null default '[]'::jsonb,   -- hashes SHA-256 de los códigos de respaldo
  created_at    timestamptz not null default now()
);
-- RLS activado y sin políticas: nadie desde el front puede leer la tabla;
-- el backend entra con la service_role key, que ignora RLS.
alter table public.users enable row level security;
