\set ON_ERROR_STOP on
-- Run locally as administrator only after the one-off migration job has exited.
-- Runtime must already have its own distinct SCRAM password, supplied privately.
-- Revocation commits separately: a later failed schema check must not restore it.
BEGIN;
DO $$ BEGIN
  IF current_user <> 'whoop_admin' OR current_database() <> 'whoop' THEN
    RAISE EXCEPTION 'WHOOP_DATABASE_FINALIZATION_UNAVAILABLE';
  END IF;
END $$;
ALTER ROLE whoop_migrate NOLOGIN PASSWORD NULL VALID UNTIL 'epoch';
REVOKE whoop_owner FROM whoop_migrate;
REVOKE ALL ON DATABASE whoop FROM whoop_migrate;
REVOKE CREATE ON DATABASE whoop FROM whoop_owner;
COMMIT;
-- Let pre-existing authentication attempts hit the fixed 5-second server limit.
-- Existing sessions are not killed: their continued presence fails the next gate.
DO $$ BEGIN PERFORM pg_sleep(6); END $$;
BEGIN;
DO $$
DECLARE tables text[];
BEGIN
  IF current_user <> 'whoop_admin' OR current_database() <> 'whoop' OR
     EXISTS (SELECT 1 FROM pg_stat_activity WHERE usename = 'whoop_migrate') OR
     EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('whoop_owner', 'whoop_migrate', 'whoop_runtime')
       AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) OR
     EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'whoop_owner' AND rolcanlogin) OR
     EXISTS (SELECT 1 FROM pg_authid WHERE rolname = 'whoop_migrate' AND (rolcanlogin OR rolpassword IS NOT NULL)) OR
     EXISTS (SELECT 1 FROM pg_auth_members WHERE member = 'whoop_migrate'::regrole) OR
     has_database_privilege('whoop_owner', 'whoop', 'CREATE') OR
     has_database_privilege('whoop_migrate', 'whoop', 'CONNECT') OR
     EXISTS (SELECT 1 FROM pg_auth_members WHERE member = 'whoop_runtime'::regrole) OR
     has_database_privilege('whoop_runtime', 'whoop', 'CREATE,TEMP') OR
     has_schema_privilege('whoop_runtime', 'public', 'CREATE') OR
     has_schema_privilege('whoop_runtime', 'drizzle', 'USAGE') OR
     NOT EXISTS (SELECT 1 FROM pg_authid WHERE rolname = 'whoop_runtime' AND NOT rolcanlogin
       AND rolpassword LIKE 'SCRAM-SHA-256$%') THEN
    RAISE EXCEPTION 'WHOOP_DATABASE_FINALIZATION_UNAVAILABLE';
  END IF;
  SELECT array_agg(tablename ORDER BY tablename) INTO tables FROM pg_tables WHERE schemaname = 'public';
  IF tables IS DISTINCT FROM ARRAY['mcp_tokens','oauth_auth_codes','oauth_clients','pending_authorizations','users','whoop_tokens'] OR
     EXISTS (SELECT 1 FROM pg_tables WHERE schemaname IN ('public','drizzle') AND tableowner <> 'whoop_owner') OR
     (SELECT count(*) FROM drizzle.__drizzle_migrations) <> 3 OR
     (SELECT count(DISTINCT (hash, created_at)) FROM drizzle.__drizzle_migrations) <> 3 OR
     EXISTS (SELECT hash, created_at FROM drizzle.__drizzle_migrations EXCEPT VALUES
       ('7845b3ce01a5bbfbbad0af50a48aa73222e37eae05b3eec9b3be4e41790b5671',1785498994215::bigint),
       ('f8c6cab011368359f4b1c834074635f2ab1511222cae17c536693f30225d1d9d',1785502357731::bigint),
       ('4b3b433350aa219334e61688c5abf407a1f77e7707b18eef2b66d538259d3a11',1792324800000::bigint)) THEN
    RAISE EXCEPTION 'WHOOP_DATABASE_FINALIZATION_UNAVAILABLE';
  END IF;
END $$;
GRANT USAGE ON SCHEMA public TO whoop_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.users, public.whoop_tokens,
  public.mcp_tokens, public.oauth_clients, public.oauth_auth_codes, public.pending_authorizations TO whoop_runtime;
ALTER ROLE whoop_runtime LOGIN;
COMMIT;
