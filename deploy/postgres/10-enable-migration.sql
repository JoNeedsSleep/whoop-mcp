\set ON_ERROR_STOP on
-- Separate approved step after storing only the migrator's strong SCRAM password
-- through the private operator channel (for example local psql \password).
BEGIN;
DO $$ BEGIN
  IF current_user <> 'whoop_admin' OR current_database() <> 'whoop' OR
     NOT EXISTS (SELECT 1 FROM pg_authid WHERE rolname = 'whoop_migrate' AND NOT rolcanlogin
       AND rolpassword LIKE 'SCRAM-SHA-256$%') OR
     EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('whoop_owner', 'whoop_migrate', 'whoop_runtime')
       AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
    RAISE EXCEPTION 'WHOOP_DATABASE_MIGRATION_ENABLE_UNAVAILABLE';
  END IF;
  EXECUTE format('ALTER ROLE whoop_migrate LOGIN VALID UNTIL %L', clock_timestamp() + interval '1 hour');
END $$;
-- Needed by standard Drizzle, scoped to this DB and without grant option.
-- Also permits schemas/publications/trusted extensions in this DB until revoked.
GRANT CREATE ON DATABASE whoop TO whoop_owner;
COMMIT;
