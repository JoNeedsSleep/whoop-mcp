\set ON_ERROR_STOP on
-- Run once, locally as whoop_admin against postgres, on a fresh dedicated cluster.
-- No passwords are accepted in this file. All new roles initially remain NOLOGIN.
DO $$ BEGIN
  IF current_user <> 'whoop_admin' OR current_database() <> 'postgres' OR
     EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('whoop_owner', 'whoop_migrate', 'whoop_runtime')) OR
     EXISTS (SELECT 1 FROM pg_database WHERE datname = 'whoop') THEN
    RAISE EXCEPTION 'WHOOP_DATABASE_PROVISIONING_UNAVAILABLE';
  END IF;
END $$;
BEGIN;
CREATE ROLE whoop_owner NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE whoop_migrate NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2;
CREATE ROLE whoop_runtime NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 12;
-- A peer-only administrator does not need a network password.
ALTER ROLE whoop_admin PASSWORD NULL;
COMMIT;
-- CREATE DATABASE cannot run inside a transaction. Partial failure is manual
-- recovery, never an automatic retry, overwrite or DROP of existing objects.
CREATE DATABASE whoop OWNER whoop_admin ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE whoop FROM PUBLIC;
\connect whoop
BEGIN;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO whoop_owner;
CREATE SCHEMA drizzle AUTHORIZATION whoop_owner;
REVOKE ALL ON SCHEMA drizzle FROM PUBLIC;
GRANT CONNECT ON DATABASE whoop TO whoop_migrate, whoop_runtime;
-- Three statements make each membership option explicit in PostgreSQL 17.
GRANT whoop_owner TO whoop_migrate WITH ADMIN FALSE;
GRANT whoop_owner TO whoop_migrate WITH INHERIT FALSE;
GRANT whoop_owner TO whoop_migrate WITH SET TRUE;
ALTER ROLE whoop_runtime IN DATABASE whoop SET search_path = public, pg_catalog;
COMMIT;
