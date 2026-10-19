# Official PostgreSQL 17.11 bookworm, AMD64. Artifact-only: no installs or RUN.
FROM postgres@sha256:66aafa11cf15800a3c94763f7e11d1e7b2e37e5e84bc4ce027cb6e1e4bfaf4df
COPY deploy/postgres/postgresql.conf.template deploy/postgres/pg_hba.conf deploy/postgres/pg_ident.conf /opt/whoop-postgres/
COPY deploy/postgres/server-cert.cnf.template /opt/whoop-postgres/
COPY deploy/postgres/00-provision.sql deploy/postgres/10-enable-migration.sql deploy/postgres/20-finalize.sql /opt/whoop-postgres/
USER 999:999
# Deliberately bypass docker-entrypoint.sh and its environment/init-script flow.
# Missing initialized PGDATA, rendered config or TLS files must stop startup.
ENTRYPOINT ["/usr/bin/setpriv", "--no-new-privs", "--", "/usr/bin/env", "-i", "PATH=/usr/lib/postgresql/17/bin:/usr/bin:/bin", "HOME=/tmp", "LANG=C", "/usr/lib/postgresql/17/bin/postgres"]
CMD ["-D", "/var/lib/postgresql/data/pgdata", "-c", "config_file=/var/lib/postgresql/data/config/postgresql.conf"]
