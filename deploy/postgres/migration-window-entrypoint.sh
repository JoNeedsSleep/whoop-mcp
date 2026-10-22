#!/bin/sh
# Only public operation/expiry arguments. No secret channel or caller SQL.
fail() { printf '%s\n' 'Migration window unavailable.' >&2; exit 1; }
case "$#" in 1|2) ;; *) fail ;; esac
case "$1" in
  inspect) [ "$#" -eq 1 ] || fail ;;
  renew) [ "$#" -eq 2 ] || fail ;;
  *) fail ;;
esac
# Reject known bootstrap/credential presence before replacing the environment.
for key in WHOOP_POSTGRES_PROVISION WHOOP_MIGRATION_BOOTSTRAP WHOOP_DATABASE_PROBE_BOOTSTRAP \
  WHOOP_BACKEND_IDENTITY_BOOTSTRAP WHOOP_BACKEND_APP_BOOTSTRAP WHOOP_GATEWAY_BOOTSTRAP \
  WHOOP_STAGING_BOOTSTRAP WHOOP_CLIENT_ID WHOOP_CLIENT_SECRET DATABASE_URL PGPASSWORD POSTGRES_PASSWORD; do
  # Variable names above are source constants, never external selectors.
  eval 'present=${'"$key"'+x}'
  [ "$present" != x ] || fail
done
exec /usr/bin/env -i PATH=/usr/local/bin:/usr/lib/postgresql/17/bin:/usr/bin:/bin HOME=/tmp TMPDIR=/tmp LANG=C \
  /usr/local/bin/node /opt/whoop-postgres/migration-window.mjs "$@"
