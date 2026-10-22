#!/bin/sh
# Fixed secret-free observation; never start PostgreSQL or mutate the volume.
fail() { printf '%s\n' 'PostgreSQL volume inspection unavailable.' >&2; exit 1; }
[ "$#" -eq 0 ] || fail
[ "${WHOOP_POSTGRES_PROVISION+x}" != x ] || fail
[ "${WHOOP_DATABASE_PROBE_BOOTSTRAP+x}" != x ] || fail
[ "${WHOOP_BACKEND_IDENTITY_BOOTSTRAP+x}" != x ] || fail
[ "${WHOOP_BACKEND_APP_BOOTSTRAP+x}" != x ] || fail
[ "${WHOOP_MIGRATION_BOOTSTRAP+x}" != x ] || fail
[ "${WHOOP_STAGING_BOOTSTRAP+x}" != x ] || fail
[ "${WHOOP_BOOTSTRAP+x}" != x ] || fail
[ "${WHOOP_GATEWAY_BOOTSTRAP+x}" != x ] || fail
[ "${WHOOP_GATEWAY_CONFIG_BOOTSTRAP+x}" != x ] || fail
[ "${WHOOP_CLIENT_ID+x}" != x ] || fail
[ "${WHOOP_CLIENT_SECRET+x}" != x ] || fail
[ "${DATABASE_URL+x}" != x ] || fail
[ "${PGPASSWORD+x}" != x ] || fail
[ "${POSTGRES_PASSWORD+x}" != x ] || fail
exec /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp LANG=C \
  /usr/local/bin/node /opt/whoop-postgres/inspect-volume.mjs
