#!/bin/sh
fail() { printf '%s\n' 'Backend configuration unavailable.' >&2; exit 1; }
[ "$#" -eq 0 ] || fail
[ "$(/usr/bin/id -u)" = 1000 ] && [ "$(/usr/bin/id -ru)" = 1000 ] &&
  [ "$(/usr/bin/id -g)" = 1000 ] && [ "$(/usr/bin/id -rg)" = 1000 ] || fail
nnp=0
while IFS=' 	' read -r key value rest; do
  if [ "$key" = NoNewPrivs: ]; then
    [ "$value" = 1 ] && [ -z "$rest" ] && [ "$nnp" -eq 0 ] || fail
    nnp=1
  fi
done < /proc/self/status
[ "$nnp" -eq 1 ] || fail
[ "${WHOOP_CLIENT_ID+x}" != x ] && [ "${WHOOP_CLIENT_SECRET+x}" != x ] &&
  [ "${DATABASE_URL+x}" != x ] && [ "${PGPASSWORD+x}" != x ] &&
  [ "${WHOOP_BACKEND_BOOTSTRAP+x}" != x ] && [ "${WHOOP_BOOTSTRAP+x}" != x ] &&
  [ "${WHOOP_STAGING_BOOTSTRAP+x}" != x ] && [ "${WHOOP_GATEWAY_BOOTSTRAP+x}" != x ] &&
  [ "${WHOOP_BACKEND_IDENTITY_BOOTSTRAP+x}" != x ] && [ "${WHOOP_POSTGRES_PROVISION+x}" != x ] &&
  [ "${WHOOP_MIGRATION_BOOTSTRAP+x}" != x ] || fail
if [ "${WHOOP_BACKEND_APP_BOOTSTRAP+x}" != x ]; then
  exec /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp NODE_ENV=production \
    /usr/local/bin/node /app/deploy/backend-provision/provision.mjs
fi
[ "${#WHOOP_BACKEND_APP_BOOTSTRAP}" -gt 1 ] && [ "${#WHOOP_BACKEND_APP_BOOTSTRAP}" -le 16384 ] || fail
printf '%s' "$WHOOP_BACKEND_APP_BOOTSTRAP" | /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp NODE_ENV=production \
  /usr/local/bin/node /app/deploy/backend-provision/provision.mjs
status=$?
unset WHOOP_BACKEND_APP_BOOTSTRAP
exit "$status"
