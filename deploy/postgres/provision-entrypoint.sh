#!/bin/sh
# Provider variable bridge: the value is never a process argument or Node env.
# The shell's original environment/provider history can retain it; remove the
# active variable and replace this temporary deployment after completion.
fail() { printf '%s\n' 'PostgreSQL preparation unavailable.' >&2; exit 1; }
[ "$#" -eq 1 ] || fail
case "$1" in init|configure|enable|finalize) ;; *) fail ;; esac
forbidden=0
[ "${WHOOP_CLIENT_ID+x}" = x ] && forbidden=1
[ "${WHOOP_CLIENT_SECRET+x}" = x ] && forbidden=1
[ "${DATABASE_URL+x}" = x ] && forbidden=1
[ "${PGPASSWORD+x}" = x ] && forbidden=1
[ "${POSTGRES_PASSWORD+x}" = x ] && forbidden=1
[ "${WHOOP_STAGING_BOOTSTRAP+x}" = x ] && forbidden=1
[ "${WHOOP_BACKEND_BOOTSTRAP+x}" = x ] && forbidden=1
[ "${WHOOP_GATEWAY_BOOTSTRAP+x}" = x ] && forbidden=1
[ "${WHOOP_BACKEND_IDENTITY_BOOTSTRAP+x}" = x ] && forbidden=1
[ "${WHOOP_MIGRATION_BOOTSTRAP+x}" = x ] && forbidden=1
[ "$forbidden" -eq 0 ] || fail

if [ "$1" != configure ]; then
  [ "${WHOOP_POSTGRES_PROVISION+x}" != x ] || fail
  exec /usr/bin/env -i PATH=/usr/local/bin:/usr/lib/postgresql/17/bin:/usr/bin:/bin HOME=/tmp TMPDIR=/tmp LANG=C \
    /usr/local/bin/node /opt/whoop-postgres/provision.mjs "$1"
fi

# Validate real/effective identities and kernel NNP before reading the value.
[ "$(/usr/bin/id -u)" = 999 ] && [ "$(/usr/bin/id -ru)" = 999 ] &&
  [ "$(/usr/bin/id -g)" = 999 ] && [ "$(/usr/bin/id -rg)" = 999 ] || fail
nnp=0
while IFS=' 	' read -r name value rest; do
  if [ "$name" = NoNewPrivs: ]; then
    [ "$value" = 1 ] && [ -z "$rest" ] && [ "$nnp" -eq 0 ] || fail
    nnp=1
  fi
done < /proc/self/status
[ "$nnp" -eq 1 ] || fail
if [ "${WHOOP_POSTGRES_PROVISION+x}" != x ]; then
  exec /usr/bin/env -i PATH=/usr/local/bin:/usr/lib/postgresql/17/bin:/usr/bin:/bin HOME=/tmp TMPDIR=/tmp LANG=C \
    /usr/local/bin/node /opt/whoop-postgres/provision.mjs configure
fi
[ "${#WHOOP_POSTGRES_PROVISION}" -gt 1 ] && [ "${#WHOOP_POSTGRES_PROVISION}" -le 32768 ] || fail
printf '%s' "$WHOOP_POSTGRES_PROVISION" | /usr/bin/env -i PATH=/usr/local/bin:/usr/lib/postgresql/17/bin:/usr/bin:/bin HOME=/tmp TMPDIR=/tmp LANG=C \
  /usr/local/bin/node /opt/whoop-postgres/provision.mjs configure
status=$?
unset WHOOP_POSTGRES_PROVISION
exit "$status"
