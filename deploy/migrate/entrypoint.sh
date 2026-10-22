#!/bin/sh
# Fixed provider-variable bridge; shell builtin printf keeps secrets out of argv.
fail() { printf '%s\n' 'Migration unavailable.' >&2; exit 1; }
[ "$#" -eq 0 ] || fail
if [ "${WHOOP_MIGRATION_BOOTSTRAP+x}" != x ]; then
  exec /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp NODE_ENV=production /usr/local/bin/node /app/deploy/migrate/migrate.mjs
fi
[ "$(/usr/bin/id -u)" = 1000 ] && [ "$(/usr/bin/id -ru)" = 1000 ] || fail
[ "$(/usr/bin/id -g)" = 1000 ] && [ "$(/usr/bin/id -rg)" = 1000 ] || fail
nnp=0
while IFS=' 	' read -r key value rest; do
  if [ "$key" = 'NoNewPrivs:' ]; then
    [ "$value" = 1 ] && [ -z "$rest" ] || fail
    nnp=$((nnp + 1))
  fi
done < /proc/self/status
[ "$nnp" = 1 ] || fail
[ "${#WHOOP_MIGRATION_BOOTSTRAP}" -gt 0 ] && [ "${#WHOOP_MIGRATION_BOOTSTRAP}" -le 32768 ] || fail
printf '%s' "$WHOOP_MIGRATION_BOOTSTRAP" |
  /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp NODE_ENV=production /usr/local/bin/node /app/deploy/migrate/bootstrap.mjs
status=$?
unset WHOOP_MIGRATION_BOOTSTRAP
exit "$status"
