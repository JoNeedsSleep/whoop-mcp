#!/bin/sh
# Fixed one-shot channel. No argument, path, SQL or role selection.
fail() { printf '%s\n' 'Database probe unavailable.' >&2; exit 1; }
[ "$#" -eq 0 ] || fail
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
if [ "${WHOOP_DATABASE_PROBE_BOOTSTRAP+x}" != x ]; then
  exec /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp NODE_ENV=production /usr/local/bin/node /app/deploy/db-probe/probe.mjs
fi
[ "${#WHOOP_DATABASE_PROBE_BOOTSTRAP}" -gt 0 ] && [ "${#WHOOP_DATABASE_PROBE_BOOTSTRAP}" -le 32768 ] || fail
printf '%s' "$WHOOP_DATABASE_PROBE_BOOTSTRAP" |
  /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp NODE_ENV=production /usr/local/bin/node /app/deploy/db-probe/probe.mjs
status=$?
unset WHOOP_DATABASE_PROBE_BOOTSTRAP
exit "$status"
