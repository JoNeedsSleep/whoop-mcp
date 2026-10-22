#!/bin/sh
if [ "$#" -ne 1 ]; then
  printf '%s\n' 'Local WHOOP sync unavailable.' >&2
  exit 1
fi
case "$1" in
  login) exec /usr/bin/setpriv --no-new-privs -- /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin /usr/bin/timeout --signal=TERM --kill-after=5 325 /usr/local/bin/node /app/deploy/local-sync/runtime.mjs login ;;
  sync) exec /usr/bin/setpriv --no-new-privs -- /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin /usr/bin/timeout --signal=TERM --kill-after=5 115 /usr/local/bin/node /app/deploy/local-sync/runtime.mjs sync ;;
  *) printf '%s\n' 'Local WHOOP sync unavailable.' >&2; exit 1 ;;
esac
