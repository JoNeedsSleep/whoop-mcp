#!/bin/sh
# Container-only entrypoint. Require inspected host-loopback publication and
# namespace firewall before startup. Private config arrives only on stdin.
if [ "$#" -ne 0 ]; then
  printf '%s\n' 'Local identity verification unavailable.' >&2
  exit 1
fi
exec /usr/bin/setpriv --no-new-privs -- /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin /usr/local/bin/node /app/deploy/identity/loopback-runtime.mjs container-edge
