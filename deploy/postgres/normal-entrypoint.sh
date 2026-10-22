#!/bin/sh
# The image clears the environment and sets NNP before this fixed entrypoint.
fail() { printf '%s\n' 'PostgreSQL startup unavailable.' >&2; exit 1; }
[ "$#" -eq 0 ] || fail
listen_addresses=$(/usr/bin/env -i PATH=/usr/lib/postgresql/17/bin:/usr/bin:/bin HOME=/tmp LANG=C UV_USE_IO_URING=0 \
  /usr/local/bin/node /opt/whoop-postgres/listen-addresses.mjs) || fail
[ -n "$listen_addresses" ] || fail
# One quoted numeric argument; no eval, caller arguments or wildcard fallback.
# exec preserves PostgreSQL as PID1 and its original signal handling.
exec /usr/bin/env -i PATH=/usr/lib/postgresql/17/bin:/usr/bin:/bin HOME=/tmp LANG=C \
  /usr/lib/postgresql/17/bin/postgres -D /var/lib/postgresql/data/pgdata \
  -c config_file=/var/lib/postgresql/data/config/postgresql.conf \
  -c "listen_addresses=$listen_addresses"
