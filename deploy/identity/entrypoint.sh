#!/bin/sh
# Fixed noninteractive bridge: never evaluate input or pass a secret in argv.
fail() { printf '%s\n' 'Identity entrypoint unavailable.' >&2; exit 1; }
[ "$#" -eq 1 ] || fail
[ "${WHOOP_CLIENT_ID+x}" != x ] || fail
[ "${WHOOP_CLIENT_SECRET+x}" != x ] || fail
[ "${DATABASE_URL+x}" != x ] || fail
[ "${PGPASSWORD+x}" != x ] || fail
[ "${WHOOP_STAGING_BOOTSTRAP+x}" != x ] || fail
[ "${WHOOP_BOOTSTRAP+x}" != x ] || fail
[ "${WHOOP_BACKEND_BOOTSTRAP+x}" != x ] || fail
[ "${WHOOP_GATEWAY_BOOTSTRAP+x}" != x ] || fail
case "$1" in
  verify|init-volume)
    [ "${WHOOP_BACKEND_IDENTITY_BOOTSTRAP+x}" != x ] || fail
    if [ "$1" = verify ]; then
      exec /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin /usr/local/bin/node /app/deploy/identity/runtime.mjs
    else
      exec /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin /usr/local/bin/node /app/deploy/identity/provision.mjs init-volume
    fi
    ;;
  provision-identity)
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
    [ "${WHOOP_BACKEND_IDENTITY_BOOTSTRAP+x}" = x ] || fail
    [ "${#WHOOP_BACKEND_IDENTITY_BOOTSTRAP}" -gt 0 ] && [ "${#WHOOP_BACKEND_IDENTITY_BOOTSTRAP}" -le 8192 ] || fail
    printf '%s' "$WHOOP_BACKEND_IDENTITY_BOOTSTRAP" |
      /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin /usr/local/bin/node /app/deploy/identity/provision.mjs provision-identity-stdin
    status=$?
    unset WHOOP_BACKEND_IDENTITY_BOOTSTRAP
    exit "$status"
    ;;
  *) fail ;;
esac
