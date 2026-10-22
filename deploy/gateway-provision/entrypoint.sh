#!/bin/sh
# Pinned noninteractive shell; never evaluate input or put secrets in argv.
fail() { printf '%s\n' 'WHOOP gateway configuration unavailable.' >&2; exit 1; }
[ "$#" -eq 1 ] || fail
[ "${WHOOP_STAGING_BOOTSTRAP+x}" != x ] || fail
[ "${WHOOP_BOOTSTRAP+x}" != x ] || fail
[ "${WHOOP_BACKEND_BOOTSTRAP+x}" != x ] || fail
[ "${WHOOP_BACKEND_APP_BOOTSTRAP+x}" != x ] || fail
[ "${WHOOP_BACKEND_IDENTITY_BOOTSTRAP+x}" != x ] || fail
[ "${WHOOP_GATEWAY_BOOTSTRAP+x}" != x ] || fail
[ "${WHOOP_POSTGRES_PROVISION+x}" != x ] || fail
[ "${WHOOP_MIGRATION_BOOTSTRAP+x}" != x ] || fail
case "$1" in
  normal|inspect)
    [ "${WHOOP_GATEWAY_CONFIG_BOOTSTRAP+x}" != x ] || fail
    if [ "$1" = normal ]; then
      exec /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin /usr/local/bin/node /app/deploy/railway/gateway-runtime.mjs /data/config/runtime.json
    else
      exec /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin /usr/local/bin/node /app/deploy/gateway-provision/provision.mjs inspect
    fi
    ;;
  configure)
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
    [ "${WHOOP_GATEWAY_CONFIG_BOOTSTRAP+x}" = x ] || fail
    [ "${#WHOOP_GATEWAY_CONFIG_BOOTSTRAP}" -gt 0 ] && [ "${#WHOOP_GATEWAY_CONFIG_BOOTSTRAP}" -le 8192 ] || fail
    printf '%s' "$WHOOP_GATEWAY_CONFIG_BOOTSTRAP" |
      /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin /usr/local/bin/node /app/deploy/gateway-provision/provision.mjs configure-stdin
    status=$?
    unset WHOOP_GATEWAY_CONFIG_BOOTSTRAP
    exit "$status"
    ;;
  *) fail ;;
esac
