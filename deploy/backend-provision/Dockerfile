# Preparation only: no npm, backend, database, HTTP or Tailscale binaries.
FROM node@sha256:efd0ab5780c2d9ab1f0f869571a00d5edb17793bff4cce4a2792e3eb0ffc7562
WORKDIR /app
COPY deploy/railway/config.mjs /app/deploy/railway/
COPY deploy/staging/runtime-check.mjs /app/deploy/staging/
COPY deploy/backend-provision/provision.mjs deploy/backend-provision/entrypoint.sh /app/deploy/backend-provision/
USER node
ENTRYPOINT ["/usr/bin/setpriv", "--no-new-privs", "--", "/bin/sh", "/app/deploy/backend-provision/entrypoint.sh"]
CMD []
