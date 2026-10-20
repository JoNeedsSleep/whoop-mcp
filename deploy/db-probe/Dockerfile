# Reuse the integrity-verified dependency tree from the reviewed migration
# artifact; only pg is imported. No migration SQL, app or enrollment module.
FROM node@sha256:efd0ab5780c2d9ab1f0f869571a00d5edb17793bff4cce4a2792e3eb0ffc7562
WORKDIR /app
ADD db-probe-dependencies.tar /app/node_modules/
COPY deploy/db-probe/probe.mjs deploy/db-probe/entrypoint.sh /app/deploy/db-probe/
COPY deploy/staging/runtime-check.mjs /app/deploy/staging/
USER node
ENTRYPOINT ["/usr/bin/setpriv", "--no-new-privs", "--", "/bin/sh", "/app/deploy/db-probe/entrypoint.sh"]
CMD []
