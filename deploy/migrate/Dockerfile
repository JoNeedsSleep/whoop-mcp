# Separate one-off artifact. No application, WHOOP, HTTP or Tailscale code.
# migration-artifact is prepared from the reviewed lock in an approved offline
# builder, with only the pg/drizzle-orm runtime dependency closure and migrations.
# The local tar preserves reviewed dependency bytes when the upload client omits
# paths named node_modules. ADD extracts only this validated local archive.
FROM node@sha256:efd0ab5780c2d9ab1f0f869571a00d5edb17793bff4cce4a2792e3eb0ffc7562
WORKDIR /app
ADD migration-dependencies.tar /app/node_modules/
COPY migration-artifact/drizzle ./drizzle
COPY deploy/migrate/migrate.mjs deploy/migrate/bootstrap.mjs deploy/migrate/entrypoint.sh /app/deploy/migrate/
COPY deploy/railway/config.mjs /app/deploy/railway/
COPY deploy/staging/runtime-check.mjs /app/deploy/staging/
USER node
ENTRYPOINT ["/usr/bin/setpriv", "--no-new-privs", "--", "/bin/sh", "/app/deploy/migrate/entrypoint.sh"]
CMD []
