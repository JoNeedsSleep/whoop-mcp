# Separate synthetic-only artifact: no npm, DB, WHOOP app or production backend.
FROM tailscale/tailscale@sha256:99691662a2e82fbfd2bf55db0fd52bacd2f4664ce6fd1deca3746a024144a2b7 AS tailscale
FROM node@sha256:efd0ab5780c2d9ab1f0f869571a00d5edb17793bff4cce4a2792e3eb0ffc7562
WORKDIR /app
COPY --from=tailscale /usr/local/bin/tailscale /usr/local/bin/tailscaled /usr/local/bin/
COPY --from=tailscale /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY deploy/railway/config.mjs deploy/railway/tailscale-supervisor.mjs ./deploy/railway/
COPY deploy/staging/service.mjs deploy/staging/runtime.mjs deploy/staging/bootstrap.mjs ./deploy/staging/
COPY deploy/staging/provision.mjs deploy/staging/provision-fixture.mjs ./deploy/staging/
COPY deploy/staging/runtime-check.mjs ./deploy/staging/
USER node
ENTRYPOINT ["/usr/bin/setpriv", "--no-new-privs", "--", "/usr/local/bin/node", "/app/deploy/staging/runtime.mjs"]
CMD ["/data/config/staging.json"]
