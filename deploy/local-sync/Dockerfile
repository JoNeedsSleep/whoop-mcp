FROM node@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392
WORKDIR /app
COPY deploy/local-sync/runtime.mjs deploy/local-sync/login.mjs deploy/local-sync/oauth.mjs deploy/local-sync/state.mjs deploy/local-sync/sync.mjs deploy/local-sync/snapshot.mjs deploy/local-sync/entrypoint.sh /app/deploy/local-sync/
COPY deploy/local-view/snapshot.mjs /app/deploy/local-view/
COPY deploy/identity/verify.mjs deploy/identity/loopback-ingress.mjs /app/deploy/identity/
COPY deploy/railway/config.mjs /app/deploy/railway/
COPY deploy/staging/runtime-check.mjs /app/deploy/staging/
COPY restricted-local/policy.mjs restricted-local/cache.mjs /app/restricted-local/
USER 1000:1000
ENTRYPOINT ["/bin/sh","/app/deploy/local-sync/entrypoint.sh"]
CMD ["sync"]
