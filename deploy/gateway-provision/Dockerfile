# Temporary stopped-gateway configuration consumer; no daemon, npm or application.
FROM node@sha256:efd0ab5780c2d9ab1f0f869571a00d5edb17793bff4cce4a2792e3eb0ffc7562
WORKDIR /app
COPY deploy/railway/config.mjs ./deploy/railway/
COPY deploy/staging/runtime-check.mjs ./deploy/staging/
COPY review-gateway/config.mjs ./review-gateway/
COPY deploy/gateway-provision/provision.mjs deploy/gateway-provision/entrypoint.sh ./deploy/gateway-provision/
USER node
ENTRYPOINT ["/usr/bin/setpriv", "--no-new-privs", "--", "/bin/sh", "/app/deploy/gateway-provision/entrypoint.sh"]
CMD ["configure"]
