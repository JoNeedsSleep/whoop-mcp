FROM node@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392
WORKDIR /gateway
COPY --chown=node:node gateway.mjs auth.mjs store.mjs server.mjs config.mjs index.mjs provision.mjs ./
USER node
ENV NODE_ENV=production
CMD ["node", "index.mjs"]
