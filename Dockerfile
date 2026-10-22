FROM node:22-slim AS build
WORKDIR /app
# No lifecycle scripts, forwarded credentials, home directories or host mounts.
COPY package.json package-lock.json ./
COPY web/package.json ./web/
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
COPY web ./web
RUN node node_modules/typescript/bin/tsc && npm run build --workspace web --ignore-scripts

FROM node:22-slim AS production-deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY web/package.json ./web/
RUN npm ci --omit=dev --workspaces=false --ignore-scripts --no-audit --no-fund

FROM node:22-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=production-deps /app/node_modules ./node_modules
COPY package.json ./
COPY --from=build /app/dist ./dist
COPY --from=build /app/web/dist ./web/dist
COPY drizzle ./drizzle
USER node
EXPOSE 8080
CMD ["node", "dist/index.js"]
