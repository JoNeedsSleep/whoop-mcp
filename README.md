> **Security review branch — not deployment-ready.** This fork now requires a single WHOOP identity, explicit HTTPS origin and approved callbacks. The upstream deployment instructions below do not describe the hardened branch. Read [SECURITY_REVIEW.md](SECURITY_REVIEW.md) for the changes, untested checks, scope limits and separately trusted gateway design before installation or account connection. Do not use the one-click deployment steps for this review draft.

# WHOOP MCP Server

A multi-user [MCP](https://modelcontextprotocol.io) server that exposes WHOOP
fitness data (recovery, sleep, workouts, cycles, profile, body measurements)
to AI clients such as Claude, ChatGPT, and local editors (Cursor, Cline).

Each user connects their own WHOOP account via OAuth and only ever sees their
own data. The server acts as a full OAuth 2.1 authorization server for MCP
clients, delegating identity to WHOOP as the upstream identity provider.

Data is fetched live from the WHOOP API on every tool call — no fitness data
is cached or stored. Postgres only holds user identity and encrypted tokens.

> **Disclaimer:** This is an independent, community open-source project. It is
> **not affiliated with, endorsed by, or sponsored by WHOOP.** "WHOOP" is a
> trademark of Whoop, Inc., used here only to describe what the software
> connects to.

## Two ways to use this

There are two ways to get WHOOP data into your AI client:

- **A. Self-host as a remote connector** (this README) — run your own instance
  (Railway 1-click, Docker, Fly.io, Render, ...) and connect any MCP client to
  it over HTTP, either via OAuth or a personal access token.
- **B. Local Claude Desktop extension** (see **Local Claude Desktop
  extension** below) — a free, packaged `.mcpb` extension that runs entirely
  on your machine. No hosting, no database: your WHOOP tokens are encrypted
  and stored locally under your OS config directory. Claude Desktop only
  (not the browser).

## 1-Click deploy on Railway

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/ZNtnVI?referralCode=zJwp1p&utm_medium=integration&utm_source=template&utm_campaign=generic)

1. Click the button above — Railway provisions the app service and a Postgres
   database, and auto-generates `ENCRYPTION_KEY` and `SESSION_SECRET`.
2. Copy your new Railway domain.
3. Create a WHOOP developer app (see **WHOOP app setup** below).
4. Enter `WHOOP_CLIENT_ID` and `WHOOP_CLIENT_SECRET` as service variables in
   Railway, then redeploy.
5. *(Optional)* To limit who can connect, set `RESTRICT_ACCESS=true` and
   `ALLOWED_WHOOP_EMAILS=…` — both are offered as optional fields on the deploy
   form and can be changed later. See **Sharing your instance with friends** below.
6. Connect an AI client (see **Connect an AI client** below).

## WHOOP app setup

> This is for the **self-hosted** instance (Way A). The local extension (Way B)
> uses a different redirect URI — see its own setup in the *Local Claude Desktop
> extension* section below.

1. Register a developer application at the [WHOOP Developer Portal](https://developer.whoop.com/).
2. Set the app's **redirect URI** to:

   ```
   https://<your-domain>/whoop/callback
   ```

3. Request the scopes:

   ```
   read:recovery read:sleep read:workout read:cycles read:profile read:body_measurement offline
   ```

4. Copy the client ID and secret — you'll enter these as `WHOOP_CLIENT_ID` /
   `WHOOP_CLIENT_SECRET`.

## Running on other hosts

Copy `.env.example` to `.env` and fill in:

| Variable | Description |
|---|---|
| `DATABASE_URL` | Postgres connection string. |
| `ENCRYPTION_KEY` | 32-byte hex key used to encrypt stored WHOOP tokens at rest. Generate with `openssl rand -hex 32`. |
| `WHOOP_CLIENT_ID` | Client ID from your WHOOP developer app. |
| `WHOOP_CLIENT_SECRET` | Client secret from your WHOOP developer app. |
| `PUBLIC_BASE_URL` | The publicly reachable base URL of this deployment, e.g. `https://your-app.example.com` (no trailing slash). Used to build OAuth redirect/callback URLs. On Railway this is derived automatically from `RAILWAY_PUBLIC_DOMAIN` when not set explicitly; on other hosts you must set it explicitly. |
| `SESSION_SECRET` | Secret used to sign the dashboard's session cookie. Generate with `openssl rand -hex 32`. |
| `PORT` | Port to listen on. Defaults to `8080`. |
| `RESTRICT_ACCESS` | Optional. `true` to enforce the allowlist below; anything else (default) leaves the server open to anyone with the URL. See *Sharing your instance with friends*. |
| `ALLOWED_WHOOP_EMAILS` | Optional. Comma-separated WHOOP account emails allowed to connect **when `RESTRICT_ACCESS=true`**. Ignored when restriction is off. |

### Docker / your own VPS

```bash
docker build -t whoop-mcp . && docker run -p 8080:8080 --env-file .env whoop-mcp
```

Set `PUBLIC_BASE_URL` explicitly in your `.env` — there's no
`RAILWAY_PUBLIC_DOMAIN` to fall back on outside Railway.

### Fly.io

`fly launch` uses the repo's Dockerfile. Set secrets via
`fly secrets set KEY=value ...`, and provision Postgres via `fly postgres create`.

### Render

Create a Web Service from this repo using the Docker environment, add a
Postgres add-on, and set the env vars from the table above in the Render
dashboard.

## Connect an AI client

### Browser (Claude.ai / ChatGPT)

1. Add a remote MCP connector pointing at:

   ```
   https://<your-domain>/mcp
   ```

2. The client discovers the OAuth endpoints automatically, redirects you
   through "Connect WHOOP", and starts calling tools (e.g.
   `get_daily_summary`) under your own WHOOP identity.

### Claude Desktop (remote)

Add a custom connector with the same URL, `https://<your-domain>/mcp`, and
go through the same "Connect WHOOP" OAuth flow.

### Optional: local clients via personal access token

1. Open the dashboard at `https://<your-domain>/dashboard` and click
   **Connect WHOOP**.
2. Once connected, click **Create personal access token** and copy the token
   (it is only shown once).
3. Configure your client's `mcp.json` to call `https://<your-domain>/mcp`
   with the token as a bearer header, for example:

```json
{
  "mcpServers": {
    "whoop": {
      "url": "https://<your-domain>/mcp",
      "headers": {
        "Authorization": "Bearer <PAT>"
      }
    }
  }
}
```

Revoke a token at any time from the dashboard, or delete your account
entirely (removes your WHOOP connection and all issued tokens).

### Sharing your instance with friends (multi-user)

The server is multi-user by design: anyone you point at your deployment
connects their **own** WHOOP account and only ever sees their own data —
exactly how the project author runs it for a small circle. To invite a friend,
just share your `https://<your-domain>/mcp` connector URL (or the dashboard
link); they go through their own "Connect WHOOP" flow. There's no per-user
setup on your side.

Two things to keep in mind before inviting people:

- **WHOOP app user limit:** a WHOOP developer app in development mode is capped
  at a small number of users (around 10). Fine for friends; a larger audience
  requires WHOOP's production review.
- **Data responsibility:** once others connect, their (encrypted) WHOOP tokens
  live in *your* database, and you become responsible for that data (e.g. GDPR
  if you're in the EU). Only invite people who are comfortable with that.

**Restricting who can connect.** By default anyone who reaches your URL can
connect their WHOOP and use the server. To lock it down to specific people, set
**both** env vars:

```
RESTRICT_ACCESS=true
ALLOWED_WHOOP_EMAILS=me@example.com,friend@example.com
```

With `RESTRICT_ACCESS=true`, only those WHOOP-account emails may connect; everyone
else is rejected at login (no account or token is created). Leave `RESTRICT_ACCESS`
unset (or `false`) to keep the server open — the email list is then ignored. The
server logs a warning at startup if the two are misconfigured (restriction on with
an empty list, or a list set while restriction is off).

## Local Claude Desktop extension (Way B)

A free, local alternative to self-hosting: a `.mcpb` extension that runs as a
subprocess inside Claude Desktop. There's no server to host and no database —
your WHOOP tokens are encrypted and stored on disk under your OS config
directory. Claude Desktop only; this doesn't work in the browser (Claude.ai
or ChatGPT), since those need a remote connector.

### 1. Get the extension

Either build it yourself:

```bash
npm run bundle:local
```

which produces `whoop-mcp.mcpb` in the repo root, or — if you don't have Node
set up — download the prebuilt `whoop-mcp.mcpb` from the
[latest release](https://github.com/caxtmann/whoop-mcp/releases/latest).

### 2. Install it

Install the `.mcpb` into Claude Desktop with any of these — if a double-click
does nothing (macOS may not associate the `.mcpb` file type), use the
**Advanced settings** route, which always works:

- **Advanced settings (most reliable):** in Claude Desktop go to **Settings →
  Extensions → Advanced settings → Extension Developer → Install Extension…**
  and pick your `whoop-mcp.mcpb`.
- **Drag & drop:** drag `whoop-mcp.mcpb` onto the Claude Desktop **Settings**
  window.
- **Double-click:** open `whoop-mcp.mcpb` from Finder (works on most, but not
  all, installs).

The install dialog asks for your **WHOOP Client ID** and **WHOOP Client
Secret** — enter the credentials from your own WHOOP developer app (see below).
The secret is stored securely in your OS keychain.

### 3. Create your own WHOOP app

1. Register a developer application at the [WHOOP Developer Portal](https://developer.whoop.com/).
2. Set the app's **redirect URI** to exactly:

   ```
   https://caxtmann.github.io/whoop-mcp/callback/
   ```

   This callback page is a tiny static page — it only displays the `code` and
   `state` for you to copy back, holds no secret, and stores no data. It is
   shared by all users of this extension. If you'd rather not depend on it, host
   your own copy of [`callback/index.html`](callback/index.html) (e.g. on your
   own GitHub Pages), use that URL as the redirect URI here, and set the optional
   **Redirect URI** field in the install dialog to the same URL — it overrides
   the default.

3. Request the scopes:

   ```
   read:recovery read:sleep read:workout read:cycles read:profile read:body_measurement offline
   ```

4. Copy the client ID and secret — enter these in the install dialog above.

### 4. Log in

1. Run the `whoop_login` tool.
2. Open the URL it returns and approve access on WHOOP.
3. WHOOP redirects to the callback page, which displays a `code` and
   `state` — copy both.
4. Run the `whoop_complete_login` tool with that `code` and `state`.

### 5. Use it

Once logged in, call the data tools directly, e.g. `get_daily_summary`,
`get_recovery`, `get_sleep`.

## Running locally (development)

1. Set up a local Postgres database and configure `DATABASE_URL`.
2. Run the setup commands:

```bash
npm install
npm run db:migrate
npm run dev
```

The server will start at `http://localhost:8080`. Check health with `GET /healthz`, which returns `{"ok":true}` once running.

## License

[MIT](LICENSE) © Christian Axtmann
