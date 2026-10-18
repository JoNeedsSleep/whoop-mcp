# Independent WHOOP gateway

This directory contains the gateway HTTP transport, authorization server and
durable store. It runs separately from the WHOOP service and has no model API
keys, model account sessions, WHOOP OAuth credentials or WHOOP database access.
Keep the PR draft. Deployment, DNS and real WHOOP setup remain separate actions;
the localhost sample dashboard is not this gateway.

## What is implemented

- Streamable HTTP MCP at `/mcp`: initialize, ping, list the one fixed tool, and
  call `get_health_summary` with a UTC date. No raw records, upstream tool
  discovery, sampling, prompts, resources or server-initiated requests.
- OAuth discovery, pre-registered public clients, S256 PKCE, explicit resource
  audience, browser-bound owner login and consent, single-use five-minute codes.
- Independent owner sign-in using a random gateway-only secret. The runtime
  stores only its SHA-256 hash. Never enter a WHOOP, Google, OpenAI or Anthropic
  password here. Browser sessions and each client's access last seven days,
  measured from issuance, without sliding renewal. No OAuth refresh grant.
- `/owner` revokes Codex or Claude Code independently; revoke-all also invalidates
  owner sessions and pending flows/codes. Revocation stops subsequent checks,
  not a request already executing. Closing a client does not revoke its token.
- SQLite persists hashed tokens, sessions, pending flows and a shared 30-call
  rolling hourly budget. Failed tool calls count. One upstream request may run
  at a time; a crash lease expires after 15 seconds. Restarting or using both
  clients cannot reset the budget. Run one replica with one persistent local DB;
  separate database copies do not coordinate quotas or revocation.
- Explicit native loopback callbacks, fixed ports and exact paths. No wildcard
  redirects, client metadata fetching, CIMD, dynamic registration or client
  secrets. Both client registrations are configured before startup.

## Runtime preparation after deployment approval

Use Node 22.23.3 or the digest-pinned image in this directory. No npm packages
are used by the gateway runtime. `node:sqlite` is experimental in this Node
release. The tests also use the already-locked MCP SDK to check interoperability.

1. Provision a dedicated gateway environment and private persistent directory
   owned by its unprivileged UID, mode `0700`. Do not share either with WHOOP.
2. In the approved environment, create a new private secret-staging directory
   and run `node provision.mjs /absolute/private/staging-directory`. It refuses
   existing key files and never prints the generated secrets. Import `owner-key`
   and `whoop-service-token` into the approved secret store. Only the latter is
   mounted into the gateway runtime as a regular read-only `0600`/`0400` file.
   The operator uses the owner key at the gateway login page; do not send it in
   chat, shell arguments, URLs, screenshots or logs.
3. Fill a copy of `config.example.json`. `ownerSecretHash` comes from
   `hashes.json`; `upstreamTokenFile` points to the dedicated service-token file.
   Configure only `GATEWAY_SERVICE_TOKEN_SHA256` from `hashes.json` on the WHOOP
   service. This credential authorizes only its bounded summary endpoint for
   the configured WHOOP identity. It cannot log in or access legacy MCP. Omit
   the hash to disable the summary endpoint. User PATs are not accepted there.
4. Set distinct canonical HTTPS origins for the gateway and WHOOP backend.
   Keep configuration read-only to the runtime and not writable by other users.
   Set `GATEWAY_CONFIG_FILE` to its absolute path and run `node index.mjs` in
   the isolated gateway. It binds only `127.0.0.1`; it does not terminate TLS.
5. Put the reviewed TLS ingress in the same network namespace. It must preserve
   the canonical gateway `Host`, reject other hosts, restrict ingress to the
   owner/authorized clients, and avoid logging query strings, cookies, forms
   and Authorization headers. Keep WHOOP admin/OAuth ingress separately
   protected. Default-deny gateway egress except the fixed WHOOP endpoint;
   default-deny WHOOP egress except WHOOP API and its own database. Enforce these
   outside the WHOOP process. No personal files, SSH agents or admin credentials.
6. Check HTTPS cookie behavior, revocation, denied foreign traffic and restore
   of the gateway DB through that actual topology before using real data. Do
   not reset/delete the DB to clear a rate limit. Backups remain sensitive;
   restoring an older DB may resurrect revoked tokens until their expiry, so
   revoke all before reopening restored ingress. Protect the host clock.

The machine credential intentionally has an independent operational lifecycle:
it does not expire at every user login. Rotate by replacing the private gateway
file and matching WHOOP hash, then restarting both. Removing the WHOOP hash
revokes it. Keep the raw machine key out of the WHOOP service. Rotating the owner
key/hash invalidates owner sessions; revoke-all first to invalidate client
grants too. Losing WHOOP's upstream grant still requires reconnecting WHOOP.

## Connect Codex

After the gateway is reachable at its approved HTTPS address, merge this into
the Codex configuration for the intended scope. Replace the example URL with
that gateway's `/mcp` endpoint. Do not replace unrelated configuration.

```toml
[mcp_servers.whoop]
url = "https://gateway.example.invalid/mcp"
enabled_tools = ["get_health_summary"]

[mcp_servers.whoop.oauth]
client_id = "codex"
callback_url = "http://127.0.0.1:17643/callback"
callback_port = 17643
```

Run `codex mcp login whoop`, sign in to the gateway in your browser and approve
Codex. Use `/mcp` to check its status. Local app, CLI and IDE clients on the same
Codex host share configuration. The gateway advertises issuer identification
and returns `iss`, allowing this stable pre-registered callback. If a port is
occupied, change both the client's listener/callback and its gateway registration
to another explicitly reviewed port. [Official Codex MCP documentation](https://developers.openai.com/codex/mcp).

## Connect Claude Code

From the intended project, after substituting the approved gateway URL:

```sh
claude mcp add --transport http --scope local --client-id claude-code --callback-port 17644 whoop https://gateway.example.invalid/mcp
```

Open `/mcp` in Claude Code and authenticate WHOOP. The gateway browser session
can be reused, but Claude Code gets a separate authorization and consent. Do
not pass `--client-secret` or a bearer header. This uses
`http://localhost:17644/callback`; versions that send a different callback must
be upgraded or have that exact callback separately reviewed and registered.
Use both clients concurrently; revoke either on the gateway's `/owner` page.
After seven days, authenticate again. [Official Claude Code MCP documentation](https://code.claude.com/docs/en/mcp).

These steps do not configure cloud-hosted clients. They require the local client
and browser to reach the protected gateway. A private Tailscale HTTPS name can
be used initially; custom-domain/public ingress is a separate deployment choice.

## Validation

Run only in the approved isolated Node 22 environment with the repository's
verified cached dependencies and synthetic secrets. The TLS fixture requires
OpenSSL inside that environment, or `GATEWAY_TEST_TLS_DIR` pointing to an
explicit private synthetic fixture containing `ca.pem`, `server.pem` and
`server-key.pem`. Certificate and hostname verification remain enabled:

```sh
node --test review-gateway/*.test.mjs
```

Native HTTP and locked-SDK tests exercise both callback shapes, OAuth discovery,
PKCE, consent and code replay, bearer use, persisted expiry, revocation, shared
budgets and malicious upstream results. They do not substitute for checking the
installed Codex/Claude binaries and actual protected TLS deployment. See the
root `SECURITY_REVIEW.md` for run results and remaining release conditions.
