# Independent WHOOP gateway

This directory contains the gateway HTTP transport, authorization server and
durable store. It runs separately from the WHOOP service and has no model API
keys, model account sessions, WHOOP OAuth credentials or WHOOP database access.
Keep the PR draft. Deployment, DNS and real WHOOP setup remain separate actions;
the localhost sample dashboard is not this gateway.

For the current threat model, connect clients through the
[restricted offline local adapter](../restricted-local/README.md), not directly
to this gateway's `/mcp` endpoint. A compromised gateway can alter any direct MCP
response. The local adapter instead synchronizes data from `/data/snapshot` and
defines its own tools and messages on the laptop.

## What is implemented

- Streamable HTTP MCP at `/mcp`: initialize, ping, list the one fixed tool, and
  call `get_health_summary` with a UTC date. No raw records, upstream tool
  discovery, sampling, prompts, resources or server-initiated requests.
- Authenticated GET `/data/snapshot`: seven fixed UTC dates, no query or body,
  seven shared quota charges, bounded reconstructed data only. Rechecks the grant
  during collection and before returning; failures discard the whole snapshot.
- OAuth discovery, pre-registered public clients, S256 PKCE, explicit resource
  audience, browser-bound owner login and consent, single-use five-minute codes.
- Independent owner sign-in using a random gateway-only secret. The runtime
  stores only its SHA-256 hash. Never enter a WHOOP, Google, OpenAI or Anthropic
  password here. Browser sessions and each client's access last seven days,
  measured from issuance, without sliding renewal. No OAuth refresh grant.
- `/owner` revokes Codex or Claude Code independently; revoke-all also invalidates
  owner sessions and pending flows/codes. Revocation stops subsequent checks,
  not a request already executing. Closing a client does not revoke its token.
- SQLite persists hashed tokens, sessions, pending flows and a shared 70-summary-call
  rolling hourly budget. Failed tool calls count. One upstream request may run
  at a time; a crash lease expires after 15 seconds. Restarting or using both
  clients cannot reset the budget. Run one replica with one persistent local DB;
  separate database copies do not coordinate quotas or revocation.
  Both the durable store and in-memory adapter enforce the same 70-call ceiling:
  two clients × four snapshots/hour × seven summaries = 56 steady-state calls,
  plus 14 of rolling-window timing allowance. This is a summary budget, not a
  count of WHOOP API requests. Three WHOOP collections per summary mean about
  168 ordinary API requests/hour (4,032/day) before bounded pagination, token
  refresh and retries. This arithmetic is not a provider-limit or latency guarantee.
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
revokes it. Store only the verifier hash in WHOOP configuration; the service
still receives the raw bearer on HTTPS requests. A compromised service or its
TLS terminator can capture it. That credential authorizes the same bounded
summary route, not gateway or model-account login. Rotating the owner
key/hash invalidates owner sessions; revoke-all first to invalidate client
grants too. Losing WHOOP's upstream grant still requires reconnecting WHOOP.

## Connect local clients

Use the [restricted local adapter instructions](../restricted-local/README.md).
Each client connects to its own offline stdio reader; a separate login/sync
process holds its gateway grant. The callback ports identify those separate
local login processes, rather than granting a remote MCP server access to the
client. No installed client settings were changed during this review.

Direct HTTP MCP remains implemented for protocol testing and a narrower threat
model that trusts this gateway. Do not use it for the current user-facing setup:
that would restore the malicious-MCP path the local adapter is meant to remove.
The legacy local extension is also not a substitute for the restricted reader.

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
