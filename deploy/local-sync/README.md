# Local WHOOP connection

This mode keeps the WHOOP connection on one personal laptop. One isolated sync
process updates two separate caches; Codex and Claude Code each read their own
cache through the restricted, offline MCP reader.

## Use

Authorize the local WHOOP app in the browser and confirm the displayed account.
The connection lasts seven days from that confirmation. Refreshing tokens does
not extend the deadline. A fresh WHOOP authorization is required after expiry.
The WHOOP password or Google login stays with WHOOP and the browser.

The background worker attempts a sync every 15 minutes after the previous
attempt finishes. The laptop and OrbStack must be running. Sleeping pauses work;
waking does not cause a burst of missed syncs. There is also a durable 15-minute
admission check, so restarting the worker cannot repeatedly refresh the grant.

The MCP tool is `get_health_summary`, with a UTC date argument. Its output is a
validated numerical daily summary from the most recent seven-day collection.
Reader caches expire after 90 minutes, or at the seven-day authorization
deadline if earlier. Stale data produces `LOCAL_HEALTH_DATA_UNAVAILABLE`.
Neither reader logs in, refreshes credentials, downloads code, or contacts WHOOP.
When an assistant calls the tool, the requested summary enters its conversation
and may be sent to that client's model provider. Local storage and syncing do
not make Codex or Claude's model inference local. OAuth credentials are never
part of the reader output.

## Boundaries

- Login uses the registered `http://localhost:17645/whoop/callback`. The host
  listener is published on loopback only. State, PKCE, browser cookies, an
  ingress marker and explicit account confirmation protect the local return.
- The app runs in a pinned Node 22 container with a read-only root filesystem,
  no host-directory mounts, no forwarded credentials or SSH agent, no added
  capabilities and no privilege escalation. Sync publishes no ports.
- The sync container mounts only a private authorization volume and the two
  cache volumes. Its network namespace permits one verified public WHOOP IPv4
  address on port 443; the HTTP clients enforce the official TLS hostname and
  fixed paths. There are no redirects or automatic retries.
- The authorization volume contains the WHOOP client secret, access and refresh
  tokens, and the confirmed numerical account ID. It is not mounted in either
  reader. Names and email addresses are not retained there.
- Each reader has no network, no authorization volume and one read-only cache
  mount. Its tool definitions and output schema are local code, not remote MCP
  instructions. Unknown fields, arbitrary text and invalid values fail closed.
- A single writer lock covers login, refresh and collection. Rotated tokens are
  persisted before health requests. An interrupted or ambiguous refresh requires
  reauthorization instead of reusing the old token. Cache writes are atomic.

Docker volume isolation is not encryption at rest and does not protect against
an administrator or a compromised Docker daemon on this laptop. A compromised
sync process can access its WHOOP tokens and permitted health data. The offline
reader reduces the path from remote content into the assistants; it does not
make the assistants or the laptop immune to compromise.

Expiry denies reader access even while the laptop is asleep. Provider revocation
and local credential cleanup can occur only when the worker next runs, and
provider revocation can fail if WHOOP is unreachable. Removing local credentials
does not prove erasure from storage snapshots or backups.

## Operator and clients

The host operator and reader bridge are trusted orchestration. They use a fixed
Docker socket with an empty Docker credential configuration, clear the inherited
environment, verify image IDs and exact volume labels, and verify container
settings before running application code. The operator sends initial app
credentials through a pipe only after its isolation checks pass. Subsequent
syncs read credentials solely inside the authorization container.

Client entries must launch `reader-launch.mjs` through an environment-clearing
wrapper with the literal client argument `codex` or `claude-code`. They must not
point at the legacy network-enabled MCP server. Leave ordinary client approval
and sandbox settings in place. A client may need a new session to load a newly
added MCP entry.

The quiet background worker records only operation status and isolation
evidence. It does not emit health values, tokens, OAuth codes or desktop
notifications. Its files and receipts belong in a private local installation;
they must not be committed.

## Validation

Tests use synthetic identities and tokens in isolated Node 22 containers with
no network. They cover token rotation, interrupted refresh, competing writers,
durable rate admission, expiry and clock rollback, login cancellation and
handoff, callback validation, cache rejection and reader cleanup. Live validation
must separately confirm container and network controls, human WHOOP consent,
successful cache publication and both client connections. A passing synthetic
suite alone does not establish a live WHOOP connection.

The initial combined suite passed 67 tests. A native Claude Code connection
then exposed additional standard `clientInfo` fields that the strict reader
rejected. A reviewed compatibility fix accepts bounded `description` and
`websiteUrl` strings and discards them without fetching or reflecting them.
The final reader/bridge suite passed 22 tests, including the installed client's
metadata shape, and the packaged reader passed stdio checks for both clients.
Sync/auth code and its immutable image were unchanged by that reader fix.

Live activation subsequently verified the local seven-day grant, one successful
sync, seven available dates through both installed client entries, a native
Codex tool call and Claude Code's native connection check. The quiet scheduler
was registered and its first attempt was correctly limited by the durable
15-minute gate. Verification records contain status/counts and isolation
metadata, not profile details, tokens or health measurements.
