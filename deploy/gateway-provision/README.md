# Stopped gateway configuration handoff

This temporary, nonroot consumer switches the existing gateway from the synthetic
fixture to one approved real backend. It does not start any network client,
Tailscale daemon, application or database. Preparing it is not authorization to
deploy it or expose real data.

Before switching targets, use the existing owner route to revoke all client
grants and verify that the old grants receive 401. Then stop the gateway and
ensure no old or new deployment can overlap the handoff. Preserve the existing
SQLite database, quotas, owner verifier, callback registrations and node state.
After a clean normal restart, obtain fresh client grants. Existing synthetic
grants must never acquire access to real data.

Use the existing gateway's separately approved staging operator, not the new
production-environment token. The only bootstrap variable is
`WHOOP_GATEWAY_CONFIG_BOOTSTRAP`. Its bounded JSON envelope has exactly:

```json
{
  "mode": "whoop-gateway-backend-cutover",
  "hostname": "gateway.example.ts.net",
  "backendHostname": "backend.example.ts.net",
  "backendIpv4": "100.90.80.70",
  "serviceToken": "<approved dedicated gateway-to-backend machine credential>",
  "expected": {
    "appSha256": "<SHA256 of current app.json bytes>",
    "runtimeSha256": "<SHA256 of current runtime.json bytes>",
    "tokenFileSha256": "<SHA256 of current service-token bytes, including newline>",
    "stagingMarkerSha256": "<SHA256 of current staging-gateway.json bytes>"
  }
}
```

The old bytes and staging marker must describe the reviewed synthetic gateway
with its two exact native callback registrations. All hashes and schemas are
validated before writing. The backend name/IP and distinct machine credential
are explicit approved operator inputs; schema validation does not authorize
them. Derive the expected hashes from attested original configuration bytes or
a separately reviewed fixed-file hash observation, never from guesses.

The temporary image also supports the fixed `inspect` shell mode with no
bootstrap present. It validates the same four current private files and emits
only one JSON event `gateway-configuration-hashes` with `appSha256`,
`runtimeSha256`, `tokenFileSha256` and `stagingMarkerSha256`, then holds without
starting a service. It accepts no filename and never reads SQLite or node
credential contents. Record this stopped-volume observation before preparing
the cutover envelope; inspection neither authorizes a target nor performs it.

The fixed shell runs under `setpriv --no-new-privs`, requires all real/effective
UID/GID values to be 1000, and passes the value via bounded stdin to Node after
`env -i`. There is no secret argument or arbitrary command/path mode. Initial
shell environment and provider variable/deployment history can still retain the
bootstrap. Remove it, inspect the finished phase and replace the temporary
deployment with a fresh normal image. Variable deletion can itself redeploy a
provider's old phase; that phase fails closed without its required bootstrap.
Normal mode rejects leftover bootstrap before starting Node with a clean
environment. Revoke delegated operator tokens and remove their exact containers
within 24 hours or the shorter approved session.

The consumer claims the same exclusive `/data/tailscale/runtime.lock` as the
normal supervisor. It never clears a stale/existing lock. It creates one private
`/data/config/gateway-cutover` attempt containing old files, staged new files and
a fixed phase marker. It removes active `runtime.json` before publishing the
new app/token, then atomically publishes the new runtime last. Successful
completion removes only the exact owned lock inode. Failures before final lock
release keep the lock, private backups and phase evidence and refuse retries.
A directory-fsync failure after final unlink can report failure after the lock
is released; at that point all committed files are already verified and synced. Do not delete
the attempt or lock to retry: stop the consumer and inspect/recover the specific
failed phase under a separate reviewed procedure. Backups contain the old
machine credential and require the same private-volume protection.

This is a stopped-service operation, not a general live configuration
transaction. A startup that already read old files before waiting for the lock
cannot be recalled; provider stop/no-overlap is mandatory. The same UID can
modify its own configuration. The preserved staging marker intentionally no
longer matches the new target, so the synthetic-only wrapper cannot be reused.
The consumer never reads or rewrites SQLite or Tailscale credential files.

Local preparation passed on 2026-10-19: 22 source tests, no failures/skips, plus
the actual packaged AMD64 shell inspector and synthetic configuration handoff.
Both fresh fixtures passed all 12 isolation checks, source hashes and exact
container cleanup. Packaged checks verified that hostile Node/OpenSSL settings
were cleared before Node, outputs contained only fixed status/hash fields, the
owner/clients/database/node bytes were preserved, and no listener or daemon was
started. AMD64 ran through OrbStack translation, not native Railway.

The temporary configuration image is
`sha256:09f2f17b008f97fe3da1fd6ed7a236e1d8eebe6abc7f68a9f27b31b3ee243bcd`.
Evidence is under the private local `gateway-provision-20261019a` directory:
source run `attempt-20261019T060335-7af97722`, packaged run
`attempt-20261019T060412-d8143bbf`, and final
`gateway-provision-result.json` SHA256
`542674040be64d167b7790274475fd34bf6419fb35acb846e53e3e787d936997`.
The manifest's original `smoke_pending` field records build-time state; the final
report and packaged-run result record the completed check. No provider action,
real secret or data was used. Known runtime advisories and the provider's
filesystem/egress limits remain; this is not release or activation approval.
