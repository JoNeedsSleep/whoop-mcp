# Synthetic staging upstream

This separate image supports the authorized Railway/Tailscale and two-client
callback test. It serves invented numeric summaries only. It contains no WHOOP
OAuth/client code, database driver, production backend, WHOOP login page, profile
or real health data. Do not connect WHOOP, supply WHOOP/database credentials or
present these fixtures as a person's measurements. The PR remains draft.

The service implements only a fixed health marker and the gateway's existing
`GET /internal/health-summary?date=YYYY-MM-DD` contract. Six of the latest seven
UTC days return fixed representative numbers; the oldest returns `NO_DATA`.
The exact Host and dedicated gateway machine credential are mandatory for data.
It cannot be pointed at an upstream or database: configuration has no such field,
and its code makes no outbound HTTP request. The Tailscale daemon still connects
to its control/relay services. Railway does not enforce default-deny remote
egress, so this is an intentionally limited fixture implementation, not a claim
that compromised arbitrary code could never open an Internet connection.

## Build and storage

Build only in the approved offline environment from an allowlisted snapshot.
Use `deploy/staging/Dockerfile` for the fixture and
`deploy/staging/Dockerfile.gateway` for the staging gateway, both AMD64. These
artifact-only Dockerfiles copy reviewed modules and pinned vendor binaries; they
run no npm installation, migration or `RUN` instruction. The gateway uses the
unchanged production authentication and private transport modules plus a staging
configuration wrapper. No WHOOP backend is copied into either image.

Preserve readable permissions when transferring the allowlisted public build
context. The reviewed local export uses mode 0444; a trusted source-only upload
may use 0644, with final image files owned by root and readable by UID 1000.
Verify the uploaded modes before building and verify module loading as UID 1000
before provisioning. Do not transfer public source as 0600: `COPY` preserves
that mode, which prevents the non-root process from importing root-owned modules.
Keep private configuration, token and enrollment transfers at 0600; the readable
source mode applies only to the reviewed, hash-allowlisted files in this context.

Each role gets its own fresh `/data` volume and node identity. The fixture needs
private `config` and `tailscale` directories; the gateway additionally needs
`app` for its independent SQLite authorization store. There is no WHOOP database.
All directories are UID/GID 1000 mode 0700 and configuration files are mode 0600.
Never share volumes or machine credentials with another application/environment.

## Temporary staging variable provisioning

The selected Railway provisioning path uses a temporary service variable through
the project-scoped control plane. It does not register an account/workspace SSH
identity, forward an SSH agent or add public ingress. This is a narrow staging
exception: `WHOOP_STAGING_BOOTSTRAP` contains only freshly generated staging
machine credentials/configuration and one short-lived, single-use Tailscale key.
It must never contain WHOOP, database, model, account-administration or unrelated
credentials. Keep the owner key in the approved secret store. Bootstrap
configuration stores only its SHA256 verifier; later owner sign-in sends the raw
key over HTTPS to the gateway, which could capture it if compromised.

Deleting a variable from `process.env` is hygiene, not secure erasure. The initial
Linux process environment and Railway variable/deployment history may retain its
original contents. Treat the control-plane history as secret-bearing. Revoke the
one-use enrollment key, delete the active variable, and create a fresh normal
deployment before serving the application. Keep the machine credential dedicated
to this disposable staging environment and rotate/revoke it when staging ends.
The durable node credential remains until its node identity is revoked.

Use `railway up <same-reviewed-context>` for every phase transition after
updating the intended start command and variables. In the live staging check,
`railway redeploy` reused the previous deployment's start-command manifest even
after the service's configured start command changed. Environment changes did
take effect: UID 1000 ran the old root-initialization command, which rejected the
request before provisioning or enrollment. A successful settings update therefore
does not establish which command the new deployment will run. Check the actual
deployment's start command and its fresh runtime report against the intended
phase before proceeding. Keep the same reviewed, hash-verified context and its
readable public-source modes for each upload; do not use `railway redeploy` to
switch phases.

### 1. Secret-free volume initialization

Railway documents [root-owned runtime volumes](https://docs.railway.com/volumes)
and a [main-process UID override](https://docs.railway.com/variables/reference).
Deploy the pinned image with one fresh `/data` volume, no public domain/TCP proxy,
no public health check and no application secrets. Set `RAILWAY_RUN_UID=0` only
for this initialization phase. Do not set the bootstrap variable yet, even empty.

Use the role's exact start command:

```text
# Fixture
/usr/bin/setpriv --no-new-privs -- /usr/local/bin/node /app/deploy/staging/bootstrap.mjs init-volume
# Gateway
/usr/bin/setpriv --no-new-privs -- /usr/local/bin/node /app/deploy/staging/gateway-bootstrap.mjs init-volume
```

Apply that command with a fresh `railway up` of the reviewed role context.

The helper validates a root-owned, non-writable base and empty fixed child
directories, changes only those directories, clears supplementary groups, drops
to UID/GID 1000 and holds idle. It never recursively changes ownership, reads a
bootstrap secret, enrolls a node or starts an app. Unexpected/nonempty state and
any bootstrap-variable presence fail closed. Verify ownership and the resulting
process identity/capabilities before continuing. Railway's [custom start command
replaces the image entrypoint](https://docs.railway.com/deployments/start-command).

After dropping privileges, initialization emits one sanitized runtime report.
Provisioning emits the same report before writing configuration or enrolling.
It includes process identity, capability/seccomp flags, cgroup limits and fixed
mount/directory metadata; it prints no environment values or file contents.
Unavailable controls are reported as unknown and must not be counted as passing.
The fixed `setpriv --no-new-privs` prefix enables the kernel flag; every staging
CLI rejects an absent or unconfirmed flag before reading config/bootstrap input.
Custom Railway commands override image entrypoints and must retain that prefix.
This does not make the root filesystem read-only or add network restrictions.
Review the provider's actual report before allowing the next phase.

### 2. Non-root, enrollment-only deployment

Set `RAILWAY_RUN_UID=1000`. In one reviewed deployment change, set the matching
fixed-role entrypoint and temporary `WHOOP_STAGING_BOOTSTRAP` JSON below. Deliver
the JSON directly from an approved private secret source through the scoped API;
never paste it into chat, shell history, command arguments, build files or logs.
Verify the effective process UID/GID is 1000. The provisioner checks both and
requires the kernel no-new-privileges flag before reading the variable value.

```text
# Fixture
/usr/bin/setpriv --no-new-privs -- /usr/local/bin/node /app/deploy/staging/provision-fixture.mjs
# Gateway
/usr/bin/setpriv --no-new-privs -- /usr/local/bin/node /app/deploy/staging/provision-gateway.mjs
```

Start this phase with `railway up` of the same reviewed role context, then verify
the deployment manifest contains the matching provisioning command.

Each image contains only its matching entrypoint. The shared helper rejects the
other role, unknown fields, malformed input and JSON over 8192 bytes. It removes
the variable from its current JavaScript environment immediately after reading
it, validates the entire envelope/key/config before file writes, and passes no
inherited environment to Tailscale children.

Fixture envelope, with reviewed actual identity and fresh key/hash substituted:

```json
{
  "mode": "synthetic-fixture-only",
  "role": "fixture",
  "config": {
    "mode": "synthetic-fixture-only",
    "hostname": "staging-backend.example-tailnet.ts.net",
    "serviceTokenSha256": "REPLACE_WITH_FRESH_STAGING_MACHINE_TOKEN_SHA256"
  },
  "enrollmentKey": "REPLACE_WITH_SINGLE_USE_BACKEND_TAGGED_KEY"
}
```

Gateway envelope, after approving the fixture's exact node IP:

```json
{
  "mode": "synthetic-fixture-only",
  "role": "gateway",
  "config": {
    "mode": "synthetic-fixture-only",
    "hostname": "staging-gateway.example-tailnet.ts.net",
    "fixtureHostname": "staging-backend.example-tailnet.ts.net",
    "fixtureIpv4": "100.72.0.9",
    "ownerSecretHash": "REPLACE_WITH_SHA256_OF_FRESH_RANDOM_OWNER_KEY",
    "serviceToken": "REPLACE_WITH_FRESH_STAGING_MACHINE_TOKEN"
  },
  "enrollmentKey": "REPLACE_WITH_SINGLE_USE_GATEWAY_TAGGED_KEY"
}
```

Placeholders fail validation. The gateway token uses the existing
`whoopgw_service_` format and must match the fixture's hash. The owner key is 32
random bytes generated/stored through the approved secret store. The helper
constructs fixed paths, gateway role and the two reviewed callbacks; input cannot
choose additional clients, endpoints, app commands, lifetimes or storage paths.

Configuration writes are exclusive/private. Gateway completion uses a final
hash-only marker after the token/app/runtime files. Configuration is written
before enrollment, so a restart after partial enrollment or a used key cannot
start another daemon or overwrite the files. Tailscale enrollment uses the fixed
role tag, private key file and stripped child environment, then closes the daemon.
Successful provisioning prints only a fixed acknowledgement and holds idle; no
fixture/gateway application, relay or public service starts.

### 3. Revoke, remove and start a fresh normal deployment

After the acknowledgement, confirm the exact node/tag/IP in the personal Tailscale
control plane and revoke the one-use enrollment key. Delete the active bootstrap
variable, remove the provisioning start-command override, retain
`RAILWAY_RUN_UID=1000`, and perform a fresh normal deployment using the same
reviewed context and volume through `railway up`. Verify the deployed command now
uses the image's normal entrypoint. Both normal runtimes reject bootstrap-variable presence,
including an empty value. Normal startup requires enrolled state and cannot
initiate enrollment. The gateway wrapper also rejects a wrong role, altered
callback/config files or a mismatched machine token before normal startup.

If any stage fails or its result is uncertain, stop, revoke the attempted key and
inspect the private state. Do not simply supply a new key, overwrite config,
loosen permissions or remove locks to make a retry pass. Inspect all owners before
explicit stale-state recovery. The shared supervisor/key cleanup and abrupt
interruption rules in the [private runtime guide](../railway/README.md) apply.
The older stdin helpers remain available for an explicitly approved operator
channel and isolated tests; this staging plan does not require SSH enrollment.

The fixture listens only on `127.0.0.1:8080`; gateway listens on loopback 8787.
Private Serve provides HTTPS 443. Pin gateway-to-fixture policy to the exact
approved fixture IP:443, not every node carrying a backend tag. Verify effective
ACLs, private certificates and absence of public Railway ingress/Funnel before
running clients. Configuration binds an operator-approved fixture; it cannot
attest that arbitrary software at that hostname returns honest data.

## Live callback and data test

### Callback verification

1. Deploy this staging gateway image with its separate SQLite volume, fresh owner
   secret and fresh machine credential. Set its fixture origin/IP to the synthetic
   node. The generated config retains only the fixed `codex` callback
   `http://127.0.0.1:17643/callback` and `claude-code` callback
   `http://localhost:17644/callback`, exact issuer/resource and S256 requirements.
2. Enroll the independently reviewed local transports under their distinct tags.
   Verify approved IP443 paths and denied laptop/unrelated/reverse paths, no
   public Railway ingress or Funnel, valid private HTTPS certificates, and the
   launcher isolation before starting either login.
3. Run the separate local login for Codex, open its locally constructed URL in
   the approved tailnet browser, and use only the staging gateway owner secret.
   Verify explicit consent and delivery to `127.0.0.1:17643/callback` with matching
   state/issuer, then token exchange and private token-file storage. Repeat for
   Claude Code at localhost:17644/callback. Never enter WHOOP credentials or
   visit a WHOOP authorization flow during this test.
4. Confirm both grants advertise/persist 604800 seconds and remain reusable after
   process restart without a fresh login. This establishes issuance/reuse, not
   seven elapsed days of live expiry testing; exact day-seven expiry already has
   synthetic-clock tests. Do not change production lifetimes or system clocks.
5. Sync each client sequentially to avoid shared single-flight contention. Check
   the seven dates and known fixture values (today's recovery 74, HRV 52.5,
   resting heart rate 54, sleep 28200000ms, performance 91, strain 8.2). Use the pinned
   offline reader in each intended client and label every result as synthetic.
   Confirm tool calls do not create remote requests; 15-minute admission and
   90-minute cache bounds still apply.
6. Revoke one staging grant through the owner page and verify the other remains
   valid. A rejected sync deletes that client's cache; already cached data can
   remain readable until the next permitted sync or expiry. Keep tokens, cookie
   values, enrollment keys and owner secrets out of screenshots/logs/chat.

Record sanitized outcomes and any provider/browser constraints. At completion,
stop staging resources and revoke staging grants/node identities according to
the approved lifecycle plan. These instructions do not claim the live test has
already run, and they do not authorize a subsequent WHOOP connection.

## Local verification

All 31 staging Node tests and 14 shared supervisor/runtime tests passed on
2026-10-18 in a fresh verified Node 22.23.3 container, with zero failures or skips.
Before source transfer/execution, checks
confirmed UID/GID 1000, no host mounts or credentials, dropped capabilities,
no-new-privileges, active seccomp, read-only root, private tmpfs and `network:none`;
Internet, metadata and host connection attempts failed. Only the allowlisted
source ran there, with no npm/dependency installation. The container was stopped
and removed afterward.

Tests exercise actual loopback fixture HTTP, gateway contract compatibility,
bounded stdin/private exclusive writes, fixed callbacks, wrong-role/config/token
rejection, missing completion marker, and no runtime delegation on failure.
Temporary-variable tests cover privilege checks before secret reads, complete
pre-write validation, fixed-role enrollment, no automatic retry after success or
failure, normal-runtime refusal, and fixed sanitized errors. Runtime-report tests
cover bounded reads, unknown/weaker controls, unsafe identities and no secret or
caller-selected file contents in reports.
Root directory initialization uses an injected filesystem/identity fixture;
actual Railway root-to-nonroot transition, variable provisioning, enrollment,
certificates, policy and browser callbacks remain separate checks. No external
account or WHOOP connection was made by these tests.

Both final AMD64 images were built offline from the tested allowlisted sources
and cached pinned bases, with no `RUN` instruction. Passive image inspection
confirmed the packaged source hashes and absence of extra application files.
Fresh isolated image smoke tests verified fixed failures for missing config,
root execution and bootstrap-variable presence, plus sanitized runtime reports.
All smoke containers were stopped and removed. The first AMD64 isolation probe
stopped before project execution because Node added `UV_USE_IO_URING=0`; a clean
pinned-base check reproduced that behavior, and the rerun allowed only that exact
nonsecret value on x64 while retaining every other isolation check. This is local
packaging evidence, not verification of Railway's eventual runtime controls.

The existing pinned-base `setpriv` binary was separately exercised offline:
kernel no-new-privileges changed from zero to one, a spawned child retained one,
and the staging guard rejected the unwrapped process while accepting the wrapped
process. UID/GID, capabilities and seccomp stayed unchanged. The packaged CLI
guards enforce this condition; internal library exports and arbitrary replacement
commands are not a provider-wide execution policy.


## Synthetic staging transport workaround

The verified synthetic gateway wrapper enables a trusted, strictly boolean
`gatewayRelayOnly` runtime option. Only the gateway tag can use it; it
adds the literal `TS_DEBUG_ALWAYS_USE_DERP=true` to that daemon's fixed environment.
It is not accepted from runtime JSON, environment variables, HTTP input or CLI
arguments. The real gateway wrapper now explicitly selects the same option after
the user accepted its experimental transport limitation. Backend wrappers and
local transports retain the default transport behavior.

The [pinned Tailscale 1.104.1 source](https://github.com/tailscale/tailscale/blob/v1.104.1/wgengine/magicsock/magicsock.go#L3525)
implements this experimental debug setting by disabling its UDP transports. In the staging comparison, native verified TLS
failed after the connection changed from DERP to direct; all seven handshakes
completed when confined to DERP. This identifies a usable staging workaround,
not the underlying packet-loss cause or a stable production API. WireGuard
end-to-end encryption, certificate/hostname verification, ACLs, TLS settings,
MTU and request deadlines remain unchanged. DERP introduces relay dependency
and possible latency/throughput costs; ongoing reliability is not established.
The final normal staging image contains no temporary native probe, stage logs
or byte-count diagnostics. This accepted transport limitation does not authorize
billing, real database migrations or WHOOP OAuth consent.
