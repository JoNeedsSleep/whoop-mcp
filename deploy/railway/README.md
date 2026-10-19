# Private Railway runtime package

This is reviewed source packaging, not deployment authorization or evidence of a
working tailnet. Keep the PR draft. No existing account, DNS record, WHOOP grant,
Railway resource or installed client configuration is changed by these files.
The remote-compromise model and Railway egress limitation in
[RAILWAY_PLAN.md](../../RAILWAY_PLAN.md) still apply.

## Process and network layout

Each remote service runs one application and one userspace `tailscaled` in the
same container. Gateway Serve terminates private HTTPS443 and proxies to
`http://127.0.0.1:8787`; backend Serve uses `http://127.0.0.1:8080`. Neither app
binds a public interface. The gateway reaches only the configured backend's
tailnet IPv4:443 through its local SOCKS5 daemon and a fixed Unix relay. The
application still verifies the backend's HTTPS certificate and exact hostname.
The gateway wrapper explicitly enables the pinned vendor's experimental
`TS_DEBUG_ALWAYS_USE_DERP=true` daemon setting to avoid the direct-path TLS
failure reproduced in private staging. This reviewed source constant is not an
environment, JSON or CLI option; backend/local roles cannot enable it. It retains
TLS verification and HTTP/2 mitigation, but adds relay dependence and remains an
accepted personal-deployment limitation rather than a stable vendor API.
No generic proxy, HTTP fallback, `https+insecure`, TUN device, NET_ADMIN, exit
node, route advertisement, Tailscale SSH, web management or Funnel is enabled.

The local transport is a separate container for each client. Only that container
holds its node state and administrative socket. Login/sync receives only the
fixed raw TLS relay socket. Sync has no network interface beyond loopback; login
has only its loopback-published callback and established replies. The offline
reader sees neither transport socket nor credentials. See the local launcher's
[instructions](../../restricted-local/README.md).

The supervisor strips inherited environment variables from Tailscale and backend
children, uses fixed absolute binary paths, discards child diagnostics, rejects
unsafe saved preferences/Serve mappings before starting a daemon, and verifies
effective preferences, exact node tag/DNS identity and Serve configuration before
starting the app/relay. A state-volume lock prevents concurrent supervisors.
Normal startup requires enrolled state and cannot initiate enrollment. Unknown
configuration fields fail closed. No Tailscale identity header grants app access;
gateway consent, PKCE, exact callbacks and seven-day grants remain required.

## Pinned artifact builds

Build only in the already approved isolated builder, with an allowlisted source
snapshot, no credentials, no host mounts and no network. Dockerfiles run no
dependency installation or project build scripts. The backend context requires
these previously built artifacts:

```text
backend-artifact/package.json
backend-artifact/node_modules/   # reviewed production dependencies
backend-artifact/dist/           # compiled server
backend-artifact/web/dist/       # compiled dashboard
backend-artifact/drizzle/        # migration files, not executed by startup
deploy/railway/{config,tailscale-supervisor,runtime}.mjs
```

Use the repository-shaped context root and the Dockerfile-specific allowlist:

```sh
docker build --network=none --platform=linux/amd64 -f deploy/railway/Dockerfile.backend -t whoop-backend-reviewed .
docker build --network=none --platform=linux/amd64 -f deploy/railway/Dockerfile.gateway -t whoop-gateway-reviewed .
docker build --network=none --platform=linux/arm64 -f restricted-local/Dockerfile.transport -t whoop-local-transport-reviewed .
```

These are operator build examples, not commands to run against a personal home
directory. The Dockerfiles pin architecture-specific manifests of Node22.23.3
and official Tailscale1.104.1. Record the output image ID, inspect its architecture
and final allowlisted files, and use that immutable image for later release.
The parent multiarch indexes were Node
`sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392`
and Tailscale
`sha256:87c55d6be56ad85b3d8bceca5f87f73de288c609131460dd1be1874c250cc41d`.
Tailscale's [official container release](https://tailscale.com/changelog#2026-10-13)
and [Docker documentation](https://tailscale.com/docs/features/containers/docker)
establish provenance, not an exhaustive vulnerability audit.

## Explicit configuration and storage

After deployment/storage/account approval, provision a dedicated persistent
`/data` volume for each remote role. Its `/data/tailscale`, `/data/config` and
gateway-only `/data/app` directories must be owned by UID/GID1000 and mode0700;
files are mode0600. Never share these volumes across services or replicas. The
state contains a durable node credential even after the enrollment key is gone.
The app and daemon share a remote container trust domain; a compromised remote
app may steal that service's node credential. Tailnet policy must limit its use.

Gateway `/data/config/runtime.json`, with actual reviewed names/IP substituted:

```json
{"role":"gateway","hostname":"gateway.example-tailnet.ts.net","stateDirectory":"/data/tailscale","appConfigFile":"/data/config/app.json","backendIpv4":"100.72.0.9"}
```

Backend `/data/config/runtime.json`:

```json
{"role":"backend","hostname":"backend.example-tailnet.ts.net","stateDirectory":"/data/tailscale","appConfigFile":"/data/config/app.json"}
```

These names/IPs are examples only. Discover and approve actual identities through
the administrative control plane; do not guess DNS or silently accept a renamed
node. The gateway app config uses the existing
[gateway schema](../../review-gateway/config.example.json), with exactly
`publicOrigin=https://<gateway-name>`, `upstreamOrigin=https://<backend-name>`,
`port=8787`, `databaseFile=/data/app/gateway.sqlite` and
`upstreamTokenFile=/data/config/service-token`. Set the two registrations to
`codex` → `http://127.0.0.1:17643/callback` and
`claude-code` → `http://localhost:17644/callback`; never add wildcard callbacks.
Provision the independent owner-secret hash and service credential through the
reviewed gateway helper; no secret appears in this document or image.

The backend app JSON has exactly these string keys: `DATABASE_URL`, `DATABASE_HOST`,
`ENCRYPTION_KEY`, `WHOOP_CLIENT_ID`, `WHOOP_CLIENT_SECRET`, `PUBLIC_BASE_URL`,
`SESSION_SECRET`, `ALLOWED_WHOOP_USER_ID`, `GATEWAY_SERVICE_TOKEN_SHA256`.
`PUBLIC_BASE_URL` must equal its private HTTPS origin. The wrapper forces
`BIND_HOST=127.0.0.1`, `PORT=8080`, `RUN_MIGRATIONS=false`,
`ENABLE_LEGACY_DIRECT_MCP=false` and an empty direct-MCP redirect allowlist.
Migrations are a separately approved one-off operation against the dedicated DB,
after reviewing backups and invalidation effects; normal startup never applies
them. Keep PostgreSQL private with a restricted application role.

`DATABASE_HOST` must be the approved single service label followed by
`.railway.internal`. It binds the destination independently of the URI and is
not forwarded to the backend process. `DATABASE_URL` must have this exact shape
(with a canonical percent-encoded password and approved role/database names):

```text
postgresql://whoop_runtime:<encoded-password>@<DATABASE_HOST>:5432/whoop?sslmode=verify-full&sslrootcert=%2Fdata%2Fconfig%2Fdb-ca.pem
```

No alternate port, public/IP/socket host, fragment, extra/duplicate query option,
TLS override or alternate CA path is accepted. Provision only the dedicated CA's
public certificate at `/data/config/db-ca.pem`, owned by UID1000, mode0600, in the
private mode0700 config directory. The wrapper checks a regular single-link file,
bounded certificate-only contents, CA status and validity before starting the
backend or its daemon. PostgreSQL's certificate must have the exact approved
private hostname in its SAN. The pinned application `pg` driver then verifies
that name and issuer with `sslmode=verify-full`; there is no plaintext fallback.
The CA is reopened by `pg`, so this is not immutable pinning against a compromised
same-UID process that can rewrite its own configuration. Keep the CA signing key
outside both runtime containers.
Register WHOOP's exact redirect as `https://<backend-name>/whoop/callback`.
The dashboard's subsequent local completion is
`https://<backend-name>/dashboard/connected`; it is not the WHOOP registration.

## Tailnet policy draft and enrollment

Before enrollment, replace all example identities below and review the complete
policy. This fragment is not safe to append to an existing allow-all policy.
Allow only the intended browser device's exact tailnet IP, the two local transport
tags and the gateway-to-backend path. Pin destinations to the approved gateway
IP (`100.72.0.8` in this example) and backend IP (`100.72.0.9`), rather than all
nodes carrying either role tag. Replace these example IPs with the exact approved
node addresses, matching the local operator and remote gateway configuration.
Keep all other remote-initiated access to
the laptop/unrelated nodes absent. Give tag ownership only to the approved
operator group. Do not grant Funnel attributes or remote configuration rights.

```json
{
  "groups": {"group:whoop-operators": ["operator@example.test"]},
  "tagOwners": {
    "tag:whoop-local-codex": ["group:whoop-operators"],
    "tag:whoop-local-claude-code": ["group:whoop-operators"],
    "tag:whoop-gateway": ["group:whoop-operators"],
    "tag:whoop-backend": ["group:whoop-operators"]
  },
  "grants": [
    {"src": ["100.72.0.2"], "dst": ["100.72.0.8", "100.72.0.9"], "ip": ["tcp:443"]},
    {"src": ["tag:whoop-local-codex", "tag:whoop-local-claude-code"], "dst": ["100.72.0.8"], "ip": ["tcp:443"]},
    {"src": ["tag:whoop-gateway"], "dst": ["100.72.0.9"], "ip": ["tcp:443"]}
  ],
  "ssh": []
}
```

Review this using the provider's [grants syntax](https://tailscale.com/docs/reference/syntax/grants)
and policy tests before applying it. Explicitly test denied reverse directions,
ports22/5252, unrelated nodes and the local transport identities. Protect HTTPS
and MagicDNS enablement through the administrative account; Serve is
[tailnet-only](https://tailscale.com/docs/features/tailscale-serve), while Funnel
would be public and is prohibited here.

Enrollment is a distinct, manual action after approval. Use a short-lived,
single-use, preauthorized auth key carrying exactly the intended role tag.
Keep the administrative account/API/OAuth secret off the service. Use the
approved secret store to pipe that one-use key into the command's stdin; never
paste it into terminal input, chat, arguments, environment, logs or a build.
The local launcher command is `transport-enroll <client-id> <private-config>`.
For a remote image the separate command is:

```text
/usr/local/bin/node /app/deploy/railway/runtime.mjs /data/config/runtime.json --enroll
```

Run it only through an approved operator channel that forwards stdin without
recording its contents. The wrapper bounds input, creates
`enrollment.key` exclusively with mode0600, passes only the filename to the
Tailscale CLI, removes the temporary file on handled completion/failure, validates the expected tag/name and
stops. It starts no app, relay or migration. Record the new node identity,
tag, owner and lifecycle/review date; revoke the enrollment key after use.
Node-key lifetime/revocation is independent of seven-day gateway login. Choose
and audit an appropriate node lifecycle so daemon restarts reuse the same
identity instead of requiring daily reenrollment. The actual provider channel,
key consumption and ACLs remain live activation checks; no key was used in tests.

Normal remote startup uses the image's default command. Local
`transport-start` is a separate operator process; it cannot be triggered by MCP
calls. Run only one instance per state volume. A failed/killed supervisor may
leave `runtime.lock` or a Unix socket. Stop and inspect every container holding
that volume before an operator removes only those stale lock/socket files;
never delete or copy the node state or bypass the lock based on a container PID.
An abrupt interruption during enrollment can also leave `enrollment.key`;
revoke the one-use key and inspect/remove that residue through the same approved
operator recovery channel. Never treat key deletion as node-identity revocation.

## Activation checks

Disable Railway public domains, TCP proxies, GitHub autodeploy, PR environments
and image auto-updates. Inspect one replica per role, exact images and dedicated
volumes. Verify gateway/backend raw ports are unreachable except loopback, the
DB has no public endpoint, and no administrative credential or unrelated file
was injected. Railway does not enforce default-deny remote egress; acceptance of
that limitation remains a prerequisite.

Check real Serve status has only HTTPS443 → the role's loopback port, no Funnel,
extra service, raw TCP forwarder or file handler. The pinned Serve source
[preserves Host for TCP HTTP proxies and overwrites forwarding headers](https://github.com/tailscale/tailscale/blob/v1.104.1/ipn/ipnlocal/serve.go#L904).
Exercise secure cookies through that actual topology; keep Express trust limited
to loopback. Synthetic TLS proxy tests establish the expected contract, not
behavior of a deployed node, browser or certificate renewal.

From approved and denied identities, verify ACLs, TLS hostname rejection,
local fixed relay destination, blocked host/LAN/metadata/IPv6 egress, and absence
of Tailscale state from login/sync/reader containers. Finally exercise WHOOP's
exact private dashboard callback in the approved tailnet browser, both client
loopback callbacks, seven-day reuse/expiry, owner/client revocation and hourly
sync/cache expiry. Configure Codex/Claude only for the pinned offline reader.
Keep account credentials out of test output and retain sanitized evidence.
Live synthetic Tailscale and callback results are recorded in
[staging validation](../staging/VALIDATION.md). Real WHOOP checks and native
client configuration remain unperformed.


## Backend TLS preparation validation (2026-10-19)

The deployment wrapper now requires the exact approved private database hostname,
canonical `verify-full` URI and private fixed-path CA before starting the backend
or its daemon. A fresh offline Node22 fixture passed 83 Railway/staging tests,
including the unchanged compiled backend's actual `pg` Pool over synthetic
TLS/SCRAM. A matching hostname/CA succeeded; wrong SAN, untrusted CA and plaintext
fallback were rejected. URI/TLS override inputs, unsafe CA files and startup
ordering were also checked. No migration or real database was involved.

The same snapshot separately tests the explicit gateway-only relay workaround:
only the gateway wrappers opt in, backend/local defaults remain unchanged, and
configuration/environment/CLI input cannot enable or override it. This does not
relabel the previously deployed synthetic artifact as a real-data deployment.

All twelve isolation probes, source hashes before/after execution and exact
container cleanup passed. The initial negative TLS assertions were corrected to
inspect Drizzle's preserved error cause; the rejected run was retained, and no
TLS check was weakened. The CA remains writable by the remote service's own UID,
Railway's accepted isolation limits remain, and runtime advisories are not
cleared. Actual billing, real database migrations and WHOOP consent still require
their separate authorization.

## Configuration delivery preparation (2026-10-19)

Use the separately reviewed [backend](../backend-provision/README.md) and
[gateway](../gateway-provision/README.md) configuration helpers for the proposed
real-data deployment. Their temporary variable-to-stdin delivery is an explicit
approval proposal described in the [activation plan](ACTIVATION.md), including
provider history retention; the generic enrollment example above does not
authorize that channel. The backend helper passed nine tests and its packaged
smoke; the gateway helper passed 22 tests and a packaged inspector/cutover smoke.
Both preserve existing identity/node state and start no network service.

The normal gateway image now enters through a fixed shell that rejects
provisioning inputs and clears inherited environment before Node. Image
`sha256:ac5da5fe3949eb226124dc881e17005015edffdc59db7764fa3b4fabc1c1ba25`
passed three separate packaged checks for missing configuration, explicit
bootstrap rejection and hostile Node/OpenSSL environment removal. Sixteen
packaged source hashes match passing isolated test inventories. All three
temporary containers were removed. These are local AMD64 checks under OrbStack
translation, not deployed Railway verification or a clean vulnerability scan.
