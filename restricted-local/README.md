# Restricted local WHOOP adapter

Use this adapter for Codex and Claude Code when a compromised remote gateway is
part of the threat model. Do not configure either client with the remote `/mcp`
URL or the legacy `src/local` extension. Those paths let remote messages enter
the assistant directly. This adapter requires a separately reviewed, pinned
local release; the gateway cannot update it.

The private transport and Railway runtime are implemented in source. They have
not been enrolled into a real tailnet or connected to WHOOP or installed clients.
Follow the remaining [activation checks](../deploy/railway/README.md#activation-checks)
before a separately approved connection; source preparation is not deployment.

```text
WHOOP -> remote WHOOP service -> remote gateway
                                 |
                       fixed GET /data/snapshot
                                 |
                     isolated local sync process
                      bearer + strict validator
                                 |
                       numeric cache (90 min)
                                 |
                    offline local stdio MCP reader
                                 |
                       Codex or Claude Code
```

The reader defines its own tool name, description, schema, error messages and
protocol capabilities. It accepts only `get_health_summary({date})`. Dates select
from the last synchronized seven UTC dates; missing dates never fetch anything.
There are no remote tool definitions, prompts, resources, URLs, sampling requests,
login tools, or sync tools. Data is reconstructed from exactly eight fields:
`date`, the fixed `AVAILABLE`/`NO_DATA` status, recovery score, HRV, resting heart
rate, sleep duration, sleep performance and strain. Numbers have bounded ranges
and precision. No remote free text or error body is returned to the assistant.

Sync is independent of the conversation. It makes one fixed HTTPS GET without
query parameters, at most once every 15 minutes per client, and persists admission before
networking. The gateway assembles seven dates using the existing summary grant
(whose OAuth resource remains `/mcp`); each date consumes the shared gateway
quota. It returns no partial snapshot. The local sync process rejects redirects,
compression, malformed UTF-8/JSON, extra fields, wrong dates and oversized data.
Its total response deadline is 40 seconds; each upstream summary has a five-second
deadline. A midnight race can reject a snapshot until the next scheduled attempt.

Two clients at four snapshots per hour need 56 daily-summary calls per hour.
Both gateway gates use the same fixed 70-call rolling-hour ceiling, including
14 calls of allowance for variable completion times at the window edge. Failed
calls still count and only one upstream call may run at a time. This explicitly
increases the allowed data-refresh rate fourfold; it adds no fields, dates or
conversation-dependent network activity. The seven-day grants and 90-minute cache
ceiling are unchanged. The cadence is prepared in source; real-data fetching and
installed client activation are still separate pending steps.

Release order matters: install the reviewed 70-call gateway package before
starting the updated local launcher with its newly pinned sync image. Existing
immutable gateway/sync images retain their old limits until explicitly replaced;
editing source alone does not change them. Preserve quota/admission databases
during the update rather than resetting their history.

## Sign-in and freshness

Sign-in is a separate human action with fixed, locally constructed OAuth URLs,
S256 PKCE, random state, exact issuer and exact callback checks. There is no
discovery, dynamic registration, remote-selected token endpoint or automatic
browser opening. Codex and Claude Code receive separate grants, each valid for
up to **seven days**, with no sliding extension. A grant is stored only in the
sync process's private authorization volume. Neither the reader nor the model
receives it. The local tool prints only the trusted authorization URL and fixed
status messages, never token contents.

Each cache expires 90 minutes after a successful sync, or at authorization expiry
if earlier. Errors do not extend freshness. A 401 deletes the cache. Revocation
can therefore leave previously accepted data readable until the next sync or its
90-minute deadline. This is deliberate bounded offline access, not immediate
remote revocation. An expired grant requires a separate sign-in; a cache miss or
MCP call cannot start sign-in or sync.

The callback URLs remain `http://127.0.0.1:17643/callback` for Codex and
`http://localhost:17644/callback` for Claude Code. The container launcher exposes
only the corresponding laptop loopback port during login. The listener uses an
explicit container mode so Docker can reach it; standalone mode binds loopback.

## Runtime boundary

The reader and sync images contain only the reviewed dependency-free Node modules
and the digest-pinned Node 22 runtime. Build with no network and an allowlisted
context. No package installation or lifecycle script is needed. Record immutable
image IDs after review; never use an image tag that the remote service can update.

The launcher runs the reader with no network, read-only root, UID 1000, all
capabilities dropped, no-new-privileges, bounded resources and only its dedicated
cache volume mounted read-only. It does not mount a home directory, source tree,
SSH agent, browser profile, authorization volume or Docker socket into the reader.
The host-side launcher necessarily has authority to invoke Docker; this is an
operator installation tool and is not exposed as an MCP tool.

OrbStack can inject its public root CA when a container starts, even with a
read-only root and no listed host mounts. This changes the container's trust
store; it does not supply the CA's private key. Every launcher-created container
sets and verifies `dev.orbstack.add-ca-certificates=false`, using OrbStack's
[documented per-container opt-out](https://docs.orbstack.dev/features/https#between-containers).
This leaves global OrbStack settings and existing containers untouched. Image
digests, read-only mounts and Docker inspection alone do not attest to daemon
behavior; check the running certificate bundle when validating a TLS image.

Sync and login get per-client authorization and cache volumes, never host bind
mounts. The launcher supports two explicit configurations:

- **Private transport:** a separate container owns a dedicated Tailscale node
  and its private state volume. Its fixed relay connects only to the configured
  gateway tailnet IPv4 on TCP 443. Sync has `network:none` and receives only the
  relay's Unix-socket volume, mounted read-only. Login receives the same socket
  plus its fixed laptop-loopback callback mapping; its bridge namespace denies
  new outbound IP connections and accepts only the callback and established
  replies. Neither application receives Tailscale state, its control socket or
  a general SOCKS/HTTP proxy. The reader receives no transport volume at all.
- **Public IPv4 mode:** the existing explicit public-address configuration is
  retained. A temporary helper limits application egress to that one address on
  TCP 443, with DNS/IPv6 blocked and the HTTPS hostname pinned in the hosts file.
  A shared CDN IP is not a hostname boundary; the trusted application also fixes
  the origin and refuses redirects. This mode does not authorize public ingress
  or substitute for the private Railway route.

Both modes verify the canonical HTTPS hostname and certificate. Private HTTPS
travels end to end through the Unix relay; it has no direct-network fallback,
remote-selected destination, proxy-environment override or insecure TLS mode.
The relay admits two streams, bounds negotiation, duration and bytes, and never
interprets client bytes as a new destination. The Tailscale service address
`100.100.100.100` is not an allowed relay target.

Before starting the local Tailscale daemon, a separate helper installs a firewall
in only that container's namespace. It permits loopback, established replies,
TCP 443 to public IPv4 addresses and DNS to **Cloudflare `1.1.1.1` on UDP/TCP 53**.
Private-address LAN/host endpoints, metadata, reserved ranges and IPv6 are denied;
new UDP peer traffic is denied. This prepares HTTPS/DERP fallback, whose real
enrolled operation remains unverified. The transport can reach public Internet
HTTPS; this is not a Tailscale-domain-only egress firewall.

External tailnet policy is mandatory: each local transport tag may reach only the
approved gateway on TCP 443; the gateway may reach only its approved backend on
TCP 443. Permit the intended browser identity separately, and deny remote nodes
access to the laptop and unrelated nodes. Review the whole policy for overlapping
allow-all grants. The local firewall cannot constrain destinations inside an
encrypted Tailscale tunnel if the transport itself is compromised. That process
holds its dedicated node credential even after its enrollment key is deleted.
See the [policy and runtime guide](../deploy/railway/README.md).

No helper or application receives the host Docker socket, host Tailscale state,
SSH forwarding, browser state or unrelated credentials. Namespace checks and any
required firewall setup complete before application or transport code starts.

The operator must review the actual deployment origin, address and proxy topology
before initializing a real connection. DNS/address changes require explicit local
configuration changes. An isolated client process does not isolate other tools
available to a Codex/Claude session: use a separate health session with no unrelated
files or secrets when stronger client-side containment is needed.

## Operator setup and client configuration

These are post-review setup instructions, not commands already executed against
real accounts. The launcher is specific to this laptop's reviewed OrbStack socket
and Docker binary; another host needs a reviewed change. Both modes require a
canonical HTTPS DNS origin on port 443 and immutable reviewed image IDs. Private
mode selects one tailnet IPv4 explicitly; public mode still rejects the tailnet
range. Neither mode relies on the laptop's Tailscale routing or host networking.

After reviewing the protected origin and runtime, build `Dockerfile.reader` and
`Dockerfile.sync` from their allowlisted contexts offline. Private mode also needs
`Dockerfile.transport` built from its repository-shaped allowlist; it copies the
pinned Tailscale binaries without installing packages. Record the resulting image
IDs in private `operator.json` (mode `0600`, parent `0700`). Private configuration:

```json
{
  "origin": "https://gateway.example-tailnet.ts.net",
  "readerImage": "sha256:REPLACE_WITH_REVIEWED_READER_IMAGE_ID",
  "syncImage": "sha256:REPLACE_WITH_REVIEWED_SYNC_IMAGE_ID",
  "privateTransport": {
    "image": "sha256:REPLACE_WITH_REVIEWED_TRANSPORT_IMAGE_ID",
    "gatewayIpv4": "REPLACE_WITH_APPROVED_GATEWAY_TAILNET_IPV4"
  }
}
```

Public-address mode instead uses this exact configuration; never combine
`approvedIpv4` and `privateTransport`:

```json
{
  "origin": "https://gateway.example.invalid",
  "approvedIpv4": "REPLACE_WITH_APPROVED_PUBLIC_IPV4",
  "readerImage": "sha256:REPLACE_WITH_REVIEWED_READER_IMAGE_ID",
  "syncImage": "sha256:REPLACE_WITH_REVIEWED_SYNC_IMAGE_ID"
}
```

The placeholders deliberately fail validation. Use a reviewed absolute Node 22
path to run the host-side launcher; all reader, sync, login and transport code
runs inside restricted containers. For each client, initialize fresh app volumes:

```sh
/absolute/node22 /absolute/restricted-local/launch.mjs init codex /private/whoop/operator.json
```

For private mode, separately initialize its dedicated node/socket volumes:

```sh
/absolute/node22 /absolute/restricted-local/launch.mjs transport-init codex /private/whoop/operator.json
```

Enrollment requires separate account/network approval and the reviewed tailnet
policy. Use a short-lived, single-use, pre-tagged key for exactly
`tag:whoop-local-codex` or `tag:whoop-local-claude-code`. Pipe it directly from the
approved secret store into the manual command below; the left-hand command is a
placeholder for the reviewed secret-store operation, not a request to type a key:

```sh
/absolute/approved-secret-store-command | /absolute/node22 /absolute/restricted-local/launch.mjs transport-enroll codex /private/whoop/operator.json
```

The launcher refuses interactive terminal input for enrollment. Never put a key
in arguments, environment, shell history, chat or logs. Enrollment starts no app
or relay. Handled completion removes its temporary key file; abrupt interruption
requires the recovery review below. Persistent node state remains private. Node
identity lifetime is separate from the seven-day
gateway grant. Normal startup reuses enrolled state and cannot enroll itself.

Start each private transport in its own terminal and leave it running:

```sh
/absolute/node22 /absolute/restricted-local/launch.mjs transport-start codex /private/whoop/operator.json
```

Then, in another terminal, run the app operations below. Public mode skips the
three `transport-*` operations. Repeat setup for `claude-code` with its separate
config-selected volumes and tagged identity:

```sh
/absolute/node22 /absolute/restricted-local/launch.mjs login codex /private/whoop/operator.json
/absolute/node22 /absolute/restricted-local/launch.mjs sync codex /private/whoop/operator.json
/absolute/node22 /absolute/restricted-local/launch.mjs watch codex /private/whoop/operator.json
```

`init` creates only fresh dedicated Docker-managed authorization/cache volumes
and refuses to overwrite existing data; `transport-init` does the same for the
separate node/socket volumes. `login` prints the fixed gateway URL for
you to open. Enter only the separate gateway owner secret there. `sync` updates
the cache once; `watch` is a foreground loop that waits 15 minutes after each
completed attempt, stopped with Ctrl-C. Startup and request time add to that
interval. Missed intervals are not replayed and failures are not retried early.
Run watches separately; Claude's watch delays its first attempt by 61 seconds
to reduce contention with Codex. Manual simultaneous syncs can still collide
with the gateway's shared single-flight limit and must wait for their next
15-minute admission. The initial stagger reduces contention; it cannot guarantee
that separately running watches never drift into each other.
The resource review date in names/labels is metadata, not automatic deletion.

The private browser sign-in must run from an independently authorized tailnet
device; application containers do not borrow its Tailscale or browser session.
Keep transport start/enrollment manual and separate from MCP calls and the watch
loop. Changing origins, node addresses or image IDs requires local review.

Only one transport owner per client is allowed. Docker atomically reserves its
fixed container name before state is mounted, and an exclusive state-file lock
also protects against concurrent supervisors. Ctrl-C requests graceful shutdown
inside that container's private PID namespace and attempts to allow five seconds
for cleanup before removing the exact owned container. Failed cleanup falls back
to forced removal. It never removes a preexisting owner.

A crash or forced stop can leave `runtime.lock` or `gateway.sock`, which make
subsequent startup fail closed; `tailscaled.sock` may also remain. For recovery, first stop and
inspect every container holding that client's node/socket volumes. Only after
confirming that no owner remains, use a trusted offline helper with those exact
named volumes to remove confirmed stale lock/socket files. Preserve
`tailscaled.state` and other identity data. Do not infer stale ownership from a
PID belonging to another container, copy host Tailscale state, relax permissions
or automatically reenroll. An interrupted enrollment key needs separate review
and revocation/removal; suspected node compromise requires identity revocation.

After those operations succeed, configure only the offline reader in Codex:

```toml
[mcp_servers.whoop_local]
command = "/absolute/node22"
args = ["/absolute/restricted-local/launch.mjs", "read", "codex", "/private/whoop/operator.json"]
enabled_tools = ["get_health_summary"]
startup_timeout_sec = 30
```

For Claude Code, use the intended project scope:

```sh
claude mcp add --transport stdio --scope local whoop-local -- /absolute/node22 /absolute/restricted-local/launch.mjs read claude-code /private/whoop/operator.json
```

Do not retain a second direct remote WHOOP MCP connection alongside this reader.
No bearer, password, OAuth client secret or token path belongs in either client
configuration. Login is performed by the separate launcher command, not the
client's MCP login action. Syntax follows the official
[Codex stdio configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
and [Claude Code stdio configuration](https://code.claude.com/docs/en/mcp).
Actual installed-client and deployed-ingress checks remain pending.

## Limits

A compromised gateway can steal gateway credentials submitted to it, leak WHOOP
data, deny service or fabricate values that pass validation. This boundary removes
the direct remote free-text/MCP-control path; it does not make the numbers true or
prove that they cannot affect model behavior. Allowed numeric values still form a
small covert channel. Parser/runtime/kernel vulnerabilities, a compromised local
release, Docker authority, or compromise of the laptop itself remain outside this
schema guarantee. WHOOP OAuth tokens and gateway login material are not Gmail
passwords, but they still grant their scoped service access.

Tests use synthetic data/accounts only. Native installed Codex/Claude connections,
real account sign-in and the eventual Railway ingress must be verified separately
after approval. The PR remains draft; no deployment or client settings are changed
by these source files.
