# Restricted local WHOOP adapter

Use this adapter for Codex and Claude Code when a compromised remote gateway is
part of the threat model. Do not configure either client with the remote `/mcp`
URL or the legacy `src/local` extension. Those paths let remote messages enter
the assistant directly. This adapter requires a separately reviewed, pinned
local release; the gateway cannot update it.

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
query parameters, at most once per hour per client, and persists admission before
networking. The gateway assembles seven dates using the existing summary grant
(whose OAuth resource remains `/mcp`); each date consumes the shared gateway
quota. It returns no partial snapshot. The local sync process rejects redirects,
compression, malformed UTF-8/JSON, extra fields, wrong dates and oversized data.
Its total response deadline is 40 seconds; each upstream summary has a five-second
deadline. A midnight race can reject a snapshot until the next scheduled attempt.

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

Sync and login get separate authorization and cache volumes, never host bind
mounts. A temporary firewall helper configures only their network namespace before
application code starts. Outbound access is limited to the operator-approved
gateway IPv4 on TCP 443, with DNS and IPv6 blocked. The hostname is pinned in the
container hosts file and TLS still checks that hostname. An IP allowlist on a
shared hosting/CDN address is not a hostname boundary; the trusted local sync code
also fixes the HTTPS origin and rejects redirects. No helper or application gets
the host Docker socket. Login alone gets a laptop-loopback callback mapping.

The operator must review the actual deployment origin, address and proxy topology
before initializing a real connection. DNS/address changes require explicit local
configuration changes. An isolated client process does not isolate other tools
available to a Codex/Claude session: use a separate health session with no unrelated
files or secrets when stronger client-side containment is needed.

## Operator setup and client configuration

These are post-review setup instructions, not commands already executed against
real accounts. The launcher is specific to this laptop's reviewed OrbStack socket
and Docker binary; another host needs a reviewed change. It currently accepts
only a canonical HTTPS DNS origin on port 443 and an explicitly approved public
IPv4. It cannot yet use a private Tailscale address; see the Railway plan's ingress
blocker. Never solve that by enabling host networking or broadening the allowlist.

After approving a reachable protected origin, build `Dockerfile.reader` and
`Dockerfile.sync` from their allowlisted contexts offline. Save the resulting
immutable image IDs in a private `operator.json` (mode `0600`, parent `0700`):

```json
{
  "origin": "https://gateway.example.invalid",
  "approvedIpv4": "REPLACE_WITH_APPROVED_PUBLIC_IPV4",
  "readerImage": "sha256:REPLACE_WITH_REVIEWED_READER_IMAGE_ID",
  "syncImage": "sha256:REPLACE_WITH_REVIEWED_SYNC_IMAGE_ID"
}
```

The placeholders deliberately fail validation. Use a reviewed absolute Node 22
path to run the host-side launcher; all reader, sync and login code runs inside
the restricted containers. In a separate terminal, run these operations for
`codex` and then `claude-code`, replacing the example paths:

```sh
/absolute/node22 /absolute/restricted-local/launch.mjs init codex /private/whoop/operator.json
/absolute/node22 /absolute/restricted-local/launch.mjs login codex /private/whoop/operator.json
/absolute/node22 /absolute/restricted-local/launch.mjs sync codex /private/whoop/operator.json
/absolute/node22 /absolute/restricted-local/launch.mjs watch codex /private/whoop/operator.json
```

`init` creates only fresh dedicated Docker-managed authorization/cache volumes
and refuses to overwrite existing data. `login` prints the fixed gateway URL for
you to open. Enter only the separate gateway owner secret there. `sync` updates
the cache once; `watch` is a foreground hourly sync loop, stopped with Ctrl-C.
Run watches separately; Claude's watch delays its first attempt by 61 seconds
to reduce contention with Codex. Manual simultaneous syncs can still collide
with the gateway's shared single-flight limit and must wait for the next hour.
The resource review date in names/labels is metadata, not automatic deletion.

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
