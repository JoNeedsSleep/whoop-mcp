# WHOOP security review branch

Review draft based on upstream `148f12076885cfe3f5f35b21a315ff71832c11e2`.
This remains a draft security review, not production approval. The user authorized private synthetic Railway staging, dependency review, and Tailscale/client callback tests using their personal account, then requested real WHOOP integration. Real-data preparation is now authorized, but activation remains pending the documented runtime gates, account authorization and live verification; the current deployment still contains synthetic data only. DNS changes and merging remain out of scope. The remediated dependency lock passed 318 tests and both server/web builds in a fresh verified disposable Node 22 environment. The branch schema and database concurrency tests ran only in a separately approved, empty synthetic PostgreSQL fixture. See [dependency remediation](DEPENDENCY_REVIEW.md), [runtime findings](IMAGE_SECURITY_REVIEW.md), and [live staging validation](deploy/staging/VALIDATION.md) for the current results and unresolved limits; older validation sections below retain their original scope. Keep this PR draft and unmerged.

On 2026-10-19, the owner explicitly accepted the documented personal Railway
limitations: writable runtime filesystems, unrestricted outbound internet,
unresolved runtime advisories and the experimental relay workaround. This is an
exception to the stricter runtime target below, not a statement that those
controls are deployed or the findings fixed. The decision expressly excluded
new billing, real database migrations and WHOOP OAuth consent. The developer app
has been created; no member has authorized it. See the [real-data activation
plan](deploy/railway/ACTIVATION.md) for the separate remaining actions.

## Intended boundary

A fully compromised WHOOP service must have no OpenAI login, OpenAI API key, browser session, GitHub token, SSH key, DNS credential, hosting administrator credential, unrelated application secret or unrelated filesystem mount to steal. WHOOP health data and the service's WHOOP-specific tokens are within the assumed compromise. The remaining `read:profile` permission also makes name/email available to a compromised service; dropping the profile tool alone cannot prevent that.

The current client-facing boundary is the restricted local adapter. The remote
WHOOP service and remote gateway may both be compromised. Clients use an offline
local MCP reader, not the remote MCP endpoint or legacy local extension. Local
code and image IDs must be reviewed and pinned independently of remote releases.

Use separate trust domains:

```text
Codex / Claude Code
        | local stdio tool calls; no network or credentials in reader
        v
Pinned offline local MCP reader
  immutable local tool definition; fixed errors; bounded numeric fields
        | read-only per-client cache, expires within 90 minutes
        v
Separate isolated local sync/login process
  seven-day gateway grant; fixed seven-day snapshot; hourly admission
        | end-to-end HTTPS through a read-only Unix relay socket
        v
Dedicated per-client Tailscale transport container
  separate node state; fixed gateway tailnet IPv4:443; external ACL required
        | fixed HTTPS /data/snapshot; no conversation-dependent requests
        v
Remote gateway + WHOOP service + dedicated database
  treat all remote responses as untrusted; no unrelated secrets/files
        | WHOOP-specific OAuth credentials
        v
WHOOP API
```

The gateway must run in a separate security principal and isolated environment, with its own reviewed, pinned release. Do not mount this service's filesystem/database into it, share service administration credentials with it, or automatically deploy gateway changes from an untrusted WHOOP build. A filter inside the WHOOP service cannot enforce the boundary after that service is compromised.

`review-gateway/gateway.mjs` is the dependency-free data adapter. It exposes one immutable tool definition, accepts a real UTC date, requests only `/internal/health-summary`, denies redirects, limits decoded responses to 4096 bytes, validates every field, rejects extra properties and text/URLs in data, and recreates the result. Numeric values are bounded and precision-limited. It never calls model APIs or forwards upstream tool metadata, sampling requests, resources, prompts, model outputs, errors or redirect advice.

The independent gateway now implements Streamable HTTP MCP, its own OAuth authorization server, exact pre-registered Codex/Claude Code callbacks, browser-bound owner sign-in/consent, and durable SQLite authorization/rate-limit state. Client-to-gateway tokens are distinct from the gateway-to-service machine credential. A configured public client ID identifies a client registration, not attested application software. The gateway exposes only reviewed protocol methods and the fixed summary tool. Thirty tool calls per rolling hour and one in-flight upstream request are enforced across both clients and restarts using the same persistent database; run one replica with one local DB. Independent per-process DB copies do not enforce a common budget.

The WHOOP service's legacy `/mcp` remains absent by default (`ENABLE_LEGACY_DIRECT_MCP=false`). Its summary endpoint now accepts only the dedicated machine credential and resolves the configured numeric WHOOP identity server-side. User PATs cannot call it. Missing machine-token hash disables the endpoint. Firewall WHOOP ingress so only the gateway reaches the summary endpoint, and protect its admin/OAuth interface separately. Runtime isolation, HTTPS ingress and actual client activation still need deployment verification; source-code implementation is not a deployed enforcement boundary.

Schema validation blocks instruction-bearing strings and unapproved fields. It does **not** authenticate plausible numbers, dates or enum values: a compromised server can fabricate a normal-looking recovery score, encode information in valid metrics, omit records, or cause denial of service. The tests explicitly demonstrate acceptance of plausible falsified data. Clinical correctness and provenance need independent verification. No absolute security or impossibility of prompt injection, model misuse or distillation is claimed. Keeping model credentials and outputs away from the server, disallowing server-initiated model calls, and applying independently enforced quotas substantially limits opportunities; it cannot prove that all misuse is impossible.

The gateway protections alone assume that gateway remains trusted. A compromised gateway can bypass its own schema, authentication and quotas, capture subsequent gateway login credentials and return malicious MCP responses. Direct remote MCP would pass those responses to the client. The implemented restricted local adapter removes that direct path: it fetches only a data snapshot, independently validates it, and serves locally constructed MCP messages from an offline reader. Neither client is configured to contact the remote MCP endpoint. This is source implementation, not a claim that installed client settings or deployment have been activated. It does not guarantee laptop safety against a vulnerable local parser/runtime/kernel, a compromised local release, or model misuse of plausible fabricated numbers.

## Patch contents

- Require an explicit canonical HTTPS `PUBLIC_BASE_URL` and configured numeric `ALLOWED_WHOOP_USER_ID`. No implicit hosting-domain fallback or open-access mode. The ID must be verified out of band; never enroll the first person who logs in. Existing sessions/tokens are checked against the configured ID when used in production.
- Request four health-read scopes, `offline`, and `read:profile` for identity. Remove `read:body_measurement`, profile/body tool registrations and handlers, and discard profile email during persistence. WHOOP profile access still includes email/name; this is a documented remaining permission, not a claim of email isolation. Existing WHOOP grants may retain older broader scopes until explicitly revoked and reauthorized later.
- Require exact, explicitly approved HTTPS MCP callback URLs. An empty allowlist disables new MCP client registration. No ChatGPT callback URLs have been guessed or configured. Existing clients are rechecked against the allowlist. Public PKCE clients only; confidential-client secrets are not stored for new registrations.
- Add per-client consent before the WHOOP redirect, with escaped client display data, exact callback shown, a browser-bound CSRF cookie, Origin validation, a single-use pending record, no-store headers and a restrictive consent-page CSP. The same browser nonce is carried into a flow-specific secure `__Host-` cookie for the WHOOP leg, with its hash retained in pending state. The WHOOP callback checks this binding before consuming state or exchanging codes; only its bound response clears the flow cookie. Dashboard logins get the same WHOOP-leg protection. The displayed client name is explicitly unverified.
- Use the canonical configured dashboard callback, secure `__Host-` cookies (HttpOnly, SameSite=Lax, Path=/, no Domain), seven-day server-checked sessions, state and PKCE. Revoke the temporary login token after session establishment.
- Atomically consume pending WHOOP states with `DELETE ... RETURNING` after browser validation. Authorization-code consumption and MCP token insertion occur in one transaction under a user-row `FOR UPDATE` lock shared with revoke-all and PAT issuance. If redemption wins, revoke-all waits and then revokes its token; if revoke-all wins, the code is gone and redemption cannot mint a token. Failed code validation rolls the transaction back. Enforce client, deadline and mandatory S256 verifier validation during exchange. SDK 1.30.0 passes the verifier only with `skipLocalPkceValidation=true`; this flag delegates checking to our mandatory provider validation, not to a trusted client. A supplied token-request redirect URI must match exactly; omission remains supported by the SDK's OAuth semantics.
- Persist fixed seven-day OAuth and PAT expirations; advertise stored expiration rather than extending it on each verification. List/revoke both token types in the dashboard and add revoke-all. Revocation does not cancel requests already executing, invalidate dashboard sessions, stop WHOOP authorization flows that have not minted a local code yet, or prevent separately authorized PAT creation/new login after the revocation transaction. The shared lock fixes the consumed-code/late-token race; it is not an account-wide authorization freeze.
- Migration `0002` expires and revokes every legacy MCP credential. This is a deliberate reauthorization requirement. Existing WHOOP grants and in-flight pending login records are not a deployment migration strategy; clear old pending authorizations/client registrations and review existing grants before later rollout.
- Serialize WHOOP refreshes across processes under the shared user-row lock, re-read token state after acquiring the lock, and explicitly use READ COMMITTED regardless of the database default. A 401 carries the exact rejected token so concurrent or delayed failures reuse a stored replacement. Login/upsert takes the same user-before-token lock order.
- Bound pending login/consent state with a shared nonblocking advisory transaction lock, a 100-record admission cap, and at most 25 expired deletions per attempt. Cap-denied requests still commit cleanup; lock/storage failures return a fixed 503. Existing states beyond the cap drain in bounded batches, and active states are not evicted.
- Add a narrow summary endpoint and fixed errors; deny WHOOP request redirects, bound timeouts and pagination. The summary selects at most one record of each type in the requested UTC API window; it is not a promise to join recovery, sleep and cycle records by physiological cycle or local calendar date.
- Disable dependency lifecycle scripts in Docker builds, use a separate production dependency stage, allowlist build-context files and run as the unprivileged `node` user. The private Railway packages now have offline artifact-only builds and architecture-specific base digests, covered below. A comprehensive dependency/base-image vulnerability review remains a release gate.

## Isolation and release requirements

1. Keep the static jojiao.com website on GitHub Pages. Website and School files and DNS remain outside this task's changes. Hosting, personal Tailscale and account actions are limited to the explicit approvals recorded above and in the activation plan. A future WHOOP subdomain can be decided separately.
2. Build only in a disposable VM or a verified container/sandbox without personal home directories, browser state, SSH agents, Docker socket, cloud instance credentials or credential forwarding. Use an empty environment and only the source snapshot. Do not run npm, the local extension, or this service directly against a personal home directory.
3. Dependency fetching is a separate phase: registry egress only, `npm ci --ignore-scripts --no-audit --no-fund`; review resolved artifacts before execution. Build/test offline with synthetic fixtures. Database integration tests require a dedicated disposable PostgreSQL database, never a service/production database. Lifecycle scripts were not inspected exhaustively, and disabling scripts does not make dependency code trusted.
4. Runtime requires a dedicated WHOOP database role/database and only WHOOP-specific secrets. Use a read-only root filesystem, limited tmpfs, no host mounts, no privilege escalation, dropped capabilities, resource limits and default-deny egress allowing WHOOP plus the dedicated database. These controls are deployment requirements, not enforced by the Dockerfile alone.
5. The current Express proxy trust is loopback only. A later TLS proxy must overwrite forwarded headers and be the only permitted connection to the service. Validate secure-cookie behavior through that actual topology. No HTTP fallback or guessed proxy trust range is provided.
6. Obtain separate approval for installation/execution in that disposable environment, database migration, deployment, DNS and account connections. Re-review the final dependency lock, gateway boundary and OAuth flow first. No secrets belong in Git, screenshots, logs or PRs.

## Validation evidence (2026-10-18)

Earlier review was static except for eight dependency-free gateway tests. An earlier macOS sandbox smoke test failed before third-party execution. No host execution was used to bypass it. The original review inspected all 781 lock entries and the locked SDK's PKCE/redirect handling. GitHub identity was verified as `JoNeedsSleep`; the working branch continued from `e9b5d1521154bf8952bead4f630471d994665f6a`.

For this follow-up, the user approved dependencies/tests conditional on verified Node 22 isolation and registry-only fetching, then separately approved a fresh disposable PostgreSQL schema and concurrency tests. Three subagents implemented and cross-reviewed refresh coordination, state admission and the isolation setup. Cross-review caught a REPEATABLE READ snapshot risk; refresh and admission now explicitly request READ COMMITTED. A test wrapper was corrected to forward transaction options.

### Verified execution boundary

- OrbStack containers used pinned official runtime images: Node `sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392` (Node 22.23.3, Linux arm64) and PostgreSQL `sha256:3645570cccdfa447589da9f57dd740faa29b30938e861289a5574b6ca6b03826` (17.11).
- Before installing or running project code, checks established non-root UID/GID, read-only root, dropped capabilities, no-new-privileges, active seccomp, bounded CPU/memory/PIDs, private tmpfs scratch, no bind/anonymous volumes, no published ports and no host filesystem, Docker/SSH socket, credentials or forwarded environment. Only an allowlisted source snapshot entered the test container, with file hashes recorded. Host GitHub authentication stayed outside all test containers.
- Tests and npm ran in a `network:none` namespace: loopback only, no routes, and negative connection tests for public internet, metadata and host addresses. PostgreSQL shared only this namespace, listened on `127.0.0.1`, and used synthetic trust authentication. Its data and socket directories were tmpfs, with no existing database connection. The three reviewed branch migrations were applied to an initially empty fixture; migration `0002` was not applied to any real database.
- Fetching was separate from installation/execution. A temporary firewall helper had NET_ADMIN only in the downloader's network namespace. It allowed only TCP 443 to a pinned public registry CDN IPv4 and denied other traffic, including IPv6 and DNS. The reviewed downloader enforced `https://registry.npmjs.org`, exact lockfile URLs, TLS hostname verification, no redirects, size/time bounds and SHA-512 integrity before saving inert tarballs. The IP firewall alone is not a hostname boundary on a shared CDN; the trusted downloader supplies that restriction. No dependency code ran in the networked container.
- Downloader negative tests covered foreign/malformed URLs, private/IPv6 addresses, wrong hashes, redirects, encoding, truncation, oversized streams and unlisted artifacts. TLS hostname mismatch was rejected; actual non-registry/host/metadata connection attempts failed. All 568 applicable unique Linux arm64 artifacts passed integrity checks (106,307,237 bytes). Offline `npm ci --ignore-scripts --no-audit --no-fund` installed 581 packages using only that cache. No dependency lifecycle scripts ran. This is provenance/integrity checking, not an exhaustive dependency vulnerability audit.
- Installed dependencies were preserved as an opaque hashed archive and restored only inside fresh verified containers for reruns. The successful build explicitly allowed execution on its private scratch tmpfs for compiler binaries. All test, fetch and database containers were confirmed stopped afterward; logs and failed-attempt evidence were retained locally. Container isolation still shares OrbStack's Linux kernel and is not a proof against kernel/runtime escape.

### Results

| Check | Result |
| --- | --- |
| `node --test review-gateway/gateway.test.mjs` | 8 passed, 0 failed |
| Server `vitest run --maxWorkers=2` | 104 passed across 21 files, 0 failed/skipped |
| Web `vitest run --maxWorkers=2` | 8 passed across 3 files, 0 failed/skipped |
| `npm run build --ignore-scripts --offline --no-audit --no-fund` | Server TypeScript, web TypeScript and Vite build passed |
| `git diff --check` | Passed |

The server suite includes four actual PostgreSQL refresh tests (three parallel summary reads, concurrent/delayed 401s, refresh versus login, and rollback/unlock after refresh failure), three state-admission tests (last-slot contention, bounded backlog cleanup committed despite denial, and preserving active/reclaiming expired flows), and both earlier revoke/redemption winner orderings. Competing refresh/revocation fixtures observe actual database lock waits on separate connections. Refresh tests also use a REPEATABLE READ connection default to verify the explicit override. Every database test requires both `WHOOP_TEST_DB_DISPOSABLE=true` and a synthetic `WHOOP_TEST_DATABASE_URL`; there is no runtime `DATABASE_URL` fallback.

Failures were retained and corrected: the first npm configuration used the same empty file for user/global configuration and was rejected before installation; a later run exposed a case-sensitive cookie assertion and Vitest accidentally discovering the separate Node gateway suite; the first build attempt was denied compiler execution by the scratch mount. Distinct empty npm configurations, case-insensitive cookie-attribute checks, explicit separation of test runners and executable private build scratch resolved these. No application security check was weakened to pass the tests.

Not executed in that earlier run: WHOOP production image build, vulnerability scanning of every dependency, real WHOOP or model-account OAuth, actual deployed gateway/ingress topology, deployment, DNS or any migration of an existing database. No external account was connected.

## Seven-day sign-in preference

At the user's request, new dashboard sessions and new OAuth/PAT credentials now have a fixed seven-day lifetime. Both the signed browser session deadline and cookie expiry use seven days; server-side validation rejects an expired cookie even when replayed manually. OAuth's advertised `expires_in`, persisted token deadline, consent copy and dashboard copy agree. Existing stored sessions/tokens retain their original deadlines. Pending state (ten minutes) and authorization codes (five minutes) remain short-lived. WHOOP upstream access-token expiry remains provider-controlled and is handled by automatic refresh; no new local OAuth refresh grant was introduced.

The user-facing benefit is avoiding the earlier eight-hour browser and one-hour OAuth reauthentication triggers. The tradeoff is up to seven days of exposure for a stolen bearer/session unless invalidated. Token revocation still applies immediately on subsequent checks; revoke-all still does not invalidate dashboard sessions. Clearing cookies, upstream revocation or a separate gateway/client policy can require earlier login. The implemented gateway independently uses the same fixed seven-day session and client-token policy.

After this change, the approved offline suites passed again: 104 server tests, eight web tests and eight gateway tests, plus the server/web type checks and build. New regressions exercise a completed login past day one, signed-cookie replay exactly at day seven, fixed token expiry and no sliding renewal. Cross-review found no remaining findings in this change. Only documentation changed after that tested source snapshot.

## Remaining limits and release blockers

### Implemented Codex and Claude Code gateway

The gateway runtime is dependency-free Node 22, with `node:sqlite` (experimental in this release) for a separate persistent database. It implements OAuth discovery, public pre-registered clients, mandatory S256 PKCE, resource/audience binding, issuer identification, short-lived browser-bound pending state and single-use five-minute authorization codes. No dynamic registration or remote client-metadata fetching is exposed. Its example registrations use exact fixed callbacks `http://127.0.0.1:17643/callback` for Codex and `http://localhost:17644/callback` for Claude Code. Paths/ports must match client configuration. The WHOOP service's exact-HTTPS callback policy remains unchanged.

Owner sign-in uses a separate randomly generated 256-bit gateway secret; only its hash is configured in the runtime. The owner secret never reaches WHOOP. Fixed seven-day server-checked browser sessions and client tokens persist across gateway restarts, with no sliding expiry or refresh grant. Tokens, sessions and authorization codes are hashed at rest. Browser login and consent require matching Origin, flow-specific secure cookies and CSRF values. Consent identifies the client, exact callback, resource and access duration. Its CSP permits only the active callback's validated origin alongside the gateway itself, so browser form redirects can complete; the exact callback URI is still enforced by OAuth. Login and owner forms remain same-origin only. `/owner` shows authorization counts/deadlines and revokes each client independently; revoke-all deletes both clients' credentials, pending flows/codes and owner sessions. In-flight requests can finish across revocation. Owner-secret rotation invalidates owner sessions; use revoke-all to invalidate client grants too.

MCP requests require a bearer on every request; an owner cookie alone cannot call tools. Canonical Host/Origin checks, header/body/time/concurrency limits, strict method/input allowlists and reconstructed responses limit transport exposure. The durable store caps auth records and imposes global authorization/login/exchange budgets. These limits may deny legitimate work during flooding; protected ingress remains necessary. Numeric health-data falsification and covert information in permitted numeric values remain possible under upstream compromise.

A separate `whoopgw_service_` machine credential authorizes only WHOOP's bounded summary route for the configured WHOOP user. Its raw value resides in a private gateway secret file; WHOOP is configured with its verifier hash in `GATEWAY_SERVICE_TOKEN_SHA256`, but receives the raw bearer on HTTPS requests. A compromised WHOOP service or its TLS terminator can capture it. The captured credential authorizes that same summary route; it does not grant gateway or model-account login authority and is neither a gateway client token nor a browser/PAT credential. It has an independent operational lifetime so user sign-in every seven days does not require reconfiguring the service. Remove/change the configured hash and restart to revoke/rotate it. Losing the upstream WHOOP grant still requires WHOOP reconnection.

The runtime entrypoint binds only loopback and requires explicit canonical HTTPS origins, a private DB directory and a private regular service-token file. A strict separate Docker context includes only the seven gateway runtime modules and pins the verified Node digest. The provisioning helper writes fresh random secrets to private files without printing or overwriting them. Model account credentials and WHOOP OAuth credentials are absent from this runtime.

[Gateway setup instructions](review-gateway/README.md) contain separate Codex and Claude Code configurations and the release topology. No installed client configuration, real WHOOP grant, deployment or DNS record has been changed. The browser preview remains synthetic. Official client requirements were checked against [Codex](https://developers.openai.com/codex/mcp), [Claude Code](https://code.claude.com/docs/en/mcp) and the [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

### Gateway follow-up validation (2026-10-18)

Three subagents implemented separate auth/store, transport and client-integration work, then cross-reviewed each other's changes and the backend credential boundary. Cross-review caught a consent CSP that could block Chromium's native callback redirect; the corrected consent policy allows only the active callback origin, with delimiter-safe serialization and exact OAuth callback validation retained. No remaining actionable findings were reported within the reviewed scope.

The final run reused the previously integrity-verified dependency archive only inside a fresh pinned Node 22 container. The non-root/read-only/no-mount/no-credential/no-forwarding boundary and negative internet, metadata and host connection checks passed again. No new dependencies were fetched. The approved empty PostgreSQL fixture shared only its offline loopback namespace. A separate cached-image helper, also non-root, read-only and without network, mounts or capabilities, generated only synthetic TLS certificates; its Docker daemon was never started or exposed. TLS tests trust that explicit fixture CA and reject wrong hostnames and untrusted certificates.

| Final gateway follow-up check | Result |
| --- | --- |
| `node --test review-gateway/*.test.mjs` | 47 passed, 0 failed/skipped |
| Server `vitest run --maxWorkers=2` | 109 passed across 23 files, 0 failed/skipped |
| Web `vitest run --maxWorkers=2` | 8 passed across 3 files, 0 failed/skipped |
| Offline server/web type checks and Vite build | Passed |
| Dependency-free gateway Docker build | Passed with cached digest-pinned Node, no network, strict seven-module context |
| Packaged gateway without configuration | Failed closed with exit 1 and fixed error, offline/unprivileged/no mounts |
| `git diff --check` | Passed |

Coverage includes both pre-registered native callback shapes through the locked MCP SDK, exact PKCE/resource/client/code binding, simulated day-one reuse and exact day-seven expiry, restart persistence, independent revocation, shared durable quotas, malicious upstream responses, the real runtime entrypoint behind a certificate-verified synthetic TLS proxy, and startup/shutdown. Dedicated WHOOP summary credentials are tested against PAT substitution, missing/rotated hashes and unrelated login/MCP routes. These are protocol and synthetic runtime tests, not installed Codex/Claude binaries or actual browser OAuth.

Failed runs were retained: stale keep-alive connections in restart fixtures, an SDK error-name mismatch, unavailable OpenSSL in the pinned Node image, a synthetic TLS request accidentally using the deliberately bad HTTP Host as its TLS identity, and a smoke assertion expecting the wrong fixed error string. Test fixtures/assertions were corrected without disabling TLS verification or weakening auth checks. The CSP issue was corrected in production code and regression-tested. The final 164 tests and build passed; all test/database/certificate-helper/smoke containers are stopped. Only documentation changed after that tested source snapshot. The existing loopback-only sample preview was refreshed with the tested web build, preserving synthetic state.

The WHOOP production image, dependency-wide vulnerability scanning, deployed ingress/egress, installed native clients and real accounts remain untested. The gateway image was built locally only; no registry push or deployment occurred.

### Other release blockers

The consent-to-WHOOP browser nonce, single-use state, code/issuance transaction and default-disabled direct MCP route retain the earlier review's protections. The new concurrency tests confirm coordination inside PostgreSQL, not atomicity between WHOOP's remote token rotation and a database commit. If WHOOP rotates successfully and persistence then fails, reconnect/recovery can still be necessary. A refresh holds the user lock through the bounded upstream request; login, token issuance and revocation may wait for it.

Pending-state admission bounds stored records and cleanup work. It does not rate-limit HTTP traffic or prevent someone filling the available slots; independently protected ingress and durable request budgets remain required. If admission fails after consent has consumed the old state, the fixed 503 requires restarting that login flow. The cap does not evict active flows, and an inherited backlog may require several attempts to drain.

The implemented gateway has no deployed enforcement boundary yet. Actual browser cookie behavior and installed-client login through the chosen protected TLS ingress, dedicated runtime secrets/network policy, a separately trusted gateway release and production rollout/migration review remain release checks. Native CLI binaries and real accounts were not used by the synthetic tests. Restore of an older gateway DB can resurrect then-valid grants: revoke all before reopening restored ingress. The PR must remain draft and unmerged. Website/School files, deployments, DNS and account connections remain outside this work.


## Restricted local adapter follow-up (2026-10-18)

At the user's request, the threat model now includes a compromised remote gateway.
The new `restricted-local/` code separates human login and hourly data sync from
an offline stdio MCP reader. Both clients use their own reader/cache and seven-day
gateway grant; neither reader receives a token or contacts remote MCP. The earlier
legacy local extension is not an acceptable substitute.

The local policy is bundled with the reviewed release. It recreates exactly eight
summary fields, checks seven consecutive UTC dates, bounded numeric ranges and
precision, and rejects remote text, tool definitions, metadata, URLs and extra
fields. MCP request dates only select cached dates. Cache misses and tool calls
cannot trigger sync, login or network activity. The new authenticated gateway GET
`/data/snapshot` takes no query/body and collects only the fixed seven-day window,
charging the shared quota for each summary and rechecking the grant before each
fetch and before delivery. Failed collection returns no partial snapshot.

Local OAuth uses fixed configured endpoints, state/S256/issuer/exact callbacks,
a five-minute listener and five-second token exchange bound. No discovery or
remote-selected endpoint is used. Token files are private, client/origin-bound
and locally capped at the original seven-day deadline. Sync durably charges an
hourly attempt before networking; rejects redirects, compression, oversized or
malformed bodies; and applies a 40-second overall deadline. Cache writes are
atomic and private; reads reject unsafe file types/links, permissions, malformed
UTF-8 and unknown fields. A cache expires within 90 minutes and never outlives its
authorization. A 401 removes it. Already cached data can remain readable after
remote revocation until the next sync or that deadline; revocation cannot retract
copies already delivered. Failed sync never extends freshness.

The reviewed host-side launcher uses the fixed OrbStack socket and an empty Docker
configuration with a stripped environment. It selects immutable locally approved
image IDs and dedicated labeled per-client Docker volumes; it never mounts a host
directory or forwards credentials/SSH. The reader is non-root, read-only, network
none, capabilities dropped, no-new-privileges, memory/swap/CPU/PID limited, and sees
only its cache volume read-only. Sync/login sees only its own authorization/cache
volumes. Its process starts inert; a separate pinned helper gets NET_ADMIN only
in that container's namespace and installs default-deny IPv4/IPv6 rules before
application execution. Only the approved gateway IPv4:443 is allowed outbound;
DNS is disabled and the gateway hostname pinned locally, with TLS hostname checks
retained. Login alone exposes its exact callback port on laptop loopback. The
helper receives no Docker socket or host mounts. Operator configuration, launcher,
image IDs and Docker authority remain trusted; they are not model-facing tools.

Three subagents implemented and cross-reviewed policy/cache/reader, login/sync,
and malicious-server/launcher tests; the parent implemented the remote snapshot
endpoint and verified containers. Review fixed the container callback binding,
reader attach lifetime, cleanup after failed inspection, ignored local SDK request
metadata compatibility and Docker's canonical CAP_ spelling without widening the
capability allowlist. The final static cross-reviews reported no remaining
actionable findings within this scope.

Final validation reused the existing hashed dependency archive inside a fresh,
verified Node 22.23.3 container. No new dependencies were fetched and no lifecycle
scripts ran. Internet, metadata, host, filesystem and forwarded-credential
negative checks passed before execution. The separate empty PostgreSQL 17.11
fixture again applied only the approved branch schema to synthetic data.

| Restricted-adapter follow-up check | Result |
| --- | --- |
| Gateway Node tests, including fixed snapshot authorization/quotas | 51 passed, 0 failed/skipped |
| Local Node tests, including adversarial TLS, real SDK stdio and launcher mocks | 53 passed, 0 failed/skipped |
| Server Vitest suite, including actual PostgreSQL concurrency | 109 passed, 0 failed/skipped |
| Web Vitest suite | 8 passed, 0 failed/skipped |
| Offline server/web type checks and Vite build | Passed |
| Reader and sync image builds | Passed offline, cached pinned Node, allowlisted contexts, no packages or RUN instructions |
| Packaged reader smoke | Passed with synthetic read-only cache; writes fail EROFS, credential/host paths absent, internet/metadata/host connections denied |
| Sync network/callback smoke | Passed: namespace-only firewall, blocked unapproved public/private/metadata/IPv6 destinations, fixed hosts mapping, synthetic browser callback through laptop-loopback publication |
| `git diff --check` | Passed |

The final **221 tests** passed. Malicious HTTPS tests use an explicit synthetic CA
and real streaming transport; wrong hostnames and untrusted certificates fail.
They reject instruction strings, remote tools/prompts/resources/metadata, URL
fields, extra fields, bad dates, oversized/compressed data, redirects and raw
errors; they also demonstrate that plausible fabricated numbers pass. Locked SDK
clients exercise both client IDs over actual reader stdio. Launcher tests use an
injected Docker runner to exercise ordering, inspection drift, added capabilities
and cleanup. Separate trusted host orchestration tested the built images and
actual network/volume/callback controls; the full host launcher and installed
Codex/Claude binaries were not activated with real accounts.

Failed attempts were preserved locally. One clock-rollback fixture expected a
quota error, but token validation rejected the request earlier; the assertion was
corrected with the no-network assertion retained. Offline packaging initially
used a BuildKit-only COPY flag; root-owned files/read-only execution are preserved
with a compatible COPY. Actual Docker inspection exposed canonical CAP_NET_ADMIN
versus NET_ADMIN naming; comparison now normalizes one optional prefix and tests
reject extra, duplicate or substituted capabilities. No TLS/auth/schema check was
weakened. Test/database/certificate-helper containers are stopped, and synthetic
smoke containers/volumes were removed. Images were built locally only.

Remaining limits: a compromised remote can leak its WHOOP data/tokens and gateway
login material, deny service, or fabricate valid metrics/covert numeric messages.
The local boundary removes direct remote free-text/MCP control; it does not prove
semantic safety, data authenticity, or resistance to local parser/runtime/kernel
exploits. Other tools/files/credentials already available to a model session are
outside the reader sandbox. Use a narrowly scoped health session as well.

[RAILWAY_PLAN.md](RAILWAY_PLAN.md) documents the separate hosting proposal.
The private-transport implementation below supersedes the earlier public-IP-only
integration blocker. Railway still has no customer-enforced default-deny IPv4
egress and one shared private trust domain per environment. Only the separately
approved empty Railway project exists; no running service or deployment is claimed.

## Private connection and Railway packaging follow-up (2026-10-18)

The private launcher separates each client's Tailscale node into its own
container and state volume. Sync runs with `network:none` and sees its own
auth/cache volumes plus the relay socket volume read-only. Login receives the
same socket and a loopback-published callback; namespace rules deny all new IP
egress. Neither receives Tailscale state, its administrative socket, a general
SOCKS proxy, host files or host credentials. Reader isolation is unchanged.

The relay always connects through userspace Tailscale to the configured gateway
CGNAT IPv4:443. Its peer cannot choose a destination; admission, bytes, handshake
and total connection time are bounded. HTTPS runs end to end over the Unix byte
stream with the canonical hostname, normal certificate validation, fixed endpoint
shapes and no DNS/proxy environment/network fallback. Synthetic tests can inject
a test CA; no operator configuration or production launcher permits a CA override.

The transport itself needs public TCP443 for Tailscale control/DERP and UDP/TCP53
to 1.1.1.1. Its firewall denies LAN, metadata, host-address ranges, direct CGNAT
and IPv6 traffic; it does not constrain destinations inside encrypted Tailscale
traffic. **External tailnet ACLs must restrict each local node to only the exact
gateway:443.** A compromised transport may steal that node identity or send data
over its allowed public egress. It is credential-separated from the app, not an
internet-free process or a substitute for an ACL. No local transport is enrolled.

Railway gateway/backend wrappers run userspace Tailscale and Serve with private
HTTPS443 to loopback8787/8080. The gateway uses the same fixed TLS relay for its
single backend. Explicit enrollment reads a one-use key from stdin, writes it
only to a private temporary file, removes it on handled completion/failure and
starts no app/relay. Abrupt termination can leave that file; revoke the key and
inspect the stopped runtime before removing the residue. Normal startup requires
enrolled state. The supervisor rejects unsafe
saved configuration, verifies exact identity/settings/Serve mapping, strips child
environments and stops peers on failure. Concurrent starts fail before sharing
node state. Clean shutdown releases locks/sockets; unclean leftovers require
explicit inspected operator recovery, never automatic deletion or reenrollment.

The backend now binds loopback by default and applies migrations only with
explicit `RUN_MIGRATIONS=true`. The Railway wrapper always forces migrations and
legacy direct MCP off. Starting a runtime cannot implicitly upgrade a database.

Three subagents implemented and cross-reviewed the relay/client boundary,
deployment supervisor and adversarial tests. Review/test failures fixed a paused
SOCKS negotiation retaining a cancelled client, concurrent state writers,
partial enrollment-key cleanup and daemon spawn-error cleanup. Strict rejection
and cancellation assertions were retained. No final actionable finding remained
within their reviewed source scope; this is not an exhaustive security audit.

Validation reused the hashed dependencies only inside a newly verified offline
Node22.23.3 container. No npm fetching or lifecycle scripts ran. Official pinned
Tailscale1.104.1 images were fetched from the registry; Node/Tailscale platform
manifest digests are in the Dockerfiles. Native vendor binaries and exact CLI
settings were checked offline on ARM64 and AMD64 without enrollment. The observed
unenrolled state was empty; populated live state and certificate issuance still
need verification after approved enrollment. PostgreSQL again used only the
approved disposable synthetic fixture.

| Private-connection check | Result |
| --- | --- |
| Server Vitest suite, including PostgreSQL concurrency | 110 passed |
| Gateway Node suite | 51 passed |
| Local Node suite, including actual TLS/Unix/SOCKS and launcher failures | 72 passed |
| Deployment config, supervisor and Serve proxy-contract suite | 15 passed |
| Web Vitest suite | 8 passed |
| Server/web type checks and build | Passed offline |
| Local sync/transport ARM64 and remote gateway/backend AMD64 images | Built offline from allowlisted artifact contexts |
| Packaged sync with default transport selection | Separate containers, read-only Unix volume, synthetic TLS, wrong-host rejection, fixed destination, hourly limit and 90-minute cache passed |
| Packaged remote services and local transport | Non-root/offline; missing enrollment/config fails closed; pinned vendor versions run |
| Packaged backend startup | Health response works on loopback only; no database connection or migration at default startup |
| Graceful cleanup kernel check | Same-UID signal stays inside the private PID namespace; synthetic socket/lock removed while namespace PID1 survives |
| Actual production namespace firewall rules | 27 positive reachability controls and 27 policy checks passed on an internal dual-stack fixture network; approved HTTPS/DNS and callback replies work, prohibited destinations/ports and new login egress fail |

Final suites total **256 passed, zero failed/skipped**. Failed intermediate
attempts and logs are retained locally. Earlier fixture/string-buffer and test
runner discovery failures were corrected; native AMD64 packaging required
architecture-specific manifests rather than cached multiarch tags. The separate
container smoke uses synthetic credentials/certificates only. No image was
pushed, deployed or connected to a real account.

Firewall tests used synthetic public/metadata/tailnet address aliases on a fresh
internal Docker bridge, with no external traffic or published ports. All 12 peer
sentinels remained live after policy checks. The production rule strings were
exported only inside the verified offline Node container. Two harness failures
were corrected without changing policy: Docker error-message case and the UDP
fixture's reply source address. All network helpers, fixture containers and that
network were verified removed. Disposable build/test/database containers were
also removed; the existing sample preview was left running.

Actual Tailscale enrollment, effective ACL negative-access tests, Serve certificate
issuance, private routing from the laptop/browser, and installed Codex/Claude
login/callback behavior remain live release gates. The Serve tests exercise the
reviewed vendor proxy contract; they are not a deployed Serve assertion.
Dependency/base-image vulnerability review, a least-privilege database role,
backup/restore/revocation rehearsal and an explicitly approved migration plan
also remain. See [deployment instructions](deploy/railway/README.md). Railway's
egress/shared-environment limitations and the earlier remote-compromise limits
still apply. Seven-day authorization remains unchanged. The PR stays draft and
unmerged; no deployment, DNS, real WHOOP connection, installed client settings or
unrelated website/School files changed.
