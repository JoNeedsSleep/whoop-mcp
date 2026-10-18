# WHOOP security review branch

Review draft based on upstream `148f12076885cfe3f5f35b21a315ff71832c11e2`.
This is not an approved deployment. The server/web build and test suites now pass in a verified disposable Node 22 environment. The branch schema and database concurrency tests ran only in a separately approved, empty synthetic PostgreSQL fixture. Keep this PR draft and unmerged.

## Intended boundary

A fully compromised WHOOP service must have no OpenAI login, OpenAI API key, browser session, GitHub token, SSH key, DNS credential, hosting administrator credential, unrelated application secret or unrelated filesystem mount to steal. WHOOP health data and the service's WHOOP-specific tokens are within the assumed compromise. The remaining `read:profile` permission also makes name/email available to a compromised service; dropping the profile tool alone cannot prevent that.

Use separate trust domains:

```text
Codex / Claude Code / ChatGPT / authorized user
        | authenticated, client-initiated tool requests
        v
Separately trusted minimal gateway
  fixed reviewed tool definitions; strict input and output validation
  no model API key; no other applications; no upstream tool discovery
        | fixed HTTPS endpoint + dedicated WHOOP-service-only bearer
        v
WHOOP service + dedicated database
        | WHOOP-only OAuth credentials, restricted outbound access
        v
WHOOP API
```

The gateway must run in a separate security principal and isolated environment, with its own reviewed, pinned release. Do not mount this service's filesystem/database into it, share service administration credentials with it, or automatically deploy gateway changes from an untrusted WHOOP build. A filter inside the WHOOP service cannot enforce the boundary after that service is compromised.

`review-gateway/gateway.mjs` is the dependency-free data adapter. It exposes one immutable tool definition, accepts a real UTC date, requests only `/internal/health-summary`, denies redirects, limits decoded responses to 4096 bytes, validates every field, rejects extra properties and text/URLs in data, and recreates the result. Numeric values are bounded and precision-limited. It never calls model APIs or forwards upstream tool metadata, sampling requests, resources, prompts, model outputs, errors or redirect advice.

The independent gateway now implements Streamable HTTP MCP, its own OAuth authorization server, exact pre-registered Codex/Claude Code callbacks, browser-bound owner sign-in/consent, and durable SQLite authorization/rate-limit state. Client-to-gateway tokens are distinct from the gateway-to-service machine credential. A configured public client ID identifies a client registration, not attested application software. The gateway exposes only reviewed protocol methods and the fixed summary tool. Thirty tool calls per rolling hour and one in-flight upstream request are enforced across both clients and restarts using the same persistent database; run one replica with one local DB. Independent per-process DB copies do not enforce a common budget.

The WHOOP service's legacy `/mcp` remains absent by default (`ENABLE_LEGACY_DIRECT_MCP=false`). Its summary endpoint now accepts only the dedicated machine credential and resolves the configured numeric WHOOP identity server-side. User PATs cannot call it. Missing machine-token hash disables the endpoint. Firewall WHOOP ingress so only the gateway reaches the summary endpoint, and protect its admin/OAuth interface separately. Runtime isolation, HTTPS ingress and actual client activation still need deployment verification; source-code implementation is not a deployed enforcement boundary.

Schema validation blocks instruction-bearing strings and unapproved fields. It does **not** authenticate plausible numbers, dates or enum values: a compromised server can fabricate a normal-looking recovery score, encode information in valid metrics, omit records, or cause denial of service. The tests explicitly demonstrate acceptance of plausible falsified data. Clinical correctness and provenance need independent verification. No absolute security or impossibility of prompt injection, model misuse or distillation is claimed. Keeping model credentials and outputs away from the server, disallowing server-initiated model calls, and applying independently enforced quotas substantially limits opportunities; it cannot prove that all misuse is impossible.

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
- Disable dependency lifecycle scripts in Docker builds, use a separate production dependency stage, allowlist build-context files and run as the unprivileged `node` user. The WHOOP production image has not been built. Its release still needs reviewed digest pinning and vulnerability checks; the independent gateway image is covered below.

## Isolation and release requirements

1. Keep the static jojiao.com website on GitHub Pages. No website or School files, DNS, hosting, account connections or existing credentials were changed for this work. A future WHOOP subdomain can be decided separately.
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

A separate `whoopgw_service_` machine credential authorizes only WHOOP's bounded summary route for the configured WHOOP user. Its raw value resides in a private gateway secret file; WHOOP receives only a hash in `GATEWAY_SERVICE_TOKEN_SHA256`. It is neither a gateway client token nor a browser/PAT credential. It has an independent operational lifetime so user sign-in every seven days does not require reconfiguring the service. Remove/change the configured hash and restart to revoke/rotate it. Losing the upstream WHOOP grant still requires WHOOP reconnection.

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
