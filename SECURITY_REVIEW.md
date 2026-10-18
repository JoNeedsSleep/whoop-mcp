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

`review-gateway/gateway.mjs` is a dependency-free adapter prototype. It exposes one immutable tool definition, accepts a real UTC date, requests only `/internal/health-summary`, denies redirects, limits the decoded response to 4096 bytes, validates every field, rejects extra properties and text/URLs in data, and recreates the result. Error text is a fixed constant. Numeric values are bounded and precision-limited. Calls are limited to 30 per hour with one request in flight per adapter instance. It never calls OpenAI, accepts model credentials, forwards upstream tool metadata, sampling requests, resources, prompts or model outputs.

It does **not** implement public MCP transport, ingress authentication, production network isolation, durable/distributed quotas or deployment. Those require a separate reviewed gateway release before any model account is connected. Use independently authenticated client identity, audience-bound gateway tokens, shared durable budgets and explicit allowlists there. Reject all unsupported protocol methods. The WHOOP service's legacy `/mcp` route is now absent by default; `ENABLE_LEGACY_DIRECT_MCP` defaults to `false`. Explicitly enabling it restores a raw-record transport that bypasses this unfinished gateway; leave it disabled for this design. It is not a gateway integration switch. Firewall the service so only the gateway reaches the health-data endpoint; keep its admin/OAuth interface separately protected. Do not trust a compromised service's authentication metadata or redirect advice.

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
- Disable dependency lifecycle scripts in Docker builds, use a separate production dependency stage, allowlist build-context files and run as the unprivileged `node` user. No Docker image has been built. Images still need reviewed digest pinning and vulnerability checks before deployment.

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

Not executed: Docker production image build, vulnerability scanning of every dependency, real WHOOP or model-account OAuth, actual gateway/ingress topology, deployment, DNS or any migration of an existing database. No external account was connected.

## Seven-day sign-in preference

At the user's request, new dashboard sessions and new OAuth/PAT credentials now have a fixed seven-day lifetime. Both the signed browser session deadline and cookie expiry use seven days; server-side validation rejects an expired cookie even when replayed manually. OAuth's advertised `expires_in`, persisted token deadline, consent copy and dashboard copy agree. Existing stored sessions/tokens retain their original deadlines. Pending state (ten minutes) and authorization codes (five minutes) remain short-lived. WHOOP upstream access-token expiry remains provider-controlled and is handled by automatic refresh; no new local OAuth refresh grant was introduced.

The user-facing benefit is avoiding the earlier eight-hour browser and one-hour OAuth reauthentication triggers. The tradeoff is up to seven days of exposure for a stolen bearer/session unless invalidated. Token revocation still applies immediately on subsequent checks; revoke-all still does not invalidate dashboard sessions. Clearing cookies, upstream revocation or a separate gateway/client policy can require earlier login. The eventual gateway's independent session policy must also honor this preference.

After this change, the approved offline suites passed again: 104 server tests, eight web tests and eight gateway tests, plus the server/web type checks and build. New regressions exercise a completed login past day one, signed-cookie replay exactly at day seven, fixed token expiry and no sliding renewal. Cross-review found no remaining findings in this change. Only documentation changed after that tested source snapshot.

## Remaining limits and release blockers

### Codex and Claude Code requirement

Both local clients are intended to connect concurrently through the separately trusted gateway. Each must receive its own revocable, audience-bound gateway credential with a fixed seven-day access period; WHOOP service PATs and gateway-to-service credentials must not double as client credentials. OpenAI and Anthropic account credentials stay outside the WHOOP service and gateway. The frontend now describes this planned setup and removes direct service URLs and token-filled shell/config snippets. No client configuration or account connection was made.

Official [Codex MCP documentation](https://developers.openai.com/codex/mcp) and [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp) confirm HTTP MCP and browser OAuth support. Their native callback defaults use HTTP loopback addresses with variable ports; the WHOOP service deliberately accepts only explicitly allowed exact HTTPS callbacks. Compatibility therefore remains blocked until the independent gateway implements a reviewed native-client callback policy, PKCE, resource/audience binding and authenticated client identity. Do not widen the WHOOP service's callback policy or enable legacy direct MCP as a workaround.

Before real connections, test both clients against the actual gateway: simultaneous access, exact registered callback behavior (reject foreign host/path), successful return from browser sign-in, day-one reuse, rejection at day seven, reauthorization prompts, and independent revocation. Verify that revoking Codex leaves Claude Code working and vice versa, while shared durable request budgets cannot be bypassed by using both. Local clients must reach the protected gateway; hosted/cloud client connectivity is a separate requirement. The gateway's seven-day policy is planned, not implemented by this documentation change.

For this UI/documentation change, the eight web tests and full server/web type checks and build passed again in a fresh verified offline Node 22 container using the unchanged lockfile and integrity-checked dependency archive. The container was stopped afterward. Backend code was unchanged, so server/database/gateway tests were not repeated. Independent cross-review found no issues in the guide or documented boundary.

### Other release blockers

The consent-to-WHOOP browser nonce, single-use state, code/issuance transaction and default-disabled direct MCP route retain the earlier review's protections. The new concurrency tests confirm coordination inside PostgreSQL, not atomicity between WHOOP's remote token rotation and a database commit. If WHOOP rotates successfully and persistence then fails, reconnect/recovery can still be necessary. A refresh holds the user lock through the bounded upstream request; login, token issuance and revocation may wait for it.

Pending-state admission bounds stored records and cleanup work. It does not rate-limit HTTP traffic or prevent someone filling the available slots; independently protected ingress and durable request budgets remain required. If admission fails after consent has consumed the old state, the fixed 503 requires restarting that login flow. The cap does not evict active flows, and an inherited backlog may require several attempts to drain.

The gateway remains an unfinished adapter prototype with no deployed enforcement boundary. Actual secure-cookie behavior through a reviewed TLS proxy, full client OAuth integration, dedicated runtime secrets/network policy, a separately trusted gateway release and production rollout/migration review remain blockers. The PR must remain draft and unmerged. Website/School files, deployments, DNS and account connections remain outside this work.
