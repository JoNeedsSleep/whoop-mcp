# WHOOP security review branch

Review draft based on upstream `148f12076885cfe3f5f35b21a315ff71832c11e2`.
This is not an approved deployment. The server build, database migrations and full dependency test suite have not been run.

## Intended boundary

A fully compromised WHOOP service must have no OpenAI login, OpenAI API key, browser session, GitHub token, SSH key, DNS credential, hosting administrator credential, unrelated application secret or unrelated filesystem mount to steal. WHOOP health data and the service's WHOOP-specific tokens are within the assumed compromise. The remaining `read:profile` permission also makes name/email available to a compromised service; dropping the profile tool alone cannot prevent that.

Use separate trust domains:

```text
ChatGPT / authorized user
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
- Use the canonical configured dashboard callback, secure `__Host-` cookies (HttpOnly, SameSite=Lax, Path=/, no Domain), eight-hour server-checked sessions, state and PKCE. Revoke the temporary login token after session establishment.
- Atomically consume pending WHOOP states with `DELETE ... RETURNING` after browser validation. Authorization-code consumption and MCP token insertion occur in one transaction under a user-row `FOR UPDATE` lock shared with revoke-all and PAT issuance. If redemption wins, revoke-all waits and then revokes its token; if revoke-all wins, the code is gone and redemption cannot mint a token. Failed code validation rolls the transaction back. Enforce client, deadline and mandatory S256 verifier validation during exchange. SDK 1.30.0 passes the verifier only with `skipLocalPkceValidation=true`; this flag delegates checking to our mandatory provider validation, not to a trusted client. A supplied token-request redirect URI must match exactly; omission remains supported by the SDK's OAuth semantics.
- Persist fixed one-hour OAuth and seven-day PAT expirations; advertise stored expiration rather than extending it on each verification. List/revoke both token types in the dashboard and add revoke-all. Revocation does not cancel requests already executing, invalidate dashboard sessions, stop WHOOP authorization flows that have not minted a local code yet, or prevent separately authorized PAT creation/new login after the revocation transaction. The shared lock fixes the consumed-code/late-token race; it is not an account-wide authorization freeze.
- Migration `0002` expires and revokes every legacy MCP credential. This is a deliberate reauthorization requirement. Existing WHOOP grants and in-flight pending login records are not a deployment migration strategy; clear old pending authorizations/client registrations and review existing grants before later rollout.
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

Completed:

- GitHub authenticated login verified as `JoNeedsSleep` (ID 39445027) before fork creation and rechecked afterward. Fork page showed `JoNeedsSleep/whoop-mcp`, forked from `caxtmann/whoop-mcp`, at the reviewed upstream commit.
- Source, package scripts, Dockerfile, lock provenance and relevant test fixtures inspected without executing the third-party project.
- Lock review: 781 entries; all remote tarballs use registry.npmjs.org and have integrity values; the only non-HTTPS resolution is the local web workspace. Six entries are flagged with installation scripts (esbuild variants/fsevents). This is not a complete dependency audit.
- Downloaded the locked MCP SDK 1.30.0 tarball solely for static review; its SHA-512 matched the lockfile. Inspected token handler/provider/registration/router source to verify PKCE and redirect semantics; no SDK code executed.
- Eight dependency-free gateway tests passed on Node 22.14.0, with an empty environment, filesystem read permission restricted to this new checkout, child processes/native addons/workers disabled by Node's permission mode, and synthetic fetch responses. No remote requests, credentials or data were used by these tests. Node permission mode is not claimed as an OS sandbox for hostile dependency code.
- All 41 server/test TypeScript files parsed using Node's built-in `stripTypeScriptTypes` in transform mode, without module execution or dependency imports. This is syntax checking, not TypeScript type checking or TSX validation. An initial `--check` attempt could not parse one TypeScript file; the explicit TypeScript parser succeeded. `git diff --check` passed.

Not executed:

- npm installation, TypeScript type checking, server or web Vitest suites, Docker build, PostgreSQL migrations/integration tests, real client OAuth, WHOOP or OpenAI connections, deployment or DNS.
- The macOS sandbox smoke test failed with exit 134 before third-party execution (nested invocation was initially unavailable). No project code or dependencies were run to bypass this failure. No approval is pending in a tool dialog. A verified disposable environment and approval to install/run there are required for the outstanding execution checks.

Added regression tests cover fixed expiration, exact callbacks, PKCE, concurrent code consumption, consent rendering, hostile Host headers, host-only cookies, revoke-all, scope/identity restrictions, summary projection and raw-error suppression. Those Vitest tests are authored but **unexecuted**. Real database concurrency and full end-to-end OAuth remain release blockers, even if mocked tests later pass.

## Follow-up independent review

The review of head `986a608f495cdb9756e718f802e7602a6ddd2211` correctly identified that consent approval discarded its browser binding before the WHOOP callback. This follow-up preserves the nonce through that leg, checks it before any destructive state operation or WHOOP request, and adds a two-browser regression with an authorized-browser success/replay check. Old pending payloads without a browser binding fail closed.

The legacy direct MCP route is disabled by default; the gateway remains an unfinished adapter prototype with no deployed enforcement boundary. Revoke-all and OAuth issuance now share one user-row lock, and code consumption plus token insertion are atomic. Added real PostgreSQL concurrency tests deliberately pause between code consumption and insertion, observe the competing backend waiting on a database lock, and cover both winner orderings. Database tests now require both `WHOOP_TEST_DB_DISPOSABLE=true` and `WHOOP_TEST_DATABASE_URL`; they do not use runtime `DATABASE_URL`.

Follow-up validation is static only: all 44 server/test TypeScript files were parsed with Node's built-in TypeScript parser without execution or dependency loading, and `git diff --check` passed. Browser-binding, route-default and revocation regression tests were authored but not executed. No dependencies were installed, no failed sandbox was retried, and no database, server, browser OAuth flow or gateway code was run in this follow-up. Earlier eight gateway tests remain historical evidence for the unchanged prototype, not evidence that these new authorization changes passed. Full type checks and integration/concurrency execution remain blocked pending an approved, verified disposable environment. The PR must remain draft and unmerged.
