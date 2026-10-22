# Dependency advisory and reachability review — 2026-10-18

The baseline assessment below records the original lock and artifact. The
October 19 follow-up adopts a new lock and changes WHOOP
requests to the explicitly pinned standalone Undici client. Offline installation,
318 tests and the build passed against that lock. This does not clear the
real-data release or supersede the unresolved runtime findings below.

## Remediation follow-up — 2026-10-19

The independently reviewed lock adopted in the checkout has SHA-256
`78f5078b862fcf7e0516e503fffc3d4ba05d75b3f0396973d8db506051406ceb`.
It contains 729 package entries, compared with 781 in the baseline. Both root and
web manifests match the approved inputs. All package resolutions remain canonical
HTTPS registry.npmjs.org tarballs with SHA-512 integrity; no unchanged-version
package changed its resolved URL or integrity. This is provenance and version
review, not an exhaustive package-source or malware assessment.

| Package family | Adopted resolved version |
| --- | --- |
| `@modelcontextprotocol/sdk` | 1.31.0 |
| WHOOP's direct `undici` | 6.29.1 |
| Tooling/test `undici` copies | 7.30.1 and 8.12.2 |
| `vitest` and aligned `@vitest/*` packages | 4.1.11 |
| `proxy-addr`; `qs`; `fast-uri` | 2.0.8; 6.16.0; 3.1.8 |
| `ip-address`; `hono` | 10.7.1; 4.13.7 |
| `nanoid` 3.x; `source-map-js` | 3.3.18; 1.2.2 |
| `brace-expansion` 5.x; `js-yaml` 4.x; `postcss-selector-parser` 7.x | 5.0.12; 4.3.2; 7.1.6 |

Vitest's allowed transitive ranges also resolved Vite 8.3.4, Rolldown 1.2.14,
PostCSS 8.5.31, Picomatch 4.0.7, Chai 6.3.0 and Tinyrainbow 3.2.0. The web
workspace's Vite remains 8.2.0. Most removed entries were duplicate optional
esbuild 0.28.1 platform trees; this does not remove the older affected esbuild
0.18.20 chain. The changed packages' declared engines accept Node 22.23.3.
The offline installation/build/test results below establish compatibility for
the recorded snapshot, not every supported platform or live account flow.

The image's npm 10.9.4 failed during lock resolution. A separately admitted npm
12.2.1 CLI was fetched as inert bytes by a builtin-only downloader using two
fixed registry URLs, normal TLS hostname/CA verification, a pinned public IPv4,
response/time limits and SHA-512 verification. Its archive was independently
validated and reconstructed using regular files only; its first execution was
`--version` in a fresh network-none container. It was not globally installed or
added to the application dependency set.

Resolution retained the old lock and unchanged manifests. UID 1000 could reach
only the metadata proxy on loopback; the separate UID 1001 proxy could reach only
the pinned registry address on port 443, and reconstructed fixed-origin package
requests without forwarding caller headers. DNS, host/LAN, metadata, IPv6 and
direct resolver internet access were denied and negative-tested. Twelve policy
tests and the container/kernel/network gates passed. Lock-only install used
disabled lifecycle scripts/audit/funding, followed by a fixed lock-only update
of `brace-expansion` and `js-yaml`: npm initially retained their stale versions.
The second step changed only those two packages relative to the rejected
candidate. Strict validation then passed and all owned containers were removed.
Evidence is retained in `registry-lock-20261019a/attempt-20261019T042918-783c10f5/`
outside Git. Failed attempts remain retained as well.

The new lock was then used in
`dependency-tests-20261019a/attempt-20261019T043255-df7448d3/`. All 569 applicable
Linux ARM64 artifact blobs were rechecked against the new lock's SHA-512 hashes,
including reused blobs; no unverified cache entry was admitted. The networked
containers were removed before installation. Verified npm 12.2.1 installed 573
packages using only the offline cache, with lifecycle scripts disabled. The
preceding attempt stopped at `EMFILE` while adding all cache entries at once;
the retained failure was fixed by batches of 16 entries under the unchanged
512-file-descriptor limit. No network or isolation restriction was relaxed.

| Recorded check | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Backend, including real disposable PostgreSQL concurrency fixtures | 116 | 0 | 0 |
| Web | 8 | 0 | 0 |
| Gateway | 52 | 0 | 0 |
| Restricted local adapter | 72 | 0 | 0 |
| Railway runtime helpers | 39 | 0 | 0 |
| Synthetic staging helpers | 31 | 0 | 0 |
| Total | 318 | 0 | 0 |

TypeScript server/web compilation and the Vite build also passed. These are
correctness test results, not a repeated performance benchmark or a live WHOOP
test. A subsequent isolated seven-day snapshot composition regression also
passed (one test, three snapshots and 21 TLS requests), bringing the combined
count to 319; it is separate from the 318-test artifact above. The 182 captured
source files retained their original SHA-256
hashes after installation, tests and build, and exact container removal was
verified. The exported tested tree is 415,037,440 bytes with SHA-256
`be1e2c7cbae11570d661938ff8b01f2db72978dc7f9a7db84052d325fdf217b8`.
It includes installed dependencies and generated build outputs, so it is an
untrusted build artifact requiring separate runtime packaging review, not a
pristine source archive or approved production image.

The WHOOP API, code exchange and refresh helpers now import `fetch` from the
pinned Undici package. The WHOOP callback preserves an absent injected fetch so
both token exchange and profile lookup reach those defaults. Fixed destinations,
redirect rejection, ten-second request signals, scopes and exact-token 401
refresh behavior are unchanged. Six added MockAgent regressions exercise these
default paths with the global fetch replaced by a failure sentinel and outbound
network disabled, including credential-bearing redirect rejection. All six
passed within the backend suite. They do not
exercise a real WHOOP account or prove the absence of runtime vulnerabilities.

The SHA-512-verified SDK 1.31.0 artifact was inspected without host execution.
Its ESM authorization handler, token handler, client-auth middleware and provider
interface are byte-identical to 1.30.0. The token handler still requires a
verifier and forwards it to this provider only with
`skipLocalPkceValidation=true`; the provider's mandatory PKCE, stored-code
binding and supplied-redirect equality checks remain necessary. The SDK's
loopback-port matching is broader than this provider's exact callback allowlist;
the provider still gates code issuance. The independent client-facing gateway
does not use this SDK authorization server.

Remaining findings are not cleared: `braces` 3.0.3, `node-forge` 1.4.0, `tmp`
0.0.33 and the old esbuild 0.18.20 development chain remain at the baseline
versions and retain the reachability limits described below. Node still embeds
Undici 6.28.1; installing standalone Undici does not patch that copy, other
global-fetch callers, Node's pending October 21 fixes, or Tailscale's Go runtime.
The existing WHOOP response/body-validation limitations are also unchanged.
Reinspect the final production artifact and refresh advisory coverage before
release; no "zero vulnerabilities" or real-data release clearance is
claimed here.

The locked WHOOP backend/build dependency set has known advisories. It is not
cleared for a real-data release. The proposed synthetic private staging deployment
uses the dependency-free gateway and a separate numeric fixture service; it does
not contain this npm backend, its database driver, or WHOOP OAuth credentials.
That narrower staging scope still depends on Node, Tailscale, their libraries and
the container/hosting platform. Absence of npm dependencies is not absence of
vulnerable code.

## Baseline scope and evidence — October 18

This was a read-only review of public package metadata and source reachability.
No dependency was installed, updated or executed, and no advisory exploit was
run. No lockfile or production configuration was changed. Registry requests sent
only public package names and locked versions, without credentials, source files,
local paths or private package names. GitHub advisory requests were unauthenticated.
The existing backend artifact was inspected as inert tar members without executing
or extracting its code onto the host.

- Reviewed `package-lock.json` SHA-256:
  `93779c9ae0ac3e0779479ea88ef81380d10f938bfad45a204e585fd0a13ab70c`.
- Inventory: 778 package locations excluding the root/workspace links, 607 unique
  public package names, 716 unique name/version pairs. Of the locations, 420 have
  the lockfile's development flag and 358 do not. Those flags do not establish
  runtime reachability: the web workspace includes build tooling as dependencies.
- The npm bulk advisory endpoint returned 56 package/range records covering
  18 package names and 45 distinct GHSAs: one critical, 16 high, 23 moderate and
  five low. Vendor cross-checking added eight Undici advisories published October
  15 that were absent from that response. The resulting 53 distinct advisories
  contain one critical, 20 high, 27 moderate and five low. These are advisory
  severities, not 53 demonstrated exploitable application flaws.
- Checked the previously built production backend artifact, SHA-256
  `6aba51d4545b8ab7ed36632f80ca407f93ef642b06a70d5b4ecfadad54f74b93`.
  A package being present in that artifact is distinguished below from its
  affected function being called. The synthetic staging images do not use this
  artifact.
- Public audit responses, inventory, advisory metadata and static library excerpts
  are retained outside Git in the sibling `dependency-review-20261018/` evidence
  directory. Runtime version evidence is in
  `private-20261018a/vulnerability-review-20261018/node-runtime-versions.json`.

This is a point-in-time advisory/reachability assessment, not an exhaustive source
audit, malware detection result, proof of non-exploitability or complete image
scan. Disabling lifecycle scripts and verifying lockfile integrity do not make
package code trustworthy. Registry lag was observed directly here. Recheck the
lock and final images after remediation and immediately before release.

## Node's bundled HTTP client and synthetic staging

The isolated runtime reports Node **22.23.3**, bundled Undici **6.28.1**, OpenSSL
3.5.8, llhttp 9.4.3, nghttp2 1.69.0 and SQLite 3.51.3. The bundled Undici version
falls within five October 15 vendor advisory ranges. Two high-severity defects can
let a malicious HTTPS peer terminate a process using global `fetch`: a TLS 1.2
renegotiation error, and an excessive Content-Encoding chain followed by early
connection closure. Catching the application-level fetch rejection or checking
body size afterward does not fix these internal failure paths. See
[TLS renegotiation](https://github.com/nodejs/undici/security/advisories/GHSA-qrxm-fqhp-jwvm)
and [encoding-chain failure](https://github.com/nodejs/undici/security/advisories/GHSA-xjj6-f33q-929c).

The other three require function-valued custom TLS options passed through an
Undici Agent, an EventSource connection, or a WebSocket connection. No such use was
found in the intended private runtime. The fixes are in Undici **6.29.1**;
updating an npm package does not replace the copy embedded in Node. See the
[vendor release](https://github.com/nodejs/undici/releases/tag/v6.29.1).

Reachability differs by configuration:

- The private gateway wrapper injects `createUnixFetch` in
  `deploy/railway/runtime.mjs`. That adapter uses `node:https`, `node:tls` and a
  fixed Unix socket; it does not use Undici's network dispatcher, fetch decoding,
  cache interceptors, EventSource or WebSocket. Its `Headers` and `Response`
  objects only wrap already bounded data. Private local login/sync uses the same
  adapter. The offline MCP reader performs no networking.
- `deploy/staging/service.mjs` uses `node:http` to serve fixed synthetic numbers.
  Its runtime has no WHOOP, database, npm package or outbound HTTP client import.
  This supports a limited conclusion that the listed Undici network triggers are
  not used by that reviewed private staging path. It does not clear vulnerabilities
  in Node's HTTP/TLS implementation, SQLite, Tailscale or the platform.
- The real WHOOP backend's `src/whoop/client.ts` and `src/whoop/oauth.ts` default
  to global `fetch`. The standalone gateway's default and the public local
  transport also use it. A compromised configured upstream can therefore reach
  the two fetch crash paths in those modes. Fixed destinations and valid TLS do
  not help when the allowed upstream itself is malicious. Do not enable these
  paths with this runtime for the real-data release without remediation.

Node has also preannounced **high-severity security fixes for October 21, 2026**
across Node 22/24/26. On this review date its public announcement does not disclose
the affected features or patches, so the private path cannot be exempted from
those still-undetailed issues. A limited synthetic staging decision must retain
that uncertainty; real-data release requires the patched, digest-pinned runtime
and repeat validation when available.
[Node security announcement](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases).

## npm package triage

The targets below are the smallest versions identified as covering all advisories
listed here on the relevant major line. They are recommendations, not installed
versions or an assurance that no later issue exists. Transitive resolution and
compatibility must be checked in the isolated build before accepting a new lock.
“Shipped” refers to the inspected backend artifact, never the synthetic fixture.

| Package and locked version | Scope and observed reachability | Remediation target |
| --- | --- | --- |
| `@modelcontextprotocol/sdk` 1.30.0 | Direct backend dependency, shipped. Its high-severity credential-disclosure advisory affects HTTP OAuth **clients** holding credentials for another issuer; the maintainer explicitly excludes SDK servers and stdio clients. This service uses SDK server APIs; the local reader/login is SDK-free. SDK HTTP OAuth client calls found here are synthetic integration fixtures. | 1.31.0. Any future real SDK OAuth client must also retain/pin issuer metadata or clear old issuer-less stored credentials; upgrading alone is insufficient for those records. |
| `proxy-addr` 2.0.7 | Express transitive, shipped. Critical advisory requires an IPv4-mapped short-prefix or zero-leading IPv6 trust subnet. `src/app.ts` uses `trust proxy = "loopback"`; the inspected library resolves this to `127.0.0.1/8` and `::1/128`, not the affected configuration. No observed IP-trust bypass in this configuration. | 2.0.8; retain exact loopback proxy policy and forwarding-header tests. |
| `qs` 6.15.3 | Express/body-parser transitive, shipped. One advisory requires `comma:true`; the other requires an attacker-controlled object reaching `stringify`, including certain parse/stringify round trips. App/dashboard and SDK OAuth form parsers use `extended:false`; no corresponding stringify path or comma option was found. Application form bodies are bounded. | 6.16.0. |
| `fast-uri` 3.1.5 | AJV transitive, shipped. Six URL/authority-normalization advisories. Inspected use is AJV schema URI resolution, not the network destination allowlist. No remote `loadSchema` configuration was found; gateway/local destination checks use the built-in URL parser. | 3.1.8. |
| `ip-address` 10.4.0 | `express-rate-limit` transitive, shipped. Three classifier/subnet issues and one oversized Address6 diagnostic issue. Inspected rate limiter calls `is4`, `to4`, `networkForm` after `node:net.isIPv6`; it does not use the affected classifier/subnet methods, and malformed oversized input is rejected before construction. | 10.7.1. |
| `hono` 4.12.33 | SDK transitive, shipped. Eight advisories concern Hono middleware, query parsing, JSX or static generation. App uses Express; SDK's Node transport imports the separate `@hono/node-server` adapter, not these Hono application features. The inspected SDK imports Hono itself only in bundled example code. | 4.13.7. |
| `nanoid` 3.3.16 | PostCSS transitive, retained in backend artifact. Advisory affects custom zero-size generators; no application call was found. PostCSS is build tooling, not an HTTP pipeline here. | 3.3.18; remove unnecessary runtime build packages if feasible. |
| `source-map-js` 1.2.1 | CSS/build dependency, retained in backend artifact through PostCSS. Crafted indexed source maps can exhaust CPU. Build reads repository/dependency inputs; no HTTP source-map ingestion route was found. | 1.2.2; minimize shipped build tools. |
| `undici` 7.29.0 and 8.9.0 | Web/shadcn/dotenvx tooling and jsdom tests respectively; neither npm copy is in the inspected backend artifact. Eighteen advisories after vendor cross-check; malicious remote content matters if those tools perform network requests. Offline builds/tests limit that exposure. This is separate from Node's embedded 6.28.1. | 7.30.1 and 8.12.2, covering the October 15 fixes as well as earlier advisories. |
| `vitest` and `@vitest/mocker` 4.1.10 | Development only; absent backend artifact. Arbitrary file read requires redirect-mock registration through a reachable dev-server plugin or authenticated browser RPC. Approved suites run in an offline container using Node/jsdom, not an exposed public mocker plugin. | Update aligned Vitest packages to 4.1.11. |
| `brace-expansion` 5.0.9 | Glob/build-tool transitive, absent backend artifact. Three recursive/quadratic crafted-pattern denial-of-service issues. Build inputs are scoped repository/dependency files; malicious dependency content remains a threat to the disposable build. | 5.0.12. |
| `braces` 3.0.3 | Micromatch/build-tool transitive, absent backend artifact. Deep pattern nesting can exhaust the stack. | No patched version listed by the advisory at review time. Remove/replace the affected parent where possible; retain bounded, isolated builds and document unresolved exposure. |
| `esbuild` 0.18.20 | `drizzle-kit` → `@esbuild-kit/core-utils` transitive development dependency, absent backend artifact. Advisory concerns its development server allowing cross-origin reads. No esbuild serve invocation found in the approved workflow. Other locked esbuild 0.25.12/0.28.1 are outside this advisory's range. | Fixed in 0.25.0; update/remove the old parent chain rather than blindly overriding across incompatible 0.x APIs. |
| `js-yaml` 4.3.1 | Cosmiconfig/build-tool transitive, absent backend artifact. Crafted merge inputs can exhaust CPU. | 4.3.2. |
| `postcss-selector-parser` 7.1.4 | Shadcn/build-tool transitive, absent backend artifact. Crafted selectors can cause quadratic work. | 7.1.6. |
| `tmp` 0.0.33 | `external-editor` development/tooling chain, absent backend artifact. Two path/symlink issues require caller-controlled filesystem parameters. No editor invocation in the approved build/test commands. | Fixes available in 0.2.6; update/remove the parent chain and test compatibility, not an unreviewed 0.x override. |
| `node-forge` 1.4.0 | `@anthropic-ai/mcpb` development packager, absent backend artifact. RSA PKCS#1 v1.5 verification accepts malformed digest metadata under the advisory's low-exponent conditions. This packager is not used by the reviewed deployment path. | No patched version listed at review time. Do not rely on this verifier for untrusted signatures; remove/replace unused packaging tooling or await a reviewed fix. |

Important interpretation sources:
[SDK client/server scope](https://github.com/advisories/GHSA-6qxp-vccf-f47h),
[proxy trust precondition](https://github.com/advisories/GHSA-jqcg-44mw-7w3h),
[Vitest registration scope](https://github.com/advisories/GHSA-82fw-gwwq-j7x9).

The web workspace imports `shadcn/tailwind.css` but has no reviewed build command
that invokes the shadcn CLI. That broad tooling dependency brings an avoidable
network-capable dependency chain into the lock. Investigate replacing the CSS-only
use with a reviewed minimal asset/package, preserving license obligations. Also
inspect why PostCSS and compiler/type packages remain in the pruned backend
artifact; a `dev:false` lock flag or successful prune is not a minimal-runtime
guarantee.

## Recommended sequence

1. Keep staging synthetic and on the reviewed private Unix-HTTPS route. Keep the
   real npm backend and public/global-fetch transport outside this staging scope.
   Record the Node preannouncement and runtime version in the deployment decision.
2. Prepare a small reviewed lock update for the direct SDK and Vitest versions and
   the compatible transitive fixes above. Resolve the two no-patch advisories and
   older incompatible esbuild/tmp parent chains explicitly; do not run a blind
   `npm audit fix --force`.
3. Fetch only pinned registry artifacts with integrity checks in the approved
   download phase, then install with lifecycle scripts disabled and build/test
   offline. Re-run OAuth issuer/PKCE, proxy-header, form-parser, gateway/local
   transport and database concurrency coverage. Reinspect the actual artifact.
4. Adopt the security-patched Node image when available, review the disclosed
   CVEs and bundled component versions, and repeat the runtime/TLS/image checks.
   A current npm audit does not scan Node's embedded Undici or all OS/Go libraries.

No dependency or image upgrade was made as part of this report.

## Advisory register

The register records upstream severity and first fixes for the relevant locked
major lines. “None listed” means no patch was identified in the consulted advisory
on this date. Reachability and configuration prerequisites are discussed above;
the register alone is not a vulnerability exploitability verdict.

### Registry results verified against advisory metadata

| Package | Advisory / CVE | Severity | Affected range (relevant line) | First fixed version |
| --- | --- | --- | --- | --- |
| `@modelcontextprotocol/sdk` | [GHSA-6qxp-vccf-f47h](https://github.com/advisories/GHSA-6qxp-vccf-f47h); CVE-2026-104850 | high | `>= 1.12.0, < 1.31.0` | 1.31.0 |
| `@vitest/mocker, vitest` | [GHSA-82fw-gwwq-j7x9](https://github.com/advisories/GHSA-82fw-gwwq-j7x9); CVE-2026-84373 | moderate | `>= 2.1.0, < 4.1.11` | 4.1.11 |
| `brace-expansion` | [GHSA-6j4f-fj2g-mc7p](https://github.com/advisories/GHSA-6j4f-fj2g-mc7p); CVE-2026-102276 | high | `>= 4.0.0, < 5.0.10` | 5.0.10 |
| `brace-expansion` | [GHSA-q2hr-2g5m-vwhr](https://github.com/advisories/GHSA-q2hr-2g5m-vwhr); CVE-2026-102277 | moderate | `>= 4.0.0, < 5.0.12` | 5.0.12 |
| `brace-expansion` | [GHSA-qhr7-859c-m2p7](https://github.com/advisories/GHSA-qhr7-859c-m2p7); CVE-2026-102278 | high | `>= 4.0.0, < 5.0.11` | 5.0.11 |
| `braces` | [GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm); CVE-2026-93687 | high | `<= 3.0.3` | None listed |
| `esbuild` | [GHSA-67mh-4wv8-2f99](https://github.com/advisories/GHSA-67mh-4wv8-2f99); No CVE listed | moderate | `<= 0.24.2` | 0.25.0 |
| `fast-uri` | [GHSA-5jgf-p345-68v8](https://github.com/advisories/GHSA-5jgf-p345-68v8); CVE-2026-75931 | high | `>= 3.1.3, < 3.1.6` | 3.1.6 |
| `fast-uri` | [GHSA-f65p-4m7j-42xc](https://github.com/advisories/GHSA-f65p-4m7j-42xc); CVE-2026-75975 | high | `>= 3.0.0, < 3.1.6` | 3.1.6 |
| `fast-uri` | [GHSA-fph4-wmhf-6fwf](https://github.com/advisories/GHSA-fph4-wmhf-6fwf); CVE-2026-75899 | high | `>= 3.1.2, < 3.1.6` | 3.1.6 |
| `fast-uri` | [GHSA-hrr3-gc8f-f4qj](https://github.com/advisories/GHSA-hrr3-gc8f-f4qj); CVE-2026-86472 | moderate | `>= 3.0.0, < 3.1.8` | 3.1.8 |
| `fast-uri` | [GHSA-jqff-g426-hqxp](https://github.com/advisories/GHSA-jqff-g426-hqxp); CVE-2026-76172 | high | `>= 3.0.0, < 3.1.6` | 3.1.6 |
| `fast-uri` | [GHSA-qw65-cvwx-89v3](https://github.com/advisories/GHSA-qw65-cvwx-89v3); CVE-2026-84292 | high | `>= 3.0.0, < 3.1.7` | 3.1.7 |
| `hono` | [GHSA-54fx-42gc-7vw4](https://github.com/advisories/GHSA-54fx-42gc-7vw4); CVE-2026-71848 | moderate | `>= 4.12.0, < 4.12.34` | 4.12.34 |
| `hono` | [GHSA-79qm-7rj5-m7r9](https://github.com/advisories/GHSA-79qm-7rj5-m7r9); CVE-2026-71849 | low | `>= 4.7.0, < 4.12.34` | 4.12.34 |
| `hono` | [GHSA-8j4g-w8fx-2239](https://github.com/advisories/GHSA-8j4g-w8fx-2239); CVE-2026-69207 | moderate | `< 4.12.34` | 4.12.34 |
| `hono` | [GHSA-crvj-82cr-hjcx](https://github.com/advisories/GHSA-crvj-82cr-hjcx); CVE-2026-84363 | moderate | `< 4.13.5` | 4.13.5 |
| `hono` | [GHSA-f23p-vx2j-j53r](https://github.com/advisories/GHSA-f23p-vx2j-j53r); CVE-2026-71850 | moderate | `>= 3.8.0, < 4.12.34` | 4.12.34 |
| `hono` | [GHSA-g6gw-c38x-mqfc](https://github.com/advisories/GHSA-g6gw-c38x-mqfc); CVE-2026-84364 | moderate | `< 4.13.5` | 4.13.5 |
| `hono` | [GHSA-gqvv-2mrq-wpjv](https://github.com/advisories/GHSA-gqvv-2mrq-wpjv); CVE-2026-84365 | moderate | `< 4.13.5` | 4.13.5 |
| `hono` | [GHSA-hxh3-vqpv-xpqv](https://github.com/advisories/GHSA-hxh3-vqpv-xpqv); CVE-2026-93981 | moderate | `< 4.13.7` | 4.13.7 |
| `ip-address` | [GHSA-2vr4-cq9g-pvrc](https://github.com/advisories/GHSA-2vr4-cq9g-pvrc); CVE-2026-101910 | moderate | `>= 10.2.0, <= 10.5.0` | 10.5.1 |
| `ip-address` | [GHSA-h3mg-xc3c-68pw](https://github.com/advisories/GHSA-h3mg-xc3c-68pw); CVE-2026-101911 | moderate | `<= 10.7.0` | 10.7.1 |
| `ip-address` | [GHSA-j6r3-76f7-8jcv](https://github.com/advisories/GHSA-j6r3-76f7-8jcv); CVE-2026-101912 | moderate | `<= 10.7.0` | 10.7.1 |
| `ip-address` | [GHSA-rpw4-54j3-4h4q](https://github.com/advisories/GHSA-rpw4-54j3-4h4q); CVE-2026-101913 | moderate | `<= 10.5.0` | 10.5.1 |
| `js-yaml` | [GHSA-2883-xcg3-v3hh](https://github.com/advisories/GHSA-2883-xcg3-v3hh); CVE-2026-84375 | high | `>= 4.0.0, < 4.3.2` | 4.3.2 |
| `nanoid` | [GHSA-2v37-7h3g-55p8](https://github.com/advisories/GHSA-2v37-7h3g-55p8); CVE-2026-67213 | high | `< 3.3.18` | 3.3.18 |
| `node-forge` | [GHSA-86w9-cpqp-85rv](https://github.com/advisories/GHSA-86w9-cpqp-85rv); CVE-2026-85393 | high | `<= 1.4.0` | None listed |
| `postcss-selector-parser` | [GHSA-rj75-hqrm-r3gf](https://github.com/advisories/GHSA-rj75-hqrm-r3gf); CVE-2026-104844 | moderate | `< 7.1.6` | 7.1.6 |
| `proxy-addr` | [GHSA-jqcg-44mw-7w3h](https://github.com/advisories/GHSA-jqcg-44mw-7w3h); CVE-2026-90711 | critical | `>= 1.1.0, < 2.0.8` | 2.0.8 |
| `qs` | [GHSA-4mjr-xmp4-gh2g](https://github.com/advisories/GHSA-4mjr-xmp4-gh2g); CVE-2026-82417 | moderate | `>= 2.2.5, < 6.16.0` | 6.16.0 |
| `qs` | [GHSA-x5fp-wj9c-mxmx](https://github.com/advisories/GHSA-x5fp-wj9c-mxmx); CVE-2026-82562 | moderate | `>= 6.14.2, <= 6.15.3` | 6.16.0 |
| `source-map-js` | [GHSA-68fv-2mgg-jv7q](https://github.com/advisories/GHSA-68fv-2mgg-jv7q); CVE-2026-93749 | high | `>= 1.0.0, < 1.2.2` | 1.2.2 |
| `tmp` | [GHSA-52f5-9888-hmc6](https://github.com/advisories/GHSA-52f5-9888-hmc6); CVE-2025-54798 | low | `<= 0.2.3` | 0.2.4 |
| `tmp` | [GHSA-ph9p-34f9-6g65](https://github.com/advisories/GHSA-ph9p-34f9-6g65); CVE-2026-44705 | high | `< 0.2.6` | 0.2.6 |
| `undici` | [GHSA-2gqq-gqf2-x968](https://github.com/advisories/GHSA-2gqq-gqf2-x968); CVE-2026-84947 | low | `>= 7.1.0, < 7.29.1; >= 8.0.0, < 8.10.2` | 7.29.1, 8.10.2 |
| `undici` | [GHSA-2jfj-6hjv-fm6j](https://github.com/advisories/GHSA-2jfj-6hjv-fm6j); CVE-2026-84933 | moderate | `>= 7.0.0, < 7.29.1; >= 8.0.0, < 8.10.2` | 7.29.1, 8.10.2 |
| `undici` | [GHSA-3wwx-pv8p-q78v](https://github.com/advisories/GHSA-3wwx-pv8p-q78v); CVE-2026-85024 | moderate | `>= 7.28.0, < 7.29.1; >= 8.1.0, < 8.10.2` | 7.29.1, 8.10.2 |
| `undici` | [GHSA-3xpg-4rpp-hhhm](https://github.com/advisories/GHSA-3xpg-4rpp-hhhm); CVE-2026-84890 | moderate | `>= 7.15.0, < 7.29.1; >= 8.0.0, < 8.10.2` | 7.29.1, 8.10.2 |
| `undici` | [GHSA-8436-99hf-9mmv](https://github.com/advisories/GHSA-8436-99hf-9mmv); CVE-2026-85008 | low | `>= 7.0.0, < 7.29.1; >= 8.0.0, < 8.10.2` | 7.29.1, 8.10.2 |
| `undici` | [GHSA-pmjh-fq2x-6v4x](https://github.com/advisories/GHSA-pmjh-fq2x-6v4x); CVE-2026-18149 | moderate | `>= 7.11.0, < 7.29.1; >= 8.0.0, < 8.10.2` | 7.29.1, 8.10.2 |
| `undici` | [GHSA-r53p-7pc4-xj5r](https://github.com/advisories/GHSA-r53p-7pc4-xj5r); CVE-2026-18540 | low | `>= 7.0.0, < 7.29.1; >= 8.0.0, < 8.10.2` | 7.29.1, 8.10.2 |
| `undici` | [GHSA-rfgv-xxqx-mfg5](https://github.com/advisories/GHSA-rfgv-xxqx-mfg5); CVE-2026-19534 | high | `>= 7.0.0, < 7.29.1; >= 8.0.0, < 8.10.2` | 7.29.1, 8.10.2 |
| `undici` | [GHSA-rx4f-c7p8-82vq](https://github.com/advisories/GHSA-rx4f-c7p8-82vq); CVE-2026-85014 | moderate | `>= 7.0.0, < 7.29.1; >= 8.0.0, < 8.10.2` | 7.29.1, 8.10.2 |
| `undici` | [GHSA-w293-vg96-wgc3](https://github.com/advisories/GHSA-w293-vg96-wgc3); CVE-2026-84961 | high | `>= 7.24.1, < 7.29.1; >= 8.0.0, < 8.10.2` | 7.29.1, 8.10.2 |

### October 15 vendor supplement missing from the bulk response

All rows concern `undici`. The five rows with a 6.x range include the measured
Node-bundled 6.28.1; all eight include both locked npm versions.

| Advisory / CVE | Severity | Affected ranges | First fixed versions |
| --- | --- | --- | --- |
| [GHSA-qrxm-fqhp-jwvm](https://github.com/nodejs/undici/security/advisories/GHSA-qrxm-fqhp-jwvm); CVE-2026-87018 | high | `>=4.2.1, <6.29.1; >=7.0.0, <7.30.1; >=8.0.0, <8.12.2` | 6.29.1, 7.30.1, 8.12.2 |
| [GHSA-2m5v-pch6-74hx](https://github.com/nodejs/undici/security/advisories/GHSA-2m5v-pch6-74hx); CVE-2026-109383 | high | `>=4.0.0, <6.29.1; >=7.0.0, <7.30.1; >=8.0.0, <8.12.2` | 6.29.1, 7.30.1, 8.12.2 |
| [GHSA-xjj6-f33q-929c](https://github.com/nodejs/undici/security/advisories/GHSA-xjj6-f33q-929c); CVE-2026-109869 | high | `>=6.23.0, <6.29.1; >=7.18.0, <7.30.1; >=8.0.0, <8.12.2` | 6.29.1, 7.30.1, 8.12.2 |
| [GHSA-4w7w-5xrc-9h26](https://github.com/nodejs/undici/security/advisories/GHSA-4w7w-5xrc-9h26); CVE-2026-109829 | high | `>=7.0.0, <7.30.1; >=8.0.0, <8.12.2` | 7.30.1, 8.12.2 |
| [GHSA-4qv8-2p9j-2685](https://github.com/nodejs/undici/security/advisories/GHSA-4qv8-2p9j-2685); CVE-2026-109924 | moderate | `>=6.5.0, <6.29.1; >=7.0.0, <7.30.1; >=8.0.0, <8.12.2` | 6.29.1, 7.30.1, 8.12.2 |
| [GHSA-9fm3-97px-rjf6](https://github.com/nodejs/undici/security/advisories/GHSA-9fm3-97px-rjf6); CVE-2026-109932 | moderate | `>=5.15.0, <6.29.1; >=7.0.0, <7.30.1; >=8.0.0, <8.12.2` | 6.29.1, 7.30.1, 8.12.2 |
| [GHSA-55wc-3pg8-jfw6](https://github.com/nodejs/undici/security/advisories/GHSA-55wc-3pg8-jfw6); CVE-2026-87029 | moderate | `>=7.15.0, <7.30.1; >=8.0.0, <8.12.2` | 7.30.1, 8.12.2 |
| [GHSA-f72v-6w45-q472](https://github.com/nodejs/undici/security/advisories/GHSA-f72v-6w45-q472); CVE-2026-109841 | moderate | `>=7.15.0, <7.30.1; >=8.0.0, <8.12.2` | 7.30.1, 8.12.2 |
