# Private staging validation — 2026-10-19

This deployment uses synthetic data only. No WHOOP account, WHOOP token, real
health record, OpenAI credential or Anthropic credential has been connected.
The pull request remains draft. The user's later request for real WHOOP data
authorizes preparation; account authorization and the real-data release checks
remain outstanding.

## Live network checks

The two Railway services run in the dedicated private staging environment.
Neither has a Railway public domain or published TCP proxy. The personal
Tailscale policy allows only browser-to-gateway TCP 443, the two dedicated local
client tags to gateway TCP 443, and gateway-to-fixture TCP 443. The provider
accepted the policy and its 10 tests containing 115 accept/deny assertions.
Those policy assertions are not 115 live packet tests.

Bounded live probes verified the gateway certificate and hostname with normal
certificate validation, negotiated HTTP/1.1 when HTTP/2 was also offered, and
rejected HTTP/2-only negotiation. An unauthenticated snapshot returned 401;
an unrelated Host returned 403. CONNECT and an HTTP/2 connection preface did not
establish a tunnel. Fixture HTTPS, gateway SSH and gateway plain HTTP were
unavailable from the browser node. Unavailability alone does not distinguish an
ACL denial from the absence of a listener.

The first probes were unsuccessful while the TLS certificate was being issued.
Diagnostics identified a missing certificate trust bundle in the slim runtime.
The images now copy the public trust bundle from the pinned Tailscale image;
certificate verification was never disabled. The successful retry and the
earlier failures are both retained in private operator evidence.

## Client callback and data checks

Both dedicated local transport nodes enrolled and reached their ready state.
Their containers have no host bind mounts, SSH forwarding or unrelated account
credentials. OrbStack public CA injection is explicitly disabled and inspected.
The reader has no network; only the sync/login process holds its own gateway
grant and reaches the fixed HTTPS destination through its transport socket.

A real browser login test found that `Referrer-Policy: no-referrer` on the login
form caused the browser's POST Origin to fail the strict origin check. The
scripted HTTP fixtures did not expose this because they set Origin explicitly.
HTML forms now use `strict-origin`; JSON and redirect responses retain
`no-referrer`. Origin and CSRF checks remain strict. The isolated gateway suite
passed all 28 tests and the change was independently cross-reviewed.

Both real browser callbacks then completed: Codex at `127.0.0.1:17643/callback`
and Claude Code at `localhost:17644/callback`. Claude reused the existing owner
session without another secret entry. The owner page and isolated token metadata
showed separate grants expiring seven days later. These are protocol and adapter
registration tests, not a claim that native Codex or Claude settings have been
installed or that a model session has read real health data.

One synthetic, single-use callback code appeared in diagnostic output because
the browser used the callback URL as its page title. The code was PKCE-bound and
already redeemed. Subsequent diagnostics suppress both URL and title. The Codex
test grant was revoked, and an isolated read-only probe confirmed HTTP 401 while
the owner page retained the separate Claude grant. No WHOOP credential or real
health data was involved.

A fresh Codex authorization then completed without repeating the owner sign-in.
The safe owner page showed one active grant for each client, with independent
seven-day expiry times. The previously revoked grant was not restored.

Normal snapshot sync failed for both clients. A separate read-only diagnostic
received HTTP 503 from the gateway before local schema validation. A temporary,
independently reviewed gateway diagnostic then confirmed the fixed SOCKS target,
normal certificate/hostname validation, HTTP 200 and a valid single synthetic
summary. The normal snapshot still returned 503 on the subsequent probe, so the
successful single request does not establish a working seven-day snapshot path.
That diagnostic was removed by a fresh normal deployment, whose startup was
verified. Later, capped fixed-stage diagnostics on the persistent path showed
two valid summaries followed by a five-second TLS handshake timeout. The third
request's SOCKS tunnel was established in three milliseconds; previous relay
peers closed normally, and no admission rejection occurred. This narrows the
failure to the encrypted connection after tunnel establishment; it does not yet
prove a vendor, network or adapter defect. These probes did not modify client
caches or local hourly admission state and are not counted as successful syncs.
An independent native TLS probe then reproduced the failure without the gateway
HTTP parser or either relay adapter: the first two verified TLS handshakes
succeeded, then five timed out as the peer path changed from DERP to direct.
With the pinned vendor's experimental relay-only switch, all seven handshakes
succeeded over DERP. This supports a direct-path-dependent failure, not a proven
MTU diagnosis or a general Tailscale defect.

The verified synthetic staging wrapper now enables that gateway-only workaround.
The production backend/gateway wrappers and local transports retain their normal
defaults. A fresh normal deployment restored the guarded entrypoint and removed
all temporary probes, stage logging and byte-count diagnostics. Its reviewed
20-file source artifact passed 44 focused regression tests; Railway reported a
successful deployment and normal synthetic startup. See the
[workaround's scope and limits](README.md#synthetic-staging-transport-workaround).

A full live Codex proof used the normal sync implementation, default clock/TLS,
and existing seven-day grant to fetch all seven expected synthetic rows. A second
sync was correctly limited. A separate offline reader, with only the scratch
cache mounted read-only, passed MCP initialization, the immutable tool list and
the expected numeric response. Fresh disposable state/cache volumes were removed
afterward; the original client's cache and admission state were not changed.
This successful proof used the relay experiment immediately before the clean
deployment. A subsequent Claude proof against the clean deployment was
unavailable; a bounded status-only probe confirmed the preserved shared rolling
hour quota returned HTTP 429. Its scratch resources were also removed. The quota
has not been reset or relaxed to make the test pass. Both native client settings
and normal client caches remain unactivated.

## Current isolated checks

The adopted dependency lock passed 318 tests: 116 backend, 8 web, 52 gateway,
72 restricted local, 39 Railway runtime and 31 staging. Both server/web builds
passed, with no failed or skipped tests in that run. A subsequent composition
test passed three complete snapshots through the normal gateway, fixed relay,
Unix HTTPS adapter and synthetic TLS service: 21 requests including each oldest
`NO_DATA` row. It did not reproduce the live failure. Seven additional lifecycle
tests passed with SOCKS half-closes, retained TLS writable halves, fragmented and
different address-type replies, rejected handshakes and early client FIN. Relay
slots were released in those fixtures; this also did not reproduce the live
timeout. The same eight composition/lifecycle tests also passed on the pinned
AMD64 Node image under OrbStack translation, with the same Node/OpenSSL versions;
that is not a native Railway network reproduction. The temporary diagnostic
overlays passed the relevant lifecycle and snapshot tests. The final staging
runtime change passed 44 focused tests with verified isolation and cleanup.
These are functional tests, not a claim of vulnerability-free code or universal
deployed reliability.

Registry fetching and execution were separate. All 569 selected package
artifacts passed integrity checks; installation and tests ran offline in verified
Node 22 containers without host files, credentials or SSH forwarding. The
PostgreSQL fixture contained synthetic data only. Container cleanup and source
hashes were verified. See [dependency review](../../DEPENDENCY_REVIEW.md) for
the updated versions, retained failed attempts and unresolved advisories.

## Remaining real-data requirements

Real activation needs the WHOOP developer application, its exact private HTTPS
callback, the owner's numeric WHOOP identity verified before login, and the
owner's OAuth consent. It also needs a dedicated database and restricted runtime
role, separately authorized migrations, a newly built and reviewed backend,
and a decision on the unresolved runtime findings in `DEPENDENCY_REVIEW.md` and
`IMAGE_SECURITY_REVIEW.md`.

Railway's observed writable root filesystem and default outbound internet access
do not satisfy the stricter production boundary described in `SECURITY_REVIEW.md`.
Tailscale ingress policy does not supply a default-deny egress firewall. A passing
synthetic staging test cannot be used to claim those controls are deployed.

The restricted adapter currently supplies seven days of bounded numeric daily
summaries. Seven-day login lifetime is a separate setting. Neither setting means
that all historical WHOOP records have been imported.
