# Personal real-data activation plan

**Retired in favor of local-only sync.** The WHOOP Railway project was deleted
through the normal 48-hour recovery window, and Hobby renewal was cancelled.
Railway confirmed that it was stopping account resources and showed a final
amount due of $0.00; the existing paid period ends on 2026-11-18. The obsolete
gateway receipt schedule is paused. The replacement WHOOP app secret and real
health grant were kept local. The local connection, two client readers and quiet
15-minute worker were verified separately; see
[local sync](../local-sync/README.md). Keep the PR draft and unmerged.

The remainder records historical Railway preparation and validation. It is not
the current runtime or authorization to recreate services. Deletion is not proof
of erasure from provider backups or variable history. Personal Tailscale device
registrations and access rules were not removed by deleting the Railway project.

Prepared 2026-10-19. This is a reviewable plan, not evidence of deployment or
permission to perform its remaining account, billing or database actions.
The gateway still uses synthetic data. Keep the PR draft.

The owner subsequently approved the production-scoped temporary operator,
private backend/database resources, the three fresh-database migrations and a
single-use personal Tailscale enrollment key. The two private services and their
volumes now exist with the approved compute limits. Backend node enrollment
succeeded; its enrollment key is invalidated and its active bootstrap variable
was removed. Database-only credentials have now been delivered through the
reviewed non-root provisioning phase. The three migrations and subsequent
finalization completed, including revocation of the temporary migration
authority. The restored listener passed the independent runtime-role
TLS/privilege probe. No confirmed numeric WHOOP owner ID or health-data grant
has been obtained.

The separately approved browser/gateway-to-backend HTTPS rule was saved and
verified after reloading the policy, with eleven policy tests. The private
hostname resolves and the browser reaches the temporary identity page over
HTTPS. An earlier save failed a test that confused a gateway tag with the
approved exact device address; only that test was corrected, without broadening
the grant. The initial identity form redirect stalled before WHOOP consent.
After a reviewed change to an explicit sign-in link, 26 isolated tests and
packaged-image checks passed; the updated private helper reached the official
WHOOP sign-in page. The user confirmed that they signed in without clicking an
authorization button. A fresh verifier was opened afterward, but successful
authorization, owner confirmation and temporary-grant revocation have not been
observed. That five-minute verifier has expired; no owner ID was accepted.
The subsequent verifier deployment `36679510` became ready at 05:34:10 UTC on
2026-10-20 and returned its fixed unavailable status at 05:39:10 UTC. The browser
was still at the official sign-in page, without an observed authorization or
account confirmation. That expired deployment was removed and its persistent
volume preserved. A fresh owner-present flow remains required; do not reuse
the expired authorization link or infer a confirmed ID from successful sign-in.

The first PostgreSQL initializer refused the provider's empty `lost+found`
directory. A separate reviewed read-only inspector confirmed that it was the
only entry, owned by root, mode0700 and empty; PostgreSQL directories, state and
lock files were absent. This is evidence of the observed failed attempt, not
successful initialization or permission to overwrite any later content. The
strict provider-layout compatibility fix subsequently passed isolated validation.

At the live checkpoint on 2026-10-19 (CDT), the database phases were:

- Root initializer `dcc93d0b` emitted its fixed success marker at 21:21:48,
  then was removed.
- Non-root fence `bdfc24f1` reached its guarded state, then was removed.
  Database-only bootstrap delivery occurred after this fence.
- Configure deployment `651bbc96` completed at 21:27:03, then was removed.
  The active `WHOOP_POSTGRES_PROVISION` variable was deleted, and the Railway
  UI showed **No Environment Variables**.
- Enable deployment `4ecc9bfb` completed, then was removed. The temporary
  migration login was enabled with its one-hour validity limit.
- The normal PostgreSQL upload was accepted, but deployment `6306abf7` finished
  as **COMPLETED**, not running. At 02:38:24.413 GMT on 2026-10-20 it reported
  `could not create any TCP/IP sockets`. No listener or TLS check passed, and
  the three migrations and subsequent finalization/revocation checks had not run.
- Temporary diagnostic deployment `28dd95a1`, with only
  `log_min_messages=log` changed, also completed without running. At
  02:43:54.826 GMT it reported `Cannot assign requested address` for both
  DNS-resolved address families. The listener, TLS and HBA configuration were
  unchanged. This establishes the bind failure, but not which local interfaces
  should be selected. The diagnostic was removed and its command override
  cleared. Clearing it caused Railway's automatic normal-command relaunch,
  which also stopped; this did not establish readiness.
- A separately reviewed metadata-only diagnostic, deployment `93d2c179`, found
  exactly loopback and `railnet0` interfaces. The latter had private IPv4 and
  ULA IPv6 addresses plus an IPv6 link-local address. Neither service-DNS
  address matched a local interface address. The diagnostic completed and was
  removed. The reviewed runtime fix selects only `railnet0`'s private IPv4 and
  ULA IPv6 addresses; no wildcard listener was enabled.
- The corrected normal deployment `69f10600` was observed **Active/Online** on
  2026-10-20 and accepted the credential-free TCP probes described below.
  It was subsequently removed before the separate migration-window inspection.
  This establishes a working listener at that checkpoint, not database TLS,
  authentication or migration readiness.
- The one-hour migration password-validity deadline elapsed before any
  migrations ran. Expiration prevents password authentication; it does not
  itself revoke LOGIN, role membership or database CREATE. This required
  separate approval for one bounded renewal before migrations could proceed.
- Inspection deployment `2ff863bb` verified the expected empty schemas and
  migration-role state, then shut down its local PostgreSQL process before
  reporting the existing deadline `2026-10-20T03:34:11.923887Z` at
  `2026-10-20T05:23:55.803633Z`. The inspection deployment was removed.
  Automatic approval review rejected the subsequent one-hour renewal request
  because the earlier migration approval did not clearly authorize extending
  this expired credential. No renewal command executed at that point. The
  owner subsequently approved the exact additional hour; the reviewed command
  accepts only that inspected old deadline and cannot renew twice.

The approved renewal subsequently succeeded. The one-off migration job emitted
`Migrations completed.`, then was removed and its active bootstrap variable
deleted. With the normal database stopped, the finalizer emitted
`PostgreSQL preparation phase completed.` after committing migration-login,
password, membership and database-grant revocation, removing the schema owner's
temporary database CREATE privilege, and validating the exact tables and
migration ledger before enabling runtime CRUD. It stopped its local PostgreSQL
process before reporting success. The finalizer deployment was then removed
and the default listener restored. The separate TLS-verified runtime-role probe
reported `whoop-runtime-database-probe`, `passed: true` and `crudPrivileges: 24`,
verifying the expected CRUD permissions and absence of the prohibited privileges
checked by that probe. The probe deployment and its active runtime bootstrap
variable were removed; the temporary service has no environment variables.
These results do not establish backend or
WHOOP activation.

The fixed credential-free network probe passed source review and nine isolated
tests with all twelve isolation checks. Production deployment `6cf3cee3`
recorded `POSITIVE_CONFIRMED` at 05:14:25.853 UTC on 2026-10-20: both DNS families
resolved and TCP port 5432 connected on both observed addresses. Staging gateway
probe `4e2f7a0c` recorded `UNREACHABLE_OBSERVED` at 05:19:52.923 UTC: both DNS
families returned `NOT_FOUND`, and attempts to the exact positive-control
addresses timed out for IPv4 and returned unreachable for IPv6. These probes
sent no application bytes or credentials and did not test PostgreSQL TLS,
authentication, SQL or health data. They establish time-specific reachability
and unreachability, not durable firewall isolation or protection against later
network/configuration changes.

The gateway was restored as deployment `bd0326bf`, **ACTIVE**, with the exact
original staging gateway command. The private operator receipts
`database-network-positive-receipt.json`, `database-network-negative-receipt.json`
and `gateway-network-test-restoration-20261020.json` retain these results.
Migrations, finalization and independent runtime-role TLS/privilege verification
are complete. WHOOP owner confirmation and health consent remain incomplete.
Removing active provisioning variables does not erase provider history.

## Resource change

Use the existing dedicated personal WHOOP project. Keep the gateway in its
staging environment. The backend and PostgreSQL now occupy the dedicated
production environment, which has a separate Railway private network. Verify
that the gateway cannot reach the database over that private network before
real data is enabled. This separation does not restrict outbound internet.

| Resource | Proposed configuration |
| --- | --- |
| Backend | One replica, 0.5 vCPU and 500 MB RAM limits, own provider-default 5 GB capacity persistent configuration/Tailscale volume, private Tailscale HTTPS only |
| PostgreSQL | One replica, 0.5 vCPU and 500 MB RAM limits, own provider-default 5 GB capacity persistent data volume, Railway private networking only, no public TCP proxy |
| Gateway | Existing service and origin, independent volume and credentials; reviewed production cutover after backend verification |
| Migration job | Temporary process with only a dedicated migration credential and CA; no WHOOP or gateway secret; no restart loop |
| Synthetic fixture | Preserve during verification; stop after successful cutover without deleting its volume or evidence |

The owner accepted the provider-default capacity after clarification. Railway's
Hobby volumes default to 5 GB and cannot currently be downsized; billing follows
actual storage used, including filesystem metadata, rather than all allocated
capacity. [Railway volume reference](https://docs.railway.com/volumes/reference).
The database stores authorization and encrypted token state; it is not a health
history archive. The approved resources now exist; that does not establish
normal service readiness or completion of the verification gates.

PostgreSQL uses the official 17.11 bookworm AMD64 manifest
`sha256:66aafa11cf15800a3c94763f7e11d1e7b2e37e5e84bc4ce027cb6e1e4bfaf4df`.
The running backend must use the final reviewed image after the database TLS
guard is tested, rather than the earlier backend preparation image.

At the [published Railway rates](https://railway.com/pricing), two additional
services continuously consuming both of those CPU and memory limits would cost
about **$30.02 per 30 days in compute**, plus storage and outbound traffic.
Actual billing is for resource consumption, so this calculation is not a usage
forecast or a total bill cap. The existing gateway and fixture also incur usage;
stopping the fixture after cutover avoids retaining its ongoing compute cost.
Hobby has a $5 minimum including $5 of usage, rather than an additional $5 on top
of usage above that amount. Volumes cost about $0.16 per GB per 30 days and service
egress costs $0.05 per GB at these rates.

The owner explicitly authorized the **$25 compute usage hard limit per billing
cycle** on 2026-10-19. The personal workspace's Railway Usage page was then
observed already showing that saved limit; the previous pending-status report
was stale. The existing $15 email threshold and separate agent limits were left
unchanged. Compute usage here includes CPU, memory, storage and service egress.
The workspace inventory showed only this WHOOP project. Reaching the hard limit
stops all its workloads; it does not guarantee uninterrupted service or cap
separately billed subscriptions, agent usage or tax. This budget approval does
not itself authorize production resources, migrations or WHOOP consent;
the resource/migration approvals were obtained separately as recorded above.

For initial activation, propose no paid backup schedule or historical health
archive. WHOOP remains the source of health records. Losing the database would
require rebuilding it and reconnecting accounts; losing node state requires
reenrollment. Do not restore an old gateway authorization database into active
ingress without revoking its restored grants. A backup schedule or historical
import can be selected separately; neither is silently included here.

Railway's [hard compute limit](https://docs.railway.com/pricing/cost-control)
can stop workloads across the workspace. Do not silently change that setting
without checking unrelated projects and obtaining approval for that effect.

## Database and secret handling

Use a fresh dedicated database. Do not reuse an existing database or apply these
migrations to unrelated data. The runtime role receives CONNECT, public-schema
USAGE and CRUD on exactly the six application tables. It receives no ownership,
schema creation, role-management authority or migration-ledger access.

The separate [migration utility](../migrate/README.md) uses a temporary login
with membership in a NOLOGIN schema owner. Standard Drizzle requires CREATE on
this dedicated database during migration; this is not global CREATEDB. Revoke
that privilege and disable the temporary login after verified completion.
The ordinary backend always starts with migrations disabled.

The backend gets only its WHOOP app credential, WHOOP token encryption/session
keys, restricted database credential, public configuration and the hash of its
gateway machine credential. The gateway gets no WHOOP app or database
credential. Its raw machine credential is separate from browser/client grants.
Neither gets a Railway administrator token, Tailscale administrator credential,
GitHub token, model-provider key, personal home directory or SSH agent.

Provisioning must use private files and a separately reviewed delivery channel.
The proposed channel uses a separate production-environment Railway project
token in the official isolated CLI; it requires no account-wide token or SSH key.
Temporary Railway variables carry bounded, service-specific provisioning
envelopes into fixed stdin bridges, which clear the environment before Node.
Railway handles those secrets and may retain deployment history; removing an
active variable does not prove historical erasure. Root initialization runs only
on the fresh dedicated volumes without bootstrap/app credentials, then drops
privileges. Secret handling runs as the dedicated non-root service user. Normal
application startup rejects its bootstrap variables; normal PostgreSQL instead
clears its inherited environment. The operator must verify active provisioning
variables are removed before normal deployment. Do not reuse the synthetic provisioning
schema for real credentials or print secret-bearing configuration, database URLs
or responses.

Revoke the temporary production operator token and remove its isolated CLI
container after the approved operation, within 24 hours at the latest. Do not
extend human delegation silently. The pinned CLI's variable-delete command can
redeploy the current phase: account for that behavior, verify phase completion,
and deliberately select the normal command and reviewed artifact. Removing a
variable alone is not proof that the intended normal deployment is running.

After the original four-hour operator container expired, the reviewed
replacement reused the same production-scoped token and authority. The private
`production-session-20261020/result.json` records no new token, preservation of
the old stopped container and public-upload evidence, and no adoption of old
upload receipts. The replacement expires at 09:19:20 UTC on 2026-10-20; the
original delegation hard stop remains 01:16:00 UTC on 2026-10-21. This replacement
does not extend the approved delegation or authorize additional operations.

After owner verification and database finalization, the separate
[backend configuration helper](../backend-provision/README.md) accepts only the
confirmed numeric owner ID, matching existing WHOOP app identity, restricted
database credential, public CA, session/encryption keys and service-token hash.
It preserves identity and node state and publishes `app.json` last. Its nine
tests and packaged offline smoke passed; this is not live provider verification.

The [gateway helper](../gateway-provision/README.md) first reports only four
fixed configuration-file hashes for the stopped gateway. The one-use cutover
envelope binds those exact bytes, the approved backend hostname/address and a
fresh machine credential. It preserves owner/client configuration, SQLite and
node state, blocks startup during partial replacement and publishes runtime
configuration last. Its 22 tests and packaged inspection/cutover smoke passed.
No helper grants permission to leave overlapping deployments on the same volume.

## Identity, consent and verification

The WHOOP developer app exists with the exact proposed private callback and
recovery, cycles, sleep, workout and profile read scopes. Body measurements are
excluded. App creation did not authorize access to a member's data.

Verify the owner's numeric WHOOP `user_id` independently before setting the
backend allowlist. The app Client ID is not that identifier. If no trusted account
surface exposes it, prepare a separate one-time profile-only OAuth verification,
with the owner present, before the real health-data grant. Do not admit whichever
account happens to log in first and do not weaken the existing allowlist check.
The [temporary identity verifier](../identity/README.md) requests only
`read:profile`, reads name/email/user ID, and requires the owner to confirm the
displayed account. It displays the numeric ID only after successful revocation
of that temporary grant. The operator must bind that exact confirmed ID; the
utility never writes the production allowlist or requests health/offline scopes.

Enroll a dedicated backend Tailscale node in the personal tailnet. Review its
actual address before adding only browser-to-backend and gateway-to-backend
HTTPS access. Preserve denied reverse access, local-client-to-backend access,
SSH, routes, exit nodes, Funnel and public ingress. Use a one-use enrollment key
and revoke it after enrollment. Operator authority for the production Railway
environment must be explicitly scoped; do not broaden the staging CLI role.

Before release, verify private TLS including negative certificate/hostname
checks, runtime database permissions, cross-environment database denial, the
exact WHOOP callback, secure cookies and allowed identity. Revoke all synthetic
gateway grants, codes, pending flows and owner sessions using the existing owner
route, and verify old grants return 401 **before** stopping the gateway and
changing its upstream to real data. Preserve the quota database through cutover.
Then obtain fresh client authorizations and verify sequential Codex
and Claude syncs through their separate offline readers. Record status/schema
counts rather than health values. Native client configuration is a separate
activation step and has not yet been installed.

The implemented data product is **seven recent UTC daily summaries**, with six
bounded numeric metrics plus date/status. It is not an all-history import or a
raw workout archive. Each gateway/client grant lasts a fixed seven days;
activity does not extend it. The approved data-sync cadence is one attempt per
client every 15 minutes; the watch waits 15 minutes after completion, so startup
and request time add to that interval. The 90-minute maximum cache age remains
a separate control. Neither limit may be bypassed to make verification pass.
This is source preparation: real-backend deployment, real-data sync and installed
client activation have not occurred. The hourly security-receipt schedule is
independent and unchanged.
The later health-data consent includes a separate WHOOP refresh grant: its
upstream access can renew until the integration is disconnected or revoked,
independently of the seven-day gateway login. See the [privacy notice](../../PRIVACY.md)
for cache expiry versus deletion and data handling by assistant providers.

## Accepted limits and remaining approvals

The owner explicitly accepted personal Railway use with writable container
filesystems, unrestricted outbound internet, unresolved runtime advisories and
the experimental relay workaround. This acceptance does not remediate those
limits. A compromised backend can still steal WHOOP data/tokens; a compromised
gateway can steal gateway login material or fabricate plausible metrics. The
pinned offline reader rejects remote free text and arbitrary MCP metadata, but
does not prove metric authenticity or eliminate local runtime/kernel risks.

That initial decision explicitly excluded new billing, real migrations and WHOOP
user consent. The subsequent specific resource, storage, production operator and
fresh-database migration approvals are recorded above; do not infer approval for
additional resources, an existing database or broader operator authority.
Complete WHOOP consent with the owner at the actual consent screen. No DNS,
main static website, School, merge or unrelated account change is included.
