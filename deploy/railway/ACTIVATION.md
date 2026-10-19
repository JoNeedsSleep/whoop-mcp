# Personal real-data activation plan

Prepared 2026-10-19. This is a reviewable plan, not evidence of deployment or
permission to perform its remaining account, billing or database actions.
The existing Railway deployment still uses synthetic data. Keep the PR draft.

## Resource change

Use the existing dedicated personal WHOOP project. Keep the gateway in its
staging environment. Create the backend and PostgreSQL in the currently empty
production environment, which has a separate Railway private network. Verify
that the gateway cannot reach the database over that private network before
real data is enabled. This separation does not restrict outbound internet.

| Resource | Proposed configuration |
| --- | --- |
| Backend | One replica, 0.5 vCPU and 500 MB RAM limits, own 1 GB persistent configuration/Tailscale volume, private Tailscale HTTPS only |
| PostgreSQL | One replica, 0.5 vCPU and 500 MB RAM limits, own 1 GB persistent data volume, Railway private networking only, no public TCP proxy |
| Gateway | Existing service and origin, independent volume and credentials; reviewed production cutover after backend verification |
| Migration job | Temporary process with only a dedicated migration credential and CA; no WHOOP or gateway secret; no restart loop |
| Synthetic fixture | Preserve during verification; stop after successful cutover without deleting its volume or evidence |

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

Propose a **$25 compute usage hard limit per billing cycle**, with a $15 email
alert, for the personal workspace. Compute usage here includes CPU, memory,
storage and service egress. The workspace inventory currently shows only this
WHOOP project. Reaching the hard limit stops all its workloads; it does not
guarantee uninterrupted service. These values are prepared in the UI but have
not been saved or approved. Existing agent limits are outside this change.

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
activity does not extend it. An hourly sync and a 90-minute maximum cache age are
separate controls. They must not be bypassed to make verification pass.
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

That decision explicitly excluded new billing, real migrations and WHOOP user
consent. Present the exact resource, storage/budget, production operator and
one-off migration changes for approval once their preparation is reviewable.
Complete WHOOP consent with the owner at the actual consent screen. No DNS,
main static website, School, merge or unrelated account change is included.
