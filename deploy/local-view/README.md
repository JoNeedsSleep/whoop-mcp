# One-time local WHOOP viewing

This separate local session requests profile and four health-read permissions,
without `offline` or refresh-token storage. It uses the fixed registered callback
`http://localhost:17645/whoop/callback`. WHOOP must accept that registered URI;
local browser/cookie checks alone do not establish provider support. Use the
intended replacement app with valid, unexposed credentials. No Railway resource,
database, Tailscale state, enrolled node, remote gateway or model credential is
used by this session.

The fixed config shape is `{mode:"whoop-local-view",clientId,clientSecret}`.
The separately guarded runtime admits bounded private stdin only after UID/GID
1000, NNP and cleared-environment checks. Start it when the owner is ready: the
five-minute lifetime begins at server creation and never resets. Its isolated
container edge must have verified host-loopback publication and namespace
firewall controls; source checks alone do not establish that boundary.

The browser opens localhost, chooses **Continue to WHOOP**, follows the explicit
official sign-in link, signs in and authorizes the requested permissions. The
callback checks the original browser, state and PKCE exchange; it makes one
bounded profile request and asks the human to confirm the escaped name/email.
Health collection starts only after **This is my account**. Cancel revokes the
temporary grant without collecting health records.

After confirmation the same-origin progress page refreshes while a bounded
collector reads seven UTC days. The snapshot contains only the existing numeric
recovery, HRV, resting-heart-rate, sleep-duration, sleep-performance and strain
fields plus fixed dates/statuses. Workout read permission is requested as part
of the approved health-read scope set, but workout records are not needed for
these existing summaries. Missing data remains unavailable, not zero. There are
no retries, refresh tokens, scheduled requests or writes to a database/cache.

The session must successfully revoke the WHOOP grant before displaying any
summary values. Revocation affects this developer app's account connection, so
do not reuse an app with another connection you intend to keep. Collection or
revocation failure withholds all values and gives fixed manual-revocation
instructions. Closing/expiry aborts collection and attempts bounded cleanup,
including a token that arrives after shutdown began. A hard kill, network failure
or provider outage can prevent revocation; check/revoke the app connection in
WHOOP before another attempt. No automatic retry is performed.

The final table uses no scripts or external assets and contains no profile
name/email, client secret or token. The runtime closes after delivering it; the
static browser page remains visible until closed/reloaded. `no-store` does not
erase browser memory, screenshots or saved pages. The service keeps credentials,
profile and snapshot in memory only and emits fixed status messages, never
health values, identifiers or upstream errors. Values are provider data rather
than independently verified measurements. No snapshot is automatically sent to
Codex, Claude or another model.

This is a one-time seven-day snapshot, not persistent syncing or an installed
client integration. It does not establish the backend numeric allowlist or
activate the separate 15-minute restricted-reader deployment. The profile-only
identity verifier is unchanged.

Validation passed in isolated Node 22 fixtures: 29 focused tests covering the
collector, session and runtime, with no failures or skips. Tests include
provider-shaped optional callback scopes, account confirmation, cancellation,
revocation-failure withholding, late-token cleanup and delivery of the complete
response through the real loopback relay during shutdown. Kernel isolation,
source hashes before/after execution and exact container cleanup were checked.
Inputs and upstream responses in these tests were synthetic.

A separate human-authorized live run confirmed WHOOP's localhost callback,
account confirmation, seven UTC summary rows and successful temporary-grant
revocation before display. Before credential delivery, the operator checked
loopback-only host publication, denied other-container and non-loopback host
connections, denied unrelated egress and verified WHOOP TLS. An external LAN
device was not used for testing. No credentials or health values were copied
into validation evidence or documentation.

The separate profile-only verifier must retain profile-only permissions and
receive its own callback-compatibility review before any future activation.
For persistent local syncing and client integration, see
[the local sync mode](../local-sync/README.md).
