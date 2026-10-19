# Personal WHOOP integration privacy notice

Draft deployment notice, 2026-10-19. This app is for its owner's personal use.
The currently deployed test services contain synthetic data only. Real WHOOP
access requires the owner's separate consent and the remaining release checks.

## Information used

After authorization, the dedicated backend can read the WHOOP recovery, sleep,
cycle and workout data permitted by the grant. Profile permission is used to
check the owner's WHOOP user ID; WHOOP also makes name and email available under
that permission. The application does not persist the profile email. The app
does not receive the owner's Google/Gmail password.

The backend stores its WHOOP user ID, encrypted WHOOP OAuth tokens, and
application authorization/session state in a dedicated database. Encryption at
rest does not protect tokens from a fully compromised running backend that has
the decryption key. The backend fetches health records from WHOOP when needed;
this version does not maintain a complete historical health archive.

## Information sent to assistants

The restricted local adapter supplies seven recent daily summaries containing
date/status, recovery score, heart-rate variability, resting heart rate, sleep
duration, sleep performance and strain. It does not forward WHOOP profile text,
raw workout descriptions or remote tool instructions. The gateway and local
sync process handle those summaries; the offline reader exposes them to Codex
or Claude Code when the owner invokes its tool.

Data used in an assistant conversation may be processed or retained by that
assistant's provider under the owner's selected account, product and settings.
The integration cannot delete copies retained in conversations or exports.

## Service providers and retention

The intended hosting provider is Railway. Private connectivity uses the owner's
Tailscale account. Those services process infrastructure or connection metadata;
an encrypted connection does not eliminate provider metadata or account access.
The integration does not need credentials for the owner's other applications.

Gateway sessions and client grants have a fixed seven-day lifetime. The local
reader accepts a cached snapshot for at most 90 minutes, or until its grant
expires if sooner. An expired cache file may remain on disk until overwritten
or removed; expiry prevents reader use and is not physical deletion. Database,
hosting-volume and backup retention must be configured when real data is
activated; no automatic deletion or backup-retention promise is made here.

## Control and limitations

The owner can revoke individual gateway grants or all gateway grants, revoke
the WHOOP integration through WHOOP, and stop the services. A valid offline
cache can remain readable until its short expiry after remote revocation.
Deleting databases, local caches, hosting volumes or backups requires a separate
deliberate operation. Do not post health records, tokens or credentials in this
repository's issues or pull requests.

This remains an experimental personal integration. The security review records
known runtime and hosting limitations; it does not promise that health data or
WHOOP-specific credentials are safe after a server compromise. Deployment and
data-scope changes must be reflected in this notice before they take effect.
