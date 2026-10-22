This is a separate, one-off procedure for the existing expired migration login.
Live inspection ran on 2026-10-20; renewal has not run. Inspection deployment
`2ff863bb` reported the old expiry `2026-10-20T03:34:11.923887Z` after confirmed
local PostgreSQL shutdown, then was removed. Automatic approval review rejected
the renewal request because the earlier migration approval did not clearly
authorize extending the expired credential. Specific owner approval for the
additional hour is pending. This procedure does not renew a Railway operator
session or expand that session's selected role.

The original `VALID UNTIL` deadline expires password authentication, not the
role's LOGIN attribute, grants or existing sessions. See
[PostgreSQL role expiry](https://www.postgresql.org/docs/17/sql-createrole.html).
This helper changes only `whoop_migrate.rolvaliduntil`. It never sets a password,
changes LOGIN, grants membership/permissions, runs migrations or enables runtime
access. The same stored credential would work for up to one additional hour;
the absolute compiled deadline is **2026-10-21 01:16 UTC**. That is renewed access
and must not be described as a read-only operation.

Use the temporary `Dockerfile.migration-window` image on the existing database
service/volume only after the listener fix is validated and the normal database
deployment is stopped and removed. Keep the backend and migration job stopped,
all bootstrap variables absent, one volume owner, and restart policy Never.
The fixed entrypoint clears the environment before Node, requires UID/GID 999
and kernel no-new-privileges, and accepts only:

1. `inspect`: verify the exact private enabled-state/configuration, obtain the
   existing expiry through the local Unix peer-admin connection, stop PostgreSQL,
   and emit one fixed metadata record.
2. `renew <previousValidUntil>`: use the exact six-fractional-digit UTC timestamp
   from the approved inspection record. No hostname, SQL, role, password or
   duration selector exists. The timestamp is public metadata, not a credential.

Both operations take the existing exclusive volume lock and start PostgreSQL
with `listen_addresses=''`. They check the original three role attributes,
exact membership/options and database/schema privileges, runtime NOLOGIN,
no other client sessions, and empty owner-controlled `public`/`drizzle` schemas.
Any relation, function, type or migration ledger there rejects the operation.
They inspect only catalog metadata, never WHOOP/application rows. The stored
password is checked internally for SCRAM format but neither its plaintext nor
its verifier is output. The helper checks TLS-key file metadata without reading
the key. Original configuration, state marker and finalization code stay unchanged.

Renewal requires an already expired finite deadline equal to the exact supplied
old timestamp and no later than the recorded **2026-10-20 04:49 UTC** checkpoint.
Database time must be at or after that checkpoint. One transaction changes only
that deadline to the earlier of
database time plus one hour and the compiled hard stop. A replay with the same
timestamp fails, even after the renewed deadline expires. The renewed deadline
is necessarily after the checkpoint, so supplying its newly inspected value
also cannot renew again. Inspection can report a finite nonexpired deadline
immediately after an uncertain commit, without changing it. No automatic retry,
expiry refresh or rollback-to-old-expiry occurs. An uncertain commit needs
inspection before further action.

SQL statements, lock waits and subprocesses are bounded. Success is reported
only after confirmed local PostgreSQL shutdown; the temporary process then holds
inertly for deliberate operator removal. Failure attempts bounded shutdown and
retains the ownership lock if child/server termination is unconfirmed. Starting
and stopping PostgreSQL can write its ordinary server/WAL files even for the
read-only inspection transaction; this is not a filesystem snapshot operation.

After approved renewal, remove the temporary deployment, start the reviewed
normal database image, verify TLS, run the existing three-migration job once,
and perform unchanged `finalize` and runtime-role verification. Finalization
removes migration LOGIN/password/membership/CONNECT and the owner's temporary
database CREATE privilege. Do not infer health-data activation or WHOOP consent
from any migration-window result.

Isolated validation passed on 2026-10-20: seven new unit tests, twelve reused
provisioning unit tests and 26 workflow records. A disposable TLS/SCRAM database
proved expired-role inspection, exact-old-value renewal, refusal of wrong expiry,
runtime LOGIN drift, extra database privilege and nonempty schema; only the
expiry changed while password and privilege fingerprints stayed unchanged.
Both old-expiry replay and renewal using the new expiry failed. The original
migrations, finalization, runtime permissions, TLS negatives and restart checks
then passed. The active-other-session rejection is source reviewed but was not
separately exercised by this run.

The cached AMD64 image is
`sha256:a21acdb7fa250fc3c3ca59cfafaf543e31efc194ff6cc95d095e9efcfced9eac`;
its 51,200-byte public context SHA256 is
`8253c442f2ad6757d88002592574effa467fc9be0aed07977f2a6a052e71e941`.
Twelve isolation checks, 204 source hashes and cleanup of 35 containers and one
fresh volume passed. Evidence is retained in
`postgres-migration-window-20261020a/attempt-20261020T050657-0288bed9`.
These are local synthetic results under translated AMD64. The separate live
inspection above does not establish renewal, migrations or authorization.
