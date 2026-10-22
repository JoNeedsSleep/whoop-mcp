This separate one-shot process checks the finalized database with **only the runtime credential**. It does not start the backend, run migrations, read application rows, write data or change grants. It reuses the reviewed migration artifact's dependency tree, including unused Drizzle packages, but imports only `pg`; no packages are fetched or installed during image construction. No migration SQL or application module is copied. Build with the pinned AMD64 Node base and an exact reviewed source/dependency inventory, with public source readable by UID1000. Source preparation is not evidence of a live database check.

The bounded input is exactly `{host,port:5432,database:"whoop",user:"whoop_runtime",password,caCertificate}`. The host must be the separately approved single-label `.railway.internal` hostname and the explicit current CA must match the database's trust anchor. The password is the existing 64-character generated runtime password; no migration/admin/WHOOP credential belongs here. TLS verifies that exact host, with no insecure fallback. The packaged entrypoint accepts no arguments. Use private non-TTY stdin, or the explicitly scoped temporary `WHOOP_DATABASE_PROBE_BOOTSTRAP` variable through the fixed shell bridge. The bridge checks UID/GID1000 and kernel no-new-privileges before reading the variable, pipes it using shell builtin `printf`, and clears the environment before Node starts. Secrets are never argv or output.

Run once after finalization and before backend activation, in the approved private database network, with no volume mounts or public ingress, no restart policy, bounded resources and no other credentials. The process uses one connection, server read-only transactions, fixed search path, 3-second statement and 15-second overall database deadlines. A 25-second CLI watchdog includes input and shutdown. It issues only fixed catalog/privilege `SELECT` statements plus `SELECT 1`; it never attempts DDL or a write as a negative probe. It requires verified TLS, the exact runtime session/database, no privileged role attributes or memberships, disabled owner/migrator logins, revoked migration authority, no database/schema create or temp permission, owner-owned exact six tables, exactly 24 non-grantable CRUD grants, no extra table privileges and no ledger access. Output is only a fixed success object (including `crudPrivileges:24`) or `Database probe unavailable.`. Failure is unknown/not-ready, never a pass.

This is a point-in-time permission observation, not a migration-ledger-content check, data correctness check, proof of SCRAM configuration, or protection against a compromised database/provider. It does not read password hashes, health/authentication rows or the migration ledger. Metadata checks cannot prove the result of every future SQL statement or rule out later grants. Existing isolated write/denial tests provide separate synthetic evidence. Closing a client is not instant server cancellation; the statement deadline remains the bound on server work.

Remove the temporary deployment and its active bootstrap variable after collecting the fixed result. A provider variable may remain in historical deployment/platform records; clearing the shell variable does not erase that history. No secret is written to the filesystem by this utility. Reusing the completed migration service requires replacing its image with this fixed runtime-only artifact and removing the migration bootstrap first; never supply the runtime credential to the migrator or retain migration authority merely to run this check.

Validation on 2026-10-20 UTC passed eight unit tests and 22 recorded synthetic workflow checks, including six privilege-drift/recovery cases, wrong CA/SAN, plaintext refusal, and unchanged application/ledger fingerprints around each probe. All 12 isolation checks, 205 pre/post source hashes, and cleanup of ten containers plus one disposable volume passed. The 22 checks include the unit-test group and fixture preparation; they are not 22 additional unit tests. Evidence: `private-20261018a/db-probe-20261020a/attempt-20261020T012716-a8c2251b`.

The initial AMD64 image was `sha256:a7818a814a8ae7de05e7e54e7be67538febd6aa910f99f22e1a6b173a82acc90`; its public build-context SHA256 was `a7a4509bf2af99805f0be7b01c7c6f3a3452708eadfe886b7c25672c5e9e2b5e`. The offline build fetched/installed nothing. A fresh isolated packaged smoke verified 2,795 file hashes and modes, all 12 isolation controls, exact fixed errors for empty/malformed input and unexpected arguments, environment clearing before Node, no listeners, unchanged source, and exact cleanup. Evidence: `private-20261018a/db-probe-image-20261020a/attempt-20261020T012905-b48b11b8`; the preceding sandbox-denied image inspection is retained.

The current upload package stores those same 2,792 dependency files in the fixed
local `db-probe-dependencies.tar`, which Docker `ADD` extracts at
`/app/node_modules/`. This avoids the pinned Railway CLI 5.68.0 uploader's
unconditional `node_modules` path exclusion; `--no-gitignore` does not override
that exclusion in its [versioned source](https://github.com/railwayapp/cli/blob/v5.68.0/src/controllers/upload.rs).
The three runtime files, every dependency byte, root ownership and mode0444
remain unchanged. No package resolution, installation or network fetch occurs.
Only the independently hash-verified archive belongs in this build context.

The repackaged AMD64 image is
`sha256:9373c7f320b957a7dcb435d768554d4e0b70f5e9f4f3a92fa6af70738c805478`;
its 13,076,480-byte context SHA256 is
`a6abf68bd49a6e40e5c597d7c5e5c23be1f2ba07fb5afeb425029c4ed7467bc0`.
The fresh packaged check again verified all 2,795 files, actual `pg`/probe
imports, the four fixed-error/environment cases, no listeners, all twelve
isolation controls and exact cleanup. Evidence:
`private-20261018a/db-probe-upload-tar-20261020a/attempt-20261020T051659-5037edbe`.
It did not repeat the database workflow or contact a live database. Both image
checks ran under OrbStack AMD64 translation, not native Railway, and existing
runtime advisories remain unresolved.
