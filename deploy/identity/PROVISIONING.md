# Temporary backend identity preparation

Local preparation only; these files do not authorize billing, deployment, real
database migration or WHOOP consent. The separate identity verifier needs explicit
profile-only consent and does not set the real backend's numeric allowlist.

Use only reviewed immutable AMD64 images built offline from the pinned cached
Node/Tailscale artifacts, with public source files normalized to root-owned mode 0444.
The normal identity image contains no compiled WHOOP app, npm dependencies or DB.
The separate `Dockerfile.init` image defaults to the fixed empty-volume initializer
and contains no identity HTTP service. It runs as root only to create/chown the
empty `/data/config` and `/data/tailscale` directories, then clears supplementary
groups and drops UID/GID to 1000 before reporting sanitized controls and waiting.
It refuses populated directories, symlinks, unrelated entries and any bootstrap
or WHOOP/database environment input. Never supply secrets during this phase.

After the volume and provider controls are approved, use the normal non-root
image with this temporary fixed command:

```text
/usr/bin/setpriv --no-new-privs -- /bin/sh /app/deploy/identity/entrypoint.sh provision-identity
```

The only input is a dedicated `WHOOP_BACKEND_IDENTITY_BOOTSTRAP` variable whose
exact object shape is `{mode, identity, enrollmentKey}`. Its mode is
`whoop-owner-identity-bootstrap`; identity has exactly `mode`, `hostname`,
`clientId`, `clientSecret`, with mode `whoop-owner-identity` and the approved exact
backend tailnet hostname. Deliver values through the approved private operator
channel, never chat, command arguments, Git, build context or logs. The enrollment
key must be short-lived, one-use and restricted to the backend tag. Provider
variable/deployment history may retain submitted values after active removal;
revoking the enrollment key is separate from removing the active variable.
The temporary shell/process memory and initial environment may retain the input
until the fresh redeploy; clearing a variable is not secret-memory erasure.

The fixed noninteractive shell bridge strips all inherited environment before
Node starts, blocking pre-main Node/OpenSSL options. Normal/init modes reject
bootstrap presence even when empty. Provisioning checks real/effective UID/GID 1000
and kernel no-new-privileges before reading its one bounded variable, then uses
builtin printf to pipe it to clean Node stdin, never argv. Node independently caps
input at 8192 bytes and five seconds, validates the full envelope, and requires
both dedicated directories to be empty. It atomically claims private
`identity.json` first, then writes only fixed backend `runtime.json`; it cannot
write app.json, a database URL/CA, health credentials or a numeric WHOOP allowlist.
It enrolls only the exact backend node, closes that daemon and waits. No app,
identity HTTP service, database, migration or WHOOP request starts in this phase.

A failure leaves private partial-attempt evidence and refuses automatic retry or
overwrite. Stop and inspect that exact attempt before any operator recovery. After
success, revoke the one-use enrollment key, remove the active bootstrap variable
and replace the temporary command with a clean normal identity-image redeploy.
The identity runtime itself rejects bootstrap variables and cannot enroll a node.
Full backend app/CA configuration follows only after the user confirms the numeric
WHOOP identity through the separate reviewed operation.

## Local preparation evidence — 2026-10-19

The combined identity and provisioning suite passed 23/23 tests with no skips in
a fresh isolated Node 22 container. Both AMD64 images were built offline from the
exact tested source and cached pinned bases, without dependency installation or
build commands:

- Identity: `sha256:7d5e9858f5adcdf374cbe869d46b54c0e973666b6479c43fff2b54257248b6d5`.
- Empty-volume initializer: `sha256:eab211cdaae1ee1f6bfbde2917b79f6eadf19ef972c6249d7a977919346464ea`.

Packaged checks passed for hostile Node/OpenSSL environment removal before Node
starts, fixed command dispatch and secret-free errors. A separate empty root
fixture received no bootstrap or client secret and finished with real/effective
UID/GID 1000, zero effective/permitted/inheritable/ambient capabilities,
no-new-privileges, seccomp, empty private directories and no listener. Both
containers used no network or host mounts and their removal was verified. The
no-secret-arguments property was established by reviewing the fixed builtin
`printf`/stdin bridge; it is separate from the measured startup checks.

Evidence is retained under `identity-provision-20261019a`: source tests in
`attempt-20261019T053827-16441c0d`, packaged checks in
`attempt-20261019T054558-738fb974`, and final report
`identity-preparation-result.json` with SHA-256
`602a7805b5861252bc92ae2cfc8bd1b4572ebf4b0e160856c5d4578e76991453`.
The first packaged attempt is also retained: its final inspection used the
restricted root identity against directories already owned privately by UID
1000, so it failed with EACCES; the fresh retry used the directory owner without
adding privileges.

AMD64 checks ran through OrbStack translation. They do not prove Railway
isolation, clear runtime advisories, or authorize billing, deployment, enrollment,
WHOOP consent or database migration. No such external action occurred during
this preparation.
